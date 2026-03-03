#!/usr/bin/env python3

import sys, os, time
import json
from hashlib import sha256
from OpenSSL.SSL import VERIFY_PEER, VERIFY_FAIL_IF_NO_PEER_CERT
from twisted.internet import ssl, reactor
from twisted.internet.protocol import ServerFactory, ClientFactory, Factory
from twisted.protocols.basic import LineReceiver
from twisted.python import log
from collections import defaultdict
from threading import Lock

SERVER_HOST = os.getenv('SERVER_HOST', '')
SERVER_PORT = int(os.getenv('SERVER_PORT', 563))
SERVER_SSL = os.getenv('SERVER_SSL', 'false').lower() == 'true'
SERVER_USER = os.getenv('SERVER_USER', '')
SERVER_PASS = os.getenv('SERVER_PASS', '')
SERVER_CONNECTIONS = int(os.getenv('SERVER_CONNECTIONS', 20))
PROXY_SSL = os.getenv('PROXY_SSL', 'false').lower() == 'true'
PROXY_PORT = int(os.getenv('PROXY_PORT', 15630)) 
PROXY_CERT_PEM = os.getenv('PROXY_CERT_PEM', '')
PROXY_CERT_KEY = os.getenv('PROXY_CERT_KEY', '')
PROXY_CA_VERIFY = os.getenv('PROXY_CA_VERIFY', 'false').lower() == 'true'
PROXY_USERS = json.loads(os.getenv('PROXY_USERS', '{}'))
PROXY_CONNECTIONS = json.loads(os.getenv('PROXY_CONNECTIONS', ''))
if PROXY_CA_VERIFY:
    PROXY_CERT_CA = os.getenv('PROXY_CERT_CA', '')

class ConnectionManager:
    def __init__(self):
        self.total_connections = 0
        self.user_connections = defaultdict(int)
        self.lock = Lock()

    def add_connection(self, user):
        with self.lock:
            self.user_connections[user] += 1
            self.total_connections += 1
            return self.user_connections[user], self.total_connections

    def remove_connection(self, user):
        with self.lock:
            self.user_connections[user] = max(0, self.user_connections[user] - 1)
            self.total_connections = max(0, self.total_connections - 1)

connection_manager = ConnectionManager()

log.startLogging(sys.stdout)
Factory.noisy = False

class NNTPProxyServer(LineReceiver):
  clientFactory = None
  client = None
  auth_user = None
  authenticated = False

  def connectionMade(self):
    self.transport.pauseProducing()
    client = self.clientFactory()
    client.server = self
    if SERVER_SSL:
      reactor.connectSSL(SERVER_HOST, SERVER_PORT, client, ssl.ClientContextFactory())
    else:
      reactor.connectTCP(SERVER_HOST, SERVER_PORT, client)
    self.downloaded_bytes = 0
    self.uploaded_bytes = 0
    self.conn_time = time.time()

  def connectionLost(self, reason):
    if self.client is not None:
	    self.client.transport.loseConnection()
    if self.auth_user:
      connection_manager.remove_connection(self.auth_user)
      log.msg(f'user {self.auth_user!r} disconnected: duration {int(time.time() - self.conn_time)}, downloaded {self.downloaded_bytes}, uploaded {self.uploaded_bytes}')

  def lineReceived(self, line):
    if not self.authenticated:
      if line.upper().startswith(b'AUTHINFO USER '):
        parts = line.split(b' ')
        if len(parts) == 3:
          self.auth_user = parts[2].strip().decode(errors='ignore')
          if self.auth_user in PROXY_USERS and SERVER_USER:
            self.client.sendLine(f'AUTHINFO USER {SERVER_USER}'.encode())
          elif self.auth_user not in PROXY_USERS:
            log.msg(f"Unknown user {self.auth_user!r} attempted to log in")
            self.sendLine(b'481 Authentication failed')
            self.transport.loseConnection()
        else:
          self.sendLine(b'501 Syntax error in command')
          self.transport.loseConnection()
      elif line.upper().startswith(b'AUTHINFO PASS '):
        parts = line.split(b' ')
        if len(parts) >= 2:
          password = parts[2].strip() if len(parts) >= 3 else b''
          if self.auth_user and PROXY_USERS.get(self.auth_user) == sha256(password).hexdigest():
            user_conns, total_conns = connection_manager.add_connection(self.auth_user)

            if int(PROXY_CONNECTIONS.get(self.auth_user, float('inf'))) < user_conns or SERVER_CONNECTIONS < total_conns:
                connection_manager.remove_connection(self.auth_user)
                self.sendLine(b'502 Too many connections')
                self.transport.loseConnection()
                return

            self.authenticated = True
            
            if SERVER_PASS:
              self.client.sendLine(f'AUTHINFO PASS {SERVER_PASS}'.encode())
            log.msg(f"{self.auth_user!r} successfully logged in ({user_conns} connections)")
          else:
            self.sendLine(b'481 Authentication failed')
            self.transport.loseConnection()
        else:
          self.sendLine(b'501 Syntax error in command')
          self.transport.loseConnection()
      else:
        self.uploaded_bytes += len(line)
        self.client.sendLine(line)
    else:
      self.uploaded_bytes += len(line)
      self.client.sendLine(line)

class NNTPProxyClient(LineReceiver):
  server = None

  def connectionMade(self):
    self.server.client = self
    self.server.transport.resumeProducing()

  def connectionLost(self, reason):
    if self.server is not None:
	    self.server.transport.loseConnection()

  def lineReceived(self, line):
    self.server.downloaded_bytes += len(line)
    self.server.sendLine(line)

class NNTPProxyClientFactory(ClientFactory):
  server = None
  protocol = NNTPProxyClient

  def buildProtocol(self, *args, **kw):
    prot = ClientFactory.buildProtocol(self, *args, **kw)
    prot.server = self.server
    return prot

  def clientConnectionLost(self, connector, reason):
    if self.server:
      self.server.transport.loseConnection()

  def clientConnectionFailed(self, connector, reason):
    if self.server:
      self.server.transport.loseConnection()

def verifyCallback(connection, x509, errnum, errdepth, ok):
  if not ok:
    log.msg(f'invalid cert from subject: {x509.get_subject()}')
    return False
  log.msg(f'accepted cert from subject: {x509.get_subject()}')
  return True

serverFactory = ServerFactory()
serverFactory.protocol = NNTPProxyServer
serverFactory.protocol.clientFactory = NNTPProxyClientFactory
if PROXY_SSL:
  sslFactory = ssl.DefaultOpenSSLContextFactory(PROXY_CERT_KEY, PROXY_CERT_PEM)
  sslContext = sslFactory.getContext()
  if PROXY_CA_VERIFY:
      sslContext.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT, verifyCallback)
      sslContext.set_verify_depth(10)
      sslContext.load_verify_locations(PROXY_CERT_CA)
  reactor.listenSSL(PROXY_PORT, serverFactory, sslFactory)
else:
  reactor.listenTCP(PROXY_PORT, serverFactory)
reactor.run()