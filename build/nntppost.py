#!/usr/bin/env python3

import sys, os, re, time
from netrc import netrc
from email.message import EmailMessage
from email.utils import make_msgid
from twisted.news.nntp import NNTPClient
from twisted.internet import ssl, reactor, defer
from twisted.internet.protocol import ClientFactory

if len(sys.argv) < 5:
    sys.stderr.write(f"Usage: {sys.argv[0]} <from> <groups> <subject> <file1.ync> [file2.ync ...]\n")
    sys.stderr.write("""
The server comes from NNTPSERVER environment variable and
authentication information should be stored in ~/.netrc.

To post files they need to be encoded with yencode first:
http://sourceforge.net/projects/yencode/

The subject will be automatically extended with file information.
""")
    sys.exit(1)

re_file_multi = re.compile(br'^=ybegin part=(?P<part>[0-9]+) total=(?P<total>[0-9]+) line=[0-9]+ size=(?P<size>[0-9]+) name=(?P<name>.*?)\s*$')
re_file_single = re.compile(br'^=ybegin line=[0-9]+ size=(?P<size>[0-9]+) name=(?P<name>.*?)\s*$')
messages = {}
fromaddr = sys.argv[1].strip()
groups = [newsgroup.strip() for newsgroup in sys.argv[2].split(',')]
comment = sys.argv[3].strip().replace('%', '%%')
subject = """[%(file)d/%(files)d] """ + comment + """ - "%(name)s" yEnc (%(part)d/%(parts)d) %(size)d bytes - file %(file)d of %(files)d"""
file_list = sys.argv[4:]
filecount = 1
nntpserver = os.environ.get('NNTPSERVER', 'news-europe.giganews.com:443')
nntpport = 443
if ':' in nntpserver:
    nntpserver, nntpport = nntpserver.split(':')
    nntpport = int(nntpport)
nntpuser, _, nntppass = netrc().authenticators(nntpserver) or (None, None, None)

print("Process yEnc files")
for yncfile in file_list:
    if not os.access(yncfile, os.R_OK):
        raise RuntimeError(f"ERROR: file {yncfile!r} is not readable")
    with open(yncfile, "rb") as fd:
        ync_line = fd.readline().strip()
    ma_file = re_file_multi.match(ync_line) or re_file_single.match(ync_line)
    if not ma_file:
        raise RuntimeError(f"ERROR: file {yncfile!r} does not seem to be yEnc file")
    ma_file = ma_file.groupdict()
    part = int(ma_file.get(b'part', 1))
    total = int(ma_file.get(b'total', 1))
    size = int(ma_file[b'size'])
    name = ma_file[b'name'].decode()
    if name in messages:
        curparts, curtotal, curcount = messages[name]
        if curtotal != total or part in curparts:
            raise RuntimeError(f"ERROR: inconsistency with file {yncfile!r}")
        curparts.append([part, None, yncfile, size])
    else:
        messages[name] = ([[part, None, yncfile, size]], total, filecount)
        filecount = filecount + 1
    print(f"...processed file {yncfile}")
filecount -= 1

print("Check parts and generate subjects")
for name, value in messages.items():
    parts, total, curfile = value
    lastpart = 0
    parts.sort()
    for part in parts:
        if part[0] != lastpart + 1:
            raise RuntimeError(f"ERROR: part {lastpart + 1} for file {name} not exist")
        lastpart += 1
        part[1] = subject % {
            'part'  : part[0],
            'parts' : total,
            'name'  : name,
            'file'  : curfile,
            'files' : filecount,
            'size'  : part[3],
        }
    print(f"...processed file {name}")

def postFilesGenerator():
    print(f"Post {len(messages)} files in parts")
    for name, value in messages.items():
        parts, total, curfile = value
        print(f"...post file {curfile}")
        for num, subj, fname, size in parts:
            print(f"....{subj}")
            with open(fname, "rb") as src:
                msgdata = src.read()
            lines = msgdata.count(b'\n') + 1
            bytecount = len(msgdata)
            
            msgid = make_msgid()
            msgid = re.sub(r'@.*>$', '@notexists.local>', msgid)
            msgid = msgid.replace('<', f'<Part{num}of{total}.')
            
            msg = EmailMessage()
            msg["From"] = fromaddr
            msg["Subject"] = subj
            msg["User-Agent"] = "postfiles.py (http://sourceforge.net/projects/nntp2nntp/)"
            msg["X-No-Archive"] = "yes"
            msg["Message-Id"] = msgid
            msg["Newsgroups"] = ','.join(groups)
            msg["Lines"] = str(lines)
            msg["Bytes"] = str(bytecount)
            msg.set_payload(msgdata)
            yield msg.as_bytes()
        print(f"...processed file {name}")


class PosterClient(NNTPClient):
    def __init__(self, postparts):
        super().__init__()
        self._postparts = postparts

    def quit(self):
        super().quit()
        reactor.stop()

    def failed(self, message, error):
        print(f"{message}: {error}")
        self.quit()
    
    postFailed = lambda s, e: s.failed("Posting failed", e)
    authFailed = lambda s, e: s.failed("Auth failed", e)

    def connectionMade(self):
        super().connectionMade()
        if nntpuser:
            self.sendCommand(b'AUTHINFO USER ' + nntpuser.encode())
            self.deferred.addCallbacks(self.authUserOk, self.authFailed)
        else:
            self.postArticle(next(self._postparts))

    def authUserOk(self, result):
        self.sendCommand(b'AUTHINFO PASS ' + nntppass.encode())
        self.deferred.addCallbacks(self.authPassOk, self.authFailed)
        return result

    def authPassOk(self, result):
        self.postArticle(next(self._postparts))
        return result

    def articlePosted(self, result):
        try:
            self.postArticle(next(self._postparts))
        except StopIteration:
            self.quit()
        return result

class PosterFactory(ClientFactory):
    def buildProtocol(self, addr):
        return PosterClient(postFilesGenerator())

print(f"Connect to server {nntpserver}")
factory = PosterFactory()
reactor.connectSSL(nntpserver, nntpport, factory, ssl.CertificateOptions())
reactor.run()
print("All files successfully posted.")
