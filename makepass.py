#!/usr/bin/env python3

import sys
import getpass
from hashlib import sha256

print("nntp2nntp password hasher\n")
pwd = getpass.getpass()
print(f"Hashed password: {sha256(pwd.encode()).hexdigest()}")
sys.exit(0)