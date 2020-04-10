#!/usr/bin/python36
import sys
sys.path.append(".")
from pynet import *
import asyncio
import time

a = Node()
b = Node()

connect(a, b)

start()                                        # This command boots the qemu instances

# API Description:
#
# ssh(n, c)        - enqueues a command c on node n, but does not yet run them
# sync()           - runs all enqueued commands simultaneously till they end
# check(ssh(n, c)) - the command c is started directly on node n and check() will only return after it is finished.
#                    check() returns True, if the return code was successful.

print("""
WARNING: THIS TEST IS CURRENTLY BROKEN, AS THE BATCTL TPMETER ALWAYS RETURNS TRUE.
""")

addr = a.succeed('cat /sys/class/net/primary0/address')
result = b.succeed(f'batctl tp {addr}')

print(result)

finish()
