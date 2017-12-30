#!/bin/python3

import os
import sys
import fcntl
import select
import subprocess

p = subprocess.Popen(['./test.sh'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, encoding="utf-8")

# fd = p.stdout.fileno()
# fl = fcntl.fcntl(fd, fcntl.F_GETFL)
# fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def call(p, cmd):
    p.stdin.write(cmd.encode('utf-8') + b'\n')
    p.stdin.flush()

def read_all(p):
    res = b""
    while select.select([p.stdout],[],[],0)[0] != []:
        res += p.stdout.read(1)
    return res

def repl2(p):
    while True:
        p.stdout.flush()
        s = select.select([sys.stdin, p.stdout], [], [], 0.1)
        if sys.stdin in s[0]:
            c = os.read(sys.stdin.fileno(), 1).decode('utf-8')
            p.stdin.write(c)
            p.stdin.flush()
        if p.stdout in s[0]:
            sys.stdout.write(os.read(p.stdout.fileno(), 1).decode('utf-8'))
            sys.stdout.flush()

def repl3(p):
    while True:
        p.stdout.flush()
        s = select.select([sys.stdin, p.stdout], [], [], 0.1)
        if sys.stdin in s[0]:
            c = sys.stdin.read(8192)
            if c == '':
                return
            p.stdin.write(c)
            p.stdin.flush()
        if p.stdout in s[0]:
            sys.stdout.write(p.stdout.read(8192))
            sys.stdout.flush()
        #print('.', end='')
        print(p.stdout.read(100), end='')
        sys.stdout.flush()

# READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
# poller = select.poll()
# poller.register(p.stdout, READ_ONLY)


# qemu-system-x86_64 ${tmpfile} \
#     -nographic \
#     -net nic,addr=0x10 -net user \
#     -netdev bridge,id=hn0 -device e1000,addr=0x09,netdev=hn0,id=nic1
