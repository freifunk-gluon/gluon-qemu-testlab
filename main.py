#!/biin/python3

import os
import sys
import fcntl
import select
import termios
import subprocess

image = "gluon-ffh-1.0-20171228-x86-generic.img"

call = ['-nographic',
        '-net', 'nic,addr=0x10',
        '-net', 'user',
        '-netdev', 'bridge,id=hn0',
        '-device', 'e1000,addr=0x09,netdev=hn0,id=nic1',]

mac = "52:54:00:12:34:%02x"
listen = [
    '-device', 'e1000,addr=0x11,netdev=mynet0,id=nic2,mac=' + (mac % 1),
    '-netdev', 'socket,id=mynet0,listen=:1234']
connect = [
    '-device', 'e1000,addr=0x11,netdev=mynet0,id=nic2,mac=' + (mac % 2),
    '-netdev', 'socket,id=mynet0,connect=:1234']

p = subprocess.Popen(['qemu-system-x86_64', image] + call + listen, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
p2 = subprocess.Popen(['qemu-system-x86_64', '2.img'] + call + connect, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

fd = p.stdout.fileno()
fl = fcntl.fcntl(fd, fcntl.F_GETFL)
fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def call(p, cmd):
    p.stdin.write(cmd.encode('utf-8') + b'\n')
    p.stdin.flush()

def read_all(p):
    res = b""
    while select.select([p.stdout],[],[],0)[0] != []:
        res += p.stdout.read(1)
    return res

def repl():
    while True:
        a = input()
        if a == '##exit':
            break
        call(p, a.replace('\n',''))

        for i in range(10):
            print(p.stdout.readline().decode('utf-8'), end='')

def enable_echo(enable):
    fd = sys.stdin.fileno()
    new = termios.tcgetattr(fd)
    if enable:
        new[3] |= termios.ECHO
        new[3] |= termios.ICANON
        new[3] |= termios.ISIG
    else:
        new[3] &= ~termios.ECHO # no echo
        new[3] &= ~termios.ICANON # Input is delivered bytewise instead of linewise
        new[3] &= ~termios.ISIG # Disable Signals on CTRL + C

    termios.tcsetattr(fd, termios.TCSANOW, new)


def repl2(q):
    enable_echo(False)
    special_mode = False
    while True:
        s = select.select([sys.stdin, q.stdout], [], [], 0.1)
        if sys.stdin in s[0]:
            c = os.read(sys.stdin.fileno(), 1)
            if c == b'\2':
                special_mode = True
            elif special_mode and c == b'c':
                enable_echo(True)
                return
            elif special_mode and c == b'1':
                return repl2(p)
            elif special_mode and c == b'2':
                return repl2(p2)
            else:
                special_mode = False
            q.stdin.write(c)
            q.stdin.flush()
        if q.stdout in s[0]:
            sys.stdout.buffer.write(os.read(q.stdout.fileno(), 1))
            sys.stdout.buffer.flush()
            sys.stdout.flush()
        #print('.', end='')
        #sys.stdout.flush()

READ_ONLY = select.POLLIN | select.POLLPRI | select.POLLHUP | select.POLLERR
poller = select.poll()
poller.register(p.stdout, READ_ONLY)

# qemu-system-x86_64 ${tmpfile} \
#     -nographic \
#     -net nic,addr=0x10 -net user \
#     -netdev bridge,id=hn0 -device e1000,addr=0x09,netdev=hn0,id=nic1


# a1 = Node()
# a2 = Node()
# a3 = Node()
#
# connect(a1, a2)
