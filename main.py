#!/biin/python3

import os
import sys
import time
import fcntl
import select
import shutil
import termios
import subprocess

image = "gluon-ffh-1.0-20171229-x86-generic.img"


def gen_qemu_call(image, identifier, ports):

    shutil.copyfile('./' + image, './images/%02x.img' % identifier)

    # todo machine identifier
    host_id = 1
    nat_mac = "52:54:%02x:%02x:34:%02x" % (host_id, identifier, 1)
    client_mac = "52:54:%02x:%02x:34:%02x" % (host_id, identifier, 2)

    mesh_ifaces = []
    mesh_id = 1
    for port, mode in ports.items():
        if mode not in ['listen', 'connect']:
            raise ValueError('Mode invalid: ' + str(mode))

        # TODO: port > 1024

        mesh_ifaces += [
            '-device', ('e1000,addr=0x%02x,netdev=mynet%d,id=m_nic%d,mac=' + \
                "52:54:%02x:%02x:34:%02x") % (10 + mesh_id, mesh_id, mesh_id, host_id, identifier, 10 + mesh_id),

            '-netdev', 'socket,id=mynet%d,%s=:%d' % (mesh_id, mode, port)
        ]

        mesh_id += 1

    call = ['-nographic',
            '-netdev', 'user,id=hn1',
            '-device', 'e1000,addr=0x06,netdev=hn1,id=nic1,mac=' + nat_mac,
            '-netdev', 'tap,id=hn2,script=no,downscript=no',
            '-device', 'e1000,addr=0x05,netdev=hn2,id=nic2,mac=' + client_mac]

    process = subprocess.Popen(['qemu-system-x86_64', './images/%02x.img' % identifier] + call + mesh_ifaces, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    return process

def call(p, cmd):
    p.stdin.write(cmd.encode('utf-8') + b'\n')
    p.stdin.flush()

def add_bat_link(p, dev):
    call(p, 'ip link set ' + dev + ' up')
    call(p, 'batctl if add ' + dev)

p = gen_qemu_call(image, 1, {1234: 'listen'})
time.sleep(5)
p2 = gen_qemu_call(image, 2, {1234: 'connect', 1235: 'listen'})
time.sleep(5)
p3 = gen_qemu_call(image, 3, {1235: 'connect' })

time.sleep(150)

# activate shells
call(p, '')
call(p2, '')
call(p3, '')


add_bat_link(p, 'eth2')
add_bat_link(p2, 'eth2')
add_bat_link(p2, 'eth3')
add_bat_link(p3, 'eth2')

def add_hosts(p):
    call(p, '''cat >> /etc/hosts <<EOF
fdca:ffee:8::5054:1ff:fe01:3401 node1
fdca:ffee:8::5054:1ff:fe02:3401 node2
fdca:ffee:8::5054:1ff:fe03:3401 node3
EOF''')

add_hosts(p)
add_hosts(p2)
add_hosts(p3)

fd = p.stdout.fileno()
fl = fcntl.fcntl(fd, fcntl.F_GETFL)
fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

def read_all(p):
    res = b""
    while select.select([p.stdout],[],[],0)[0] != []:
        res += p.stdout.read(1)
    return res

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
            elif special_mode and c == b'3':
                return repl2(p3)
            else:
                special_mode = False
            q.stdin.write(c)
            q.stdin.flush()
        if q.stdout in s[0]:
            sys.stdout.buffer.write(os.read(q.stdout.fileno(), 1))
            sys.stdout.buffer.flush()
            sys.stdout.flush()


# a1 = Node()
# a2 = Node()
# a3 = Node()
#
# connect(a1, a2)
