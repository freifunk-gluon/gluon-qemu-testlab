#!/biin/python3

import os
import sys
import time
import fcntl
import select
import shutil
import termios
import asyncio
import subprocess

image = "image.img"

if os.environ.get('TMUX') is None:
    os.execl('/usr/bin/tmux', 'tmux', '-S', 'test', 'new', sys.executable, '-i', *sys.argv)

SSH_KEY_FILE = './ssh/id_rsa.key'
SSH_PUBKEY_FILE = SSH_KEY_FILE + '.pub'

def run(cmd):
    subprocess.run(cmd, shell=True)

# TODO: cd to project folder
if not os.path.exists(SSH_PUBKEY_FILE):
    run(f'ssh-keygen -t rsa -f {SSH_KEY_FILE} -N \'\'')

stdout_buffers = {}
processes = {}

def gen_qemu_call(image, identifier, ports):

    shutil.copyfile('./' + image, './images/%02x.img' % identifier)

    # todo machine identifier
    host_id = 1
    nat_mac = "52:54:%02x:%02x:34:%02x" % (host_id, identifier, 1)
    client_mac = "52:54:%02x:%02x:34:%02x" % (host_id, identifier, 2)
    hostname = 'node%d' % identifier

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
            '-netdev', 'tap,id=hn2,script=no,downscript=no,ifname=%s_client' % hostname,
            '-device', 'e1000,addr=0x05,netdev=hn2,id=nic2,mac=' + client_mac]

    args = ['qemu-system-x86_64', './images/%02x.img' % identifier] + call + mesh_ifaces
    process = asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    processes[identifier] = yield from process

def call(p, cmd):
    p.stdin.write(cmd.encode('utf-8') + b'\n')

def set_mesh_devs(p, devs):
    #call(p, 'ip link set ' + dev + ' up')
    #call(p, 'batctl if add ' + dev)
    call(p, 'uci set network.mesh_lan.auto=1')
    call(p, 'uci del_list network.mesh_lan.ifname=eth0')
    for d in devs:
        call(p, 'uci add_list network.mesh_lan.ifname=%s' % d)

        # deactivate offloading (maybe a bug)
        call(p, 'ethtool --offload %s rx off tx off' % d)
        call(p, 'ethtool -K %s gro off' % d)
        call(p, 'ethtool -K %s gso off' % d)

    call(p, 'uci commit network')
    call(p, 'ubus call network reload')

def add_ssh_key(p):
    # TODO: this removes baked in ssh keys :/
    with open(SSH_PUBKEY_FILE) as f:
        content = f.read()
        call(p, f'''cat >> /etc/dropbear/authorized_keys <<EOF
{content}
EOF''')


def install_clients(hostnames):
    for hostname in hostnames:
        ifname = "%s_client" % hostname
        netns = "%s_client" % hostname
        # TODO: delete them correctly
        # Issue with mountpoints yet http://man7.org/linux/man-pages/man7/mount_namespaces.7.html
        run(f'ip netns add {netns}')
        run(f'sudo ip link set netns {netns} dev {ifname}')
        run(f'ip netns exec {netns} ip link set {ifname} up')
        shell = os.environ.get('SHELL') or '/bin/bash'
        spawn_in_tmux(hostname.replace('node', 'client'), f'ip netns exec {netns} {shell}')

        ssh_opts = '-o UserKnownHostsFile=/dev/null ' + \
                   '-o StrictHostKeyChecking=no ' + \
                   f'-i {SSH_KEY_FILE} '
        spawn_in_tmux(hostname, f'ip netns exec {netns} /bin/bash -c "while ! ssh {ssh_opts} root@fdca:ffee:8::1; do sleep 1; done"')

def spawn_in_tmux(title, cmd):
    run(f'tmux -S test new-window -n {title} {cmd}')

p = gen_qemu_call(image, 1, {1234: 'listen'})
#time.sleep(5)
#p2 = gen_qemu_call(image, 2, {1234: 'connect', 1235: 'listen'})
#time.sleep(5)
#p3 = gen_qemu_call(image, 3, {1235: 'connect' })

@asyncio.coroutine
def read_to_buffer(identifier, process):
    while processes.get(identifier) is None:
        yield from asyncio.sleep(0)
    process = processes[identifier]
    i = identifier
    stdout_buffers[i] = b""
    with open('logs/node1.log', 'wb') as f1:
        while True:
            b = yield from process.stdout.read(1) # TODO: is this unbuffered?
            stdout_buffers[i] += b
            f1.write(b)
            if b == b'\n':
                f1.flush()

@asyncio.coroutine
def wait_for(identifier, b):
    i = identifier
    while stdout_buffers.get(identifier) is None:
        yield from asyncio.sleep(0)
    while True:
        if b.encode('utf-8') in stdout_buffers[i]:
            return
        yield from asyncio.sleep(0)


def add_hosts(p):
    call(p, '''cat >> /etc/hosts <<EOF
fdca:ffee:8::5054:1ff:fe01:3402 node1
fdca:ffee:8::5054:1ff:fe02:3402 node2
fdca:ffee:8::5054:1ff:fe03:3402 node3
EOF''')

@asyncio.coroutine
def test():
    yield from wait_for(1, 'Linux')
    print('Linux')
    yield from wait_for(1, 'Please press Enter to activate this console.')
    print('console appeared')
    yield from wait_for(1, 'reboot: Restarting system')
    print('leaving config mode (reboot)')
    # flush buffer
    stdout_buffers[1] = b''.join(stdout_buffers[1].split(b'reboot: Restarting system')[1:])
    yield from wait_for(1, 'Please press Enter to activate this console.')
    print('console appeared (again)')

    identifier = 1

    p = processes[identifier]

    # activate shell
    call(p, '')

    # TODO: error for ethtool not installed!
    # TODO: ethtool description
    # TODO: mehrere? variabel?
    mesh_ifaces = ['eth2']
    # wait for mesh ifaces
    for i in mesh_ifaces:
        print(f'wait for iface {i}')
        yield from wait_for(1, 'Please press Enter to activate this console.')
        print(f'iface {i} appeared')

    # wait for netifd
    # TODO: very hacky!
    call(p, 'ubus wait_for network && (echo -n "ubus_network_"; echo "appeared")') # TODO: race?
    print(f'wait for netifd ubus api')
    yield from wait_for(1, 'ubus_network_appeared')
    print(f'netifd appeared on ubus')

    set_mesh_devs(p, mesh_ifaces)

    # TODO: variabel
    add_hosts(p)

    # TODO: variabel
    call(p, 'pretty-hostname node1')

    add_ssh_key(p)

    print('waiting for configure')
    call(p, "echo -n 'sucessfully_'; echo 'configured'") # TODO: race condition?

    yield from wait_for(1, 'sucessfully_configured')
    print('configured')

    print('waiting for vx_mesh_lan to come up')
    yield from wait_for(1, 'Interface activated: vx_mesh_lan')
    print('vx_mesh_lan configured')

loop = asyncio.get_event_loop()
loop.create_task(test())
loop.create_task(read_to_buffer(1, p))
loop.create_task(p)

loop.run_forever()


with open('logs/node1.log', 'wb') as f1:
    with open('logs/node2.log', 'wb') as f2:
        with open('logs/node3.log', 'wb') as f3:
            node1_log = b""
            node2_log = b""
            node3_log = b""
            while True:
                c1 = read_all(p)
                f1.write(c1)
                node1_log += c1

                c2 = read_all(p2)
                f2.write(c2)
                node2_log += c2

                c3 = read_all(p3)
                f3.write(c3)
                node3_log += c3

                if b"sucessfully configured" in node1_log \
                    and b"sucessfully configured" in node2_log \
                    and b"sucessfully configured" in node3_log:
                    break

install_clients(['node1', 'node2', 'node3'])


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
