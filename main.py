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
from operator import itemgetter

image = "image.img"

if os.environ.get('TMUX') is None:
    os.execl('/usr/bin/tmux', 'tmux', '-S', 'test', 'new', sys.executable, '-i', *sys.argv)

SSH_KEY_FILE = './ssh/id_rsa.key'
SSH_PUBKEY_FILE = SSH_KEY_FILE + '.pub'
NEXT_NODE_ADDR = 'fdca:ffee:8::1'

class Node():

    max_id = 0
    max_port = 17321
    all_nodes = []

    def __init__(self):
        Node.max_id += 1
        Node.all_nodes += [self]
        self.id = Node.max_id
        self.hostname = f'node{self.id}'
        self.mesh_links = []
        self.if_index_max = 1

    def add_mesh_link(self, peer, _is_peer=False, _port=None):
        self.if_index_max += 1
        ifname = f'eth{self.if_index_max}'
        if _port is None:
            Node.max_port += 1
            port = Node.max_port
            conn_type = 'listen'
        else:
            port = _port
            conn_type = 'connect'
        self.mesh_links.append((ifname, peer, conn_type, port))
        if not _is_peer:
            peer.add_mesh_link(self, _is_peer=True, _port=port)
        return ifname

def run(cmd):
    subprocess.run(cmd, shell=True)

# TODO: cd to project folder
if not os.path.exists(SSH_PUBKEY_FILE):
    run(f'ssh-keygen -t rsa -f {SSH_KEY_FILE} -N \'\'')

stdout_buffers = {}
processes = {}

def gen_qemu_call(image, node):

    shutil.copyfile('./' + image, './images/%02x.img' % node.id)

    # TODO: machine identifier
    host_id = 1
    nat_mac = "52:54:%02x:%02x:34:%02x" % (host_id, node.id, 1)
    client_mac = "52:54:%02x:%02x:34:%02x" % (host_id, node.id, 2)

    mesh_ifaces = []
    mesh_id = 1
    for _, _, conn_type, port in node.mesh_links:
        if conn_type not in ['listen', 'connect']:
            raise ValueError('conn_type invalid: ' + str(conn_type))

        if conn_type == 'connect':
            yield from wait_bash_cmd(f'while ! ss -tlp4n | grep ":{port}" &>/dev/null; do sleep 1; done;')

        mesh_ifaces += [
            '-device', ('rtl8139,addr=0x%02x,netdev=mynet%d,id=m_nic%d,mac=' + \
                "52:54:%02x:%02x:34:%02x") % (10 + mesh_id, mesh_id, mesh_id, host_id, node.id, 10 + mesh_id),
            '-netdev', 'socket,id=mynet%d,%s=:%d' % (mesh_id, conn_type, port)
        ]

        mesh_id += 1

    call = ['-nographic',
            '-enable-kvm',
            '-netdev', 'user,id=hn1',
            '-device', 'rtl8139,addr=0x06,netdev=hn1,id=nic1,mac=' + nat_mac,
            '-netdev', 'tap,id=hn2,script=no,downscript=no,ifname=%s_client' % node.hostname,
            '-device', 'rtl8139,addr=0x05,netdev=hn2,id=nic2,mac=' + client_mac]

    # '-d', 'guest_errors', '-d', 'cpu_reset', '-gdb', 'tcp::' + str(3000 + node.id),
    args = ['qemu-system-x86_64',
            '-drive', 'format=raw,file=./images/%02x.img' % node.id] + call + mesh_ifaces
    process = asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    processes[node.id] = yield from process

def call(p, cmd):
    p.stdin.write(cmd.encode('utf-8') + b'\n')

def set_mesh_devs(p, devs):
    for d in devs:
        call(p, f"uci set network.{d}_mesh=interface")
        call(p, f"uci set network.{d}_mesh.auto=1")
        call(p, f"uci set network.{d}_mesh.proto=gluon_wired")
        call(p, f"uci set network.{d}_mesh.ifname={d}")

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

@asyncio.coroutine
def wait_bash_cmd(cmd):
    create = asyncio.create_subprocess_exec("/bin/bash", '-c', cmd)
    proc = yield from create

    # Wait for the subprocess exit
    yield from proc.wait()

@asyncio.coroutine
def install_client(initial_time, node):
    clientname = f"client{node.id}"
    dbg = debug_print(initial_time, clientname)

    ifname = "%s_client" % node.hostname

    dbg(f'waiting for iface {ifname} to appear')
    yield from wait_bash_cmd(f'while ! ip link show dev {ifname} &>/dev/null; do sleep 1; done;')
    dbg(f'iface {ifname} appeared')

    netns = "%s_client" % node.hostname
    # TODO: delete them correctly
    # Issue with mountpoints yet http://man7.org/linux/man-pages/man7/mount_namespaces.7.html

    run(f'ip netns add {netns}')
    run(f'sudo ip link set netns {netns} dev {ifname}')
    run(f'ip netns exec {netns} ip link set {ifname} up')
    shell = os.environ.get('SHELL') or '/bin/bash'
    spawn_in_tmux(clientname, f'ip netns exec {netns} {shell}')

    ssh_opts = '-o UserKnownHostsFile=/dev/null ' + \
               '-o StrictHostKeyChecking=no ' + \
               f'-i {SSH_KEY_FILE} '
    spawn_in_tmux(node.hostname, f'ip netns exec {netns} /bin/bash -c "while ! ssh {ssh_opts} root@{NEXT_NODE_ADDR}; do sleep 1; done"')

def spawn_in_tmux(title, cmd):
    run(f'tmux -S test new-window -d -n {title} {cmd}')

@asyncio.coroutine
def read_to_buffer(node):
    while processes.get(node.id) is None:
        yield from asyncio.sleep(0)
    process = processes[node.id]
    stdout_buffers[node.id] = b""
    with open(f'logs/{node.hostname}.log', 'wb') as f1:
        while True:
            b = yield from process.stdout.read(1) # TODO: is this unbuffered?
            stdout_buffers[node.id] += b
            f1.write(b)
            if b == b'\n':
                f1.flush()

@asyncio.coroutine
def wait_for(node, b):
    i = node.id
    while stdout_buffers.get(i) is None:
        yield from asyncio.sleep(0)
    while True:
        if b.encode('utf-8') in stdout_buffers[i]:
            return
        yield from asyncio.sleep(0)

# TODO: adjust
def add_hosts(p):
    call(p, '''cat >> /etc/hosts <<EOF
fdca:ffee:8::5054:1ff:fe01:3402 node1
fdca:ffee:8::5054:1ff:fe02:3402 node2
fdca:ffee:8::5054:1ff:fe03:3402 node3
EOF''')

def debug_print(since, hostname):
    def printfn(message):
        delta = time.time() - since
        print(f'[{delta:>8.2f} | {hostname:<9}] {message}')
    return printfn

@asyncio.coroutine
def config_node(initial_time, node):

    dbg = debug_print(initial_time, node.hostname)

    yield from wait_for(node, 'Linux')
    dbg('Linux')
    yield from wait_for(node, 'Please press Enter to activate this console.')
    dbg('console appeared')
    yield from wait_for(node, 'reboot: Restarting system')
    dbg('leaving config mode (reboot)')
    # flush buffer
    stdout_buffers[node.id] = b''.join(stdout_buffers[node.id].split(b'reboot: Restarting system')[1:])
    yield from wait_for(node, 'Please press Enter to activate this console.')
    dbg('console appeared (again)')

    p = processes[node.id]

    # activate shell
    call(p, '')

    # TODO: error for ethtool not installed!
    # TODO: ethtool description
    # TODO: mehrere? variabel?
    mesh_ifaces = list(map(itemgetter(0), node.mesh_links))
    # wait for mesh ifaces
    for i in mesh_ifaces:
        dbg(f'wait for iface {i}')
        yield from wait_for(node, 'Please press Enter to activate this console.') # TODO: FIXME
        dbg(f'iface {i} appeared')

    # wait for netifd
    # TODO: very hacky!
    call(p, 'ubus wait_for network && (echo -n "ubus_network_"; echo "appeared")') # TODO: race?
    dbg(f'wait for netifd ubus api')
    yield from wait_for(node, 'ubus_network_appeared')
    dbg(f'netifd appeared on ubus')

    set_mesh_devs(p, mesh_ifaces)

    # TODO: variabel
    add_hosts(p)

    call(p, f'pretty-hostname {node.hostname}')

    add_ssh_key(p)

    dbg('waiting for configure')
    call(p, "echo -n 'sucessfully_'; echo 'configured'") # TODO: race condition?

    yield from wait_for(node, 'sucessfully_configured')
    dbg('configured')

    dbg('waiting for vx_mesh_lan to come up')
    yield from wait_for(node, 'Interface activated: vx_mesh_lan')
    dbg('vx_mesh_lan configured')

def run_all():
    loop = asyncio.get_event_loop()

    for node in Node.all_nodes:
        loop.create_task(gen_qemu_call(image, node))
        loop.create_task(read_to_buffer(node))
        loop.create_task(config_node(initial_time, node))
        loop.create_task(install_client(initial_time, node))

    loop.run_forever()

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


initial_time = time.time()

a = Node()
for i in range(10):
    b = Node()
    a.add_mesh_link(b)
    a = b

run_all()

# a1 = Node()
# a2 = Node()
# a3 = Node()
#
# connect(a1, a2)
