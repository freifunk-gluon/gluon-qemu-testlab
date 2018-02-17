#!/biin/python3

import os
import sys
import time
import shutil
import asyncio
import asyncssh
import subprocess
from operator import itemgetter

image = "image.img"

if os.environ.get('TMUX') is None and not 'notmux' in sys.argv:
    os.execl('/usr/bin/tmux', 'tmux', '-S', 'test', 'new', sys.executable, '-i', *sys.argv)

SSH_KEY_FILE = './ssh/id_rsa.key'
SSH_PUBKEY_FILE = SSH_KEY_FILE + '.pub'
NEXT_NODE_ADDR = 'fdca:ffee:8::1'
SITE_LOCAL_PREFIX = 'fdca:ffee:8:0'

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

    fifo_path = './fifos/%02x' % node.id
    if os.path.exists(fifo_path):
        os.remove(fifo_path)
    os.mkfifo(fifo_path)
    stdin = os.open(fifo_path, os.O_NONBLOCK | os.O_RDONLY)
    process = asyncio.create_subprocess_exec(*args, stdout=subprocess.PIPE, stdin=stdin)

    processes[node.id] = yield from process

async def ssh_call(p, cmd):
    res = await p.run(cmd)
    return res.stdout

async def set_mesh_devs(p, devs):
    for d in devs:
        await ssh_call(p, f"uci set network.{d}_mesh=interface")
        await ssh_call(p, f"uci set network.{d}_mesh.auto=1")
        await ssh_call(p, f"uci set network.{d}_mesh.proto=gluon_wired")
        await ssh_call(p, f"uci set network.{d}_mesh.ifname={d}")

        # allow vxlan in firewall
        await ssh_call(p, f'uci add_list firewall.wired_mesh.network={d}_mesh')

    await ssh_call(p, 'uci commit network')
    await ssh_call(p, 'uci commit firewall')

async def add_ssh_key(p):
    # TODO: this removes baked in ssh keys :/
    with open(SSH_PUBKEY_FILE) as f:
        content = f.read()
        await ssh_call(p, f'''cat >> /etc/dropbear/authorized_keys <<EOF
{content}
EOF''')

@asyncio.coroutine
def wait_bash_cmd(cmd):
    create = asyncio.create_subprocess_exec("/bin/bash", '-c', cmd)
    proc = yield from create

    # Wait for the subprocess exit
    yield from proc.wait()

async def install_client(initial_time, node):
    clientname = f"client{node.id}"
    dbg = debug_print(initial_time, clientname)

    ifname = "%s_client" % node.hostname

    # client iface link local addr
    host_id = 1
    lladdr = "fe80::5054:%02xff:fe%02x:34%02x" % (host_id, node.id, 2)

    dbg(f'waiting for iface {ifname} to appear')
    await wait_bash_cmd(f'while ! ip link show dev {ifname} &>/dev/null; do sleep 1; done;')

    # set mac of client tap iface on host system
    client_iface_mac = "aa:54:%02x:%02x:34:%02x" % (host_id, node.id, 2)
    run(f'ip link set {ifname} address {client_iface_mac}')

    run(f'ip link set {ifname} up')
    await wait_bash_cmd(f'while ! ping -c 1 {lladdr}%{ifname} &>/dev/null; do sleep 1; done;')
    dbg(f'iface {ifname} appeared')

    # create netns
    netns = "%s_client" % node.hostname
    # TODO: delete them correctly
    # Issue with mountpoints yet http://man7.org/linux/man-pages/man7/mount_namespaces.7.html
    run(f'ip netns add {netns}')
    gen_etc_hosts_for_netns(netns)

    # wait for ssh TODO: hacky
    await asyncio.sleep(10)

    # node setup setup needs to be done here
    async with asyncssh.connect(f'{lladdr}%{ifname}', username='root', known_hosts=None) as conn:
        await config_node(initial_time, node, conn)
    dbg(f'{node.hostname} configured')

    # move iface to netns
    dbg(f'moving {ifname} to netns {netns}')
    run(f'ip link set netns {netns} dev {ifname}')
    run(f'ip netns exec {netns} ip link set {ifname} up')

    # spawn client shell
    shell = os.environ.get('SHELL') or '/bin/bash'
    spawn_in_tmux(clientname, f'ip netns exec {netns} {shell}')

    # spawn ssh shell
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
async def add_hosts(p):
    await ssh_call(p, f'cat >> /etc/hosts <<EOF\n{host_entries}\n')

def debug_print(since, hostname):
    def printfn(message):
        delta = time.time() - since
        print(f'[{delta:>8.2f} | {hostname:<9}] {message}')
    return printfn

async def config_node(initial_time, node, ssh_conn):

    dbg = debug_print(initial_time, node.hostname)

    p = ssh_conn

    # TODO: optional
    #ssh_call(p, 'for f in $(find /lib/gluon/upgrade -type f); do ${f}; done')
    await ssh_call(p, 'uci set gluon-setup-mode.@setup_mode[0].configured=\'1\'')
    await ssh_call(p, 'uci commit gluon-setup-mode')

    mesh_ifaces = list(map(itemgetter(0), node.mesh_links))
    await set_mesh_devs(p, mesh_ifaces)

    # TODO: variabel
    await add_hosts(p)
    await ssh_call(p, f'pretty-hostname {node.hostname}')
    await add_ssh_key(p)
    await ssh_call(p, f'reboot')

    #yield from asyncio.sleep(3600)

    await wait_for(node, 'reboot: Restarting system')
    dbg('leaving config mode (reboot)')
    # flush buffer
    stdout_buffers[node.id] = b''.join(stdout_buffers[node.id].split(b'reboot: Restarting system')[1:])
    await wait_for(node, 'Please press Enter to activate this console.')
    dbg('console appeared (again)')

    #ssh_call(p, 'uci set fastd.mesh_vpn.enabled=0')
    #ssh_call(p, 'uci commit fastd')
    #ssh_call(p, '/etc/init.d/fastd stop mesh_vpn')

def gen_etc_hosts_for_netns(netns):
    # use /etc/hosts and extend it
    with open('/etc/hosts') as h:
        if not os.path.exists('/etc/netns/'):
            os.mkdir('/etc/netns')
        if not os.path.exists(f'/etc/netns/{netns}/'):
            os.mkdir(f'/etc/netns/{netns}')
        with open(f'/etc/netns/{netns}/hosts', 'w') as f:
            f.write(h.read())
            f.write('\n')
            f.write(host_entries)

host_entries = ""

def run_all():
    loop = asyncio.get_event_loop()

    host_id = 1
    global host_entries

    for node in Node.all_nodes:
        host_entries += f"{SITE_LOCAL_PREFIX}:5054:{host_id}ff:fe{node.id:02x}:3402 {node.hostname}\n"
        client_name = node.hostname.replace('node', 'client')
        host_entries += f"{SITE_LOCAL_PREFIX}:a854:{host_id}ff:fe{node.id:02x}:3402 {client_name}\n"

    for node in Node.all_nodes:
        loop.create_task(gen_qemu_call(image, node))
        loop.create_task(read_to_buffer(node))
        loop.create_task(install_client(initial_time, node))

    loop.run_forever()


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
