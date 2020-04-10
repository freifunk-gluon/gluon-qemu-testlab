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

def ensure_iperf3(node):
    status, _ = node.execute('test -f /usr/bin/iperf3')
    if status != 0:
        node.succeed('gluon-wan opkg update && gluon-wan opkg install iperf3')

ensure_iperf3(a)
ensure_iperf3(b)

rule = """
config rule 'iperf3'
        option dest_port '5201'
        option src 'mesh'
        option name 'iperf3'
        option target 'ACCEPT'
        option proto 'tcp'
"""

status, _ = b.execute('grep iperf3 /etc/config/firewall > /dev/null')
if status != 0:
    b.succeed('cat >> /etc/config/firewall <<EOF \n' + rule)
    b.succeed('/etc/init.d/firewall restart')

a.succeed('ubus wait_for network.interface.bat0')
b.succeed('ubus wait_for network.interface.bat0')

iperf_server = b.execute_in_background('iperf3 -V -s')

a.wait_until_succeeds(f'iperf3 -V -c {b.hostname}')

iperf_server.cancel()

finish()
