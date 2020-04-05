#!/usr/bin/python36
import sys
sys.path.append(".")
from pynet import *
import asyncio
import time
import json

a = Node()
b = Node()

connect(a, b)

start()                                        # This command boots the qemu instances

expect_success(ssh(b, "ping -c 5 node1"))
sync(retries=10)

def neighbourinfo(req):
    res = stdout(ssh(b, f"gluon-neighbour-info -d ff02::2:1001 -p 1001 -r {req} -i eth2 -c 2"))
    ret = []
    for line in res.split('\n'):
        if not line:
            continue

        ret.append(json.loads(line))

    print(req.upper() + ":")
    print(json.dumps(ret, indent=4))
    return ret

neighbourinfo('nodeinfo')
neighbourinfo('statistics')
neighbours = neighbourinfo('neighbours')

eth2_addr_a = stdout(ssh(a, "cat /sys/class/net/eth2/address")).strip()
eth2_addr_b = stdout(ssh(b, "cat /sys/class/net/eth2/address")).strip()

res0 = neighbours[0]['batadv']
res1 = neighbours[1]['batadv']
if eth2_addr_a in res0:
    res = res0
else:
    res = res1

batadv_neighbours = res[eth2_addr_a]["neighbours"]

if eth2_addr_b in batadv_neighbours:
    print('Node 1 was successfully found in neighbours of node 2.')
else:
    print('ERROR: Node 1 was not found in neighbours of node 2.')
    exit(1)

finish()
