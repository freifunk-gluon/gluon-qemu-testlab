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

b.wait_until_succeeds("ping -c 5 node1")

def neighbourinfo(req):
    res = b.wait_until_succeeds(f"gluon-neighbour-info -d ff02::2:1001 -p 1001 -r {req} -i eth2 -c 2")
    # build json array line by line
    ret = [json.loads(l) for l in res.split('\n')]

    print(req.upper() + ":")
    print(json.dumps(ret, indent=4))
    return ret

neighbours = neighbourinfo('neighbours')

eth2_addr_a = a.succeed('cat /sys/class/net/eth2/address')
eth2_addr_b = b.succeed('cat /sys/class/net/eth2/address')

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
