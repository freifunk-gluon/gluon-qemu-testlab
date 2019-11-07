#!/usr/bin/env python3
import sys
import random
sys.path.append(".")
from pynet import *

NODE_COUNT = 30

nodes = []

for i in range(NODE_COUNT):
    n = Node()

    if len(nodes) > 0:
        connect(n, random.choice(nodes))

    nodes.append(n)

start()
finish()

