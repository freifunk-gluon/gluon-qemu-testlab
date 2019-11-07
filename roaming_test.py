#!/usr/bin/env python3

from pynet import *
import time

a, b, c, d = Node(), Node(), Node(), Node()

m1 = MobileClient()

print('move to node1')
m1.move_to(a)
time.sleep(30)

print('move to node2')
m1.move_to(b)
time.sleep(30)

print('move to node3')
m1.move_to(c)
time.sleep(30)

print('move to node4')
m1.move_to(d)
time.sleep(30)
