#!/usr/bin/env python3
import sys
sys.path.append(".")
from pynet import *

# see https://www.open-mesh.org/attachments/download/42/bottle.png

a = Node()

n1, n2 = Node(), Node()

connect(a, n1)
connect(n1, n2)

n3, n4, n5 = Node(), Node(), Node()
n6, n7, n8 = Node(), Node(), Node()

connect(n2, n3)
connect(n3, n4)
connect(n4, n5)

connect(n2, n6)
connect(n6, n7)
connect(n7, n8)

b = Node()

connect(b, n5)
connect(b, n8)

start()
finish()

