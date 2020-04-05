#!/usr/bin/env python3
import sys
sys.path.append(".")
from pynet import *

a = Node()

start()

ssh(a, "gluon-reconfigure")
sync()

finish()

