#!/usr/bin/python

import sys
import os
sys.path.append(".")
from pynet import *

DIR = os.path.dirname(__file__)

def read_key(path):
    with open(path) as f:
        return f.read().replace('\n', '')

for f in os.listdir(DIR):
    if not os.path.isdir(DIR + '/' + f):
        continue

    secret = read_key(DIR + '/' + f + '/secret')

    node = Node()
    node.hostname = f
    node.set_fastd_secret(secret)

    dom_id = int(f.split('-')[-1])
    node.set_domain('dom%d' % dom_id)

    node.site_local_prefix = 'fdca:ffee:8:%d' % dom_id
    node.next_node_addr = node.site_local_prefix + '::1'


run_all()

