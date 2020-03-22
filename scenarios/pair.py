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

# API Description:
#
# ssh(n, c)        - enqueues a command c on node n, but does not yet run them
# sync()           - runs all enqueued commands simultaneously till they end
# check(ssh(n, c)) - the command c is started directly on node n and check() will only return after it is finished.
#                    check() returns True, if the return code was successful.

rule = """
config rule 'iperf3'                          
        option dest_port '5201'               
        option src 'mesh'                     
        option name 'iperf3'                  
        option target 'ACCEPT'                
        option proto 'tcp'
"""

if not check(ssh(b, 'grep iperf3 /etc/config/firewall >/dev/null')):
    ssh_singlecmd(b, 'cat >> /etc/config/firewall <<EOF \n' + rule)
    ssh_singlecmd(b, '/etc/init.d/firewall restart')

ssh(b, 'ubus wait_for network.interface.bat0')
ssh(a, 'ubus wait_for network.interface.bat0')
sync()

exit_with_others(ssh(b, 'iperf3 -V -s'))       # sync() will not wait for this cmd to exit, but
                                               # will interrupt it via SIGINT

expect_success(ssh(a, 'iperf3 -V -c node2'))   # if this command does not return with status code
                                               # equal to 0 the test will fail

sync(retries=10)                               # the tests are performed with 10 retries, because
                                               # initially network might not be set up correctly

finish()
