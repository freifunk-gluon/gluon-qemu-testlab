#!/usr/bin/python36
import sys
sys.path.append(".")
from pynet import *
import asyncio
import time

a = Node()
b = Node()

connect(a, b)

loop = configure_all()
# loop = asyncio.get_event_loop()

p_id = 1
processes = {}
async def _ssh(p):
    n = p['node']
    cmd = p['cmd']
    global processes
    async with Node.ssh_conn(n) as c:
        res = await c.create_process(cmd)
        p['process'] = res
        return await res.wait()

def ssh(node, cmd):
    global p_id
    global processes

    p = { "node": node, "process": None, "task": None, "exit_with_others": False, "cmd": cmd, "expect_success": False }
    processes[p_id] = p
    p_id += 1

    return p

def ssh_singlecmd(node, cmd):
    ssh(node, cmd)
    sync()

def exit_with_others(p):
    p['exit_with_others'] = True
    return p

def expect_success(p):
    p['expect_success'] = True
    return p

def _sync():
    global processes

    for proc in processes.values():
        proc['task'] = loop.create_task(_ssh(proc))

    for proc in processes.values():
        if proc['exit_with_others']:
            continue

        loop.run_until_complete(proc['task'])

    for proc in processes.values():
        p = proc['process']
        t = proc['task']

        if p.exit_status is None:
            print('sending SIGINT to "' + p.command + '"')
            p.send_signal('INT')
        else:
            print('command "' + p.command + '" exited with status code ' + str(p.exit_status))
            print('stdout:')
            print(t.result().stdout)
            print('stderr:')
            print(t.result().stderr)

    success = True
    for proc in processes.values():
        if proc['expect_success'] and proc['process'].exit_status > 0:
            success = False

    if success:
        processes = {}

    return success

def sync(retries=1, sleep=5):
    while True:
        success = _sync()
        if success:
            break

        retries -= 1

        if retries < 1:
            close_qemus()
            print('TESTS FAILED!')
            exit(1)

        print('retrying. ' + str(retries) + ' retries left. retrying in ' + str(sleep) + ' seconds.')
        time.sleep(sleep)
        print('retrying now.')


rule = """
config rule 'iperf3'                          
        option dest_port '5201'               
        option src 'mesh'                     
        option name 'iperf3'                  
        option target 'ACCEPT'                
        option proto 'tcp'
"""

ssh_singlecmd(b, 'grep iperf3 /etc/config/firewall >/dev/null || cat >> /etc/config/firewall <<EOF \n' + rule)
ssh_singlecmd(b, 'grep iperf3 /etc/config/firewall >/dev/null || /etc/init.d/firewall restart')

ssh(b, 'ubus wait_for network.interface.bat0')
ssh(a, 'ubus wait_for network.interface.bat0')
sync()

exit_with_others(ssh(b, 'iperf3 -V -s'))
expect_success(ssh(a, 'sleep 3; iperf3 -V -c node2'))
sync(retries=10)

close_qemus()