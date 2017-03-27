#!/usr/bin/python

"Networking Assignment 2"

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import lg, output
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import irange, custom, quietRun, dumpNetConnections
from mininet.cli import CLI

from time import sleep, time
from multiprocessing import Process
from subprocess import Popen
import argparse

import sys
import os
from linuxrouter_switch import NetworkTopo

parser = argparse.ArgumentParser(description="Topology bandwith and TCP tests")

parser.add_argument('--dir', '-d',
                    help="Directory to store outputs",
                    default="results")

parser.add_argument('--cli', '-c',
                    action='store_true',
                    help='Run CLI for topology debugging purposes')

parser.add_argument('--time', '-t',
                    dest="time",
                    type=int,
                    help="Duration of the experiment with iperf -R.",
                    default=0)


# Expt parameters
args = parser.parse_args()

if not os.path.exists(args.dir):
    os.makedirs(args.dir)

lg.setLogLevel('info')

def waitListening(client, server, port):
    "Wait until server is listening on port"
    if not 'telnet' in client.cmd('which telnet'):
        raise Exception('Could not find telnet')
    cmd = ('sh -c "echo A | telnet -e A %s %s"' %
           (server.IP(), port))
    while 'Connected' not in client.cmd(cmd):
        output('waiting for', server,
               'to listen on port', port, '\n')
        sleep(.5)

def progress(t):
       # Begin: Template code
    while t > 0:
        print '  %3d seconds left  \r' % (t)
        t -= 1
        sys.stdout.flush()
        sleep(1)



def run_topology_experiment(net):
    "Run experiment"

    seconds = args.time

    # Get receiver and clients
    recvr = net.getNodeByName(args.server)
    sender = net.getNodeByName('h1')

    print "Starting iperf on the sender"
    if (seconds>0):
        sender.sendCmd('iperf3 -c %s -p 5001 -w 512K -t %d -R> %s/iperf_client.txt' % (recvr.IP(), seconds, args.dir))

    # Turn off and turn on links
    print "waiting for the sender to finish"
    sender.waitOutput()

def main():
    "Create and run experiment"
    start = time()

    topo = NetworkTopo()

    host = custom(CPULimitedHost)  
    net = Mininet(topo=topo, host=host )

    net.start()

    print "*** Dumping network connections:"
    dumpNetConnections(net)

    if args.cli:
        # Run CLI instead of experiment
        CLI(net)
    else:
        print "*** Running experiment"
        #run_topology_experiment(net)

    net.stop()

    end = time()
#    os.system("killall -9 tshark")
#    os.system("chown mininet:mininet /tmp/*.cap ; mv /tmp/*.cap %s" % (args.dir))
    print "Experiment took %.3f seconds" % (end - start)

if __name__ == '__main__':
    main()
