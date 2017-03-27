#!/usr/bin/python

"""

"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from mininet.link import TCLink
from mininet.link import Link
from mininet.link import TCIntf
from mininet.node import CPULimitedHost

from subprocess import Popen, PIPE
import argparse
import os
from time import sleep, time

class MyTCLink( Link ):
    "Link with symmetric TC interfaces configured via opts"
    def __init__( self, node1, node2, port1=None, port2=None,
                  intfName1=None, intfName2=None,
                  addr1=None, addr2=None, ip1=None, ip2=None, **params ):
        Link.__init__( self, node1, node2, port1=port1, port2=port2,
                       intfName1=intfName1, intfName2=intfName2,
                       cls1=TCIntf,
                       cls2=TCIntf,
                       addr1=addr1, addr2=addr2,
                       params1=params,
                       params2=params )
        if ip1 is not None:
            self.intf1.setIP(ip1)

        if ip2 is not None:
            self.intf2.setIP(ip2)


class MyRouter( Node ):
    "A Node with routing."

    def config( self, **params ):
        super( MyRouter, self).config( **params )
        self.cmd( 'echo $SHELL ; for d in $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1);do ethtool -K $d tso off gso off tx off rx off; done')

        self.cmd( 'echo $SHELL ; for d in $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1);do tshark -i $d -w /tmp/$d.cap & echo "tshark $d" ; done')


        # Add a route the reach sender network
        #self.cmd( 'ip route add 192.168.12.0/24 via 172.16.99.52' )

        # Enable forwarding on the router
        #self.cmd( 'sysctl net.ipv4.ip_forward=1' )
        self.proc = self.popen( '/home/mininet/git/MPTCP/sasn/dpisim.sh basic.conf default')

    def terminate( self ):
        #self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        self.popen("pgrep -f dpisim | xargs kill -9", shell=True).wait()
        self.popen("pgrep -f tshark | xargs kill -9", shell=True).wait()
        super( MyRouter, self ).terminate()


class MyHost( Node ):
    "A Node simple"

    def config( self, **params ):
        super( MyHost, self).config( **params )
#        self.cmd( 'ip link list')
        self.cmd( 'echo $SHELL ; for d in $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1);do ethtool -K $d tso off gso off tx off rx off; done')
#        self.cmd( 'ethtool -K $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1) tso off gso off tx off' )



    def terminate( self ):
        super( MyHost, self ).terminate()

class MyServer( Node ):
    "A Server with Web Server & iperf server"

    def config( self, **params ):
        super( MyServer, self).config( **params )
#        self.cmd( 'ip link list')
#        self.cmd( 'ethtool -K $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1) tso off gso off tx off' )
        self.cmd( 'echo $SHELL ; for d in $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1);do ethtool -K $d tso off gso off tx off rx off; done' )

        # change mtu
        self.cmd( 'echo $SHELL ; for d in $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1);do ip li set $d mtu 1460; done' )



        self.cmd('iperf3 -s -p 5001 &')
        self.cmd('python http/webserver.py&')
#        self.cmd('nginx -c /home/mininet/git/MPTCP/http/nginx.conf')

    def terminate( self ):
        self.popen("pgrep -f iperf3 | xargs kill ", shell=True).wait()
        self.popen('nginx -s stop').wait()
        super( MyServer, self ).terminate()


class NetworkTopo( Topo ):
    "A simple topology of a router with three subnets (one host in each)."

    def sysctl_set(self,key, value):
	"""Issue systcl for given param to given value and check for error."""

	p = Popen("sysctl -w %s=%s" % (key, value), shell=True, stdout=PIPE, stderr=PIPE)
	# Output should be empty; otherwise, we have an issue.	
	stdout, stderr = p.communicate()
	stdout_expected = "%s = %s\n" % (key, value)
	if stdout != stdout_expected:
		raise Exception("Popen returned unexpected stdout: %s != %s" % (stdout, stdout_expected))
	if stderr:
		raise Exception("Popen returned unexpected stderr: %s" % stderr)

    def setup_mptcp(self):
        info("Enabling MPTCP")
	self.sysctl_set('net.mptcp.mptcp_enabled', 1)
	self.sysctl_set('net.mptcp.mptcp_checksum', 0)

    def end_mptcp(self):
        info("Disabling MPTCP")
	self.sysctl_set('net.mptcp.mptcp_enabled', 0)

    def build( self, **_opts ):

        s1 = self.addSwitch('sw1')
        s2 = self.addSwitch('sw2')
        s3 = self.addSwitch('sw3')

        router = self.addNode( 'r1', cls=MyRouter, ip='10.0.0.20/24' )

        # cpu=0.5,
        host = self.addHost( 'h1', ip='10.0.0.10/24', cls=MyHost, 
                           defaultRoute='via 10.0.0.20' )

        server = self.addNode( 's1', ip='10.0.2.30/24', cls=MyServer,
                                defaultRoute='via 10.0.2.20' )


        linkConfig1 = {'bw': 10, 'delay': '10ms', 'loss': 0, 'jitter': 0, 'max_queue_size': 2000 }
        linkConfig2 = {'bw': 10, 'delay': '10ms', 'loss': 0, 'jitter': 0, 'max_queue_size': 2000 }

        # router connections
        self.addLink( s1, router, cls=MyTCLink, intfName2='r1-eth1', ip2='10.0.0.20/24', **linkConfig1)
        self.addLink( s2, router, cls=MyTCLink, intfName2='r1-eth2', ip2='10.0.1.20/24', **linkConfig1)
        self.addLink( s3, router, cls=MyTCLink, intfName2='r1-eth3', ip2='10.0.2.20/24', **linkConfig1)

        # client connections
        self.addLink( s1, host, cls=MyTCLink, intfName2='h1-eth1', ip2='10.0.0.10/24', **linkConfig1)
        self.addLink( s2, host, cls=MyTCLink, intfName2='h1-eth2', ip2='10.0.1.10/24', **linkConfig1)

        # server connections
        self.addLink( s3, server, cls=MyTCLink, intfName2='s1-eth1', ip2='10.0.2.30/24', **linkConfig2)
    

def run():
    "Test MPTCP"
    topo = NetworkTopo()
    net = Mininet( topo=topo )  
    topo.setup_mptcp()
    net.start()

    # route table for mptcp
    h1 = net.getNodeByName('h1')
    h1.cmdPrint('ip rule add from 10.0.0.10 table 1')
    h1.cmdPrint('ip route add 10.0.0.0/24 dev h1-eth1 scope link table 1')
    h1.cmdPrint('ip route add default via 10.0.0.20 dev h1-eth1 table 1')

    h1.cmdPrint('ip rule add from 10.0.1.10 table 2')
    h1.cmdPrint('ip route add 10.0.1.0/24 dev h1-eth2 scope link table 2')
    h1.cmdPrint('ip route add default via 10.0.1.20 dev h1-eth2 table 2')

#    h1.cmdPrint( 'echo $SHELL ; for d in $(ip li | awk \'BEGIN {FS=":"} /^[0-9]+:(.*):/ {print $2}\'  | grep -v lo | cut -d\'@\' -f 1); do ethtool -K $d tso off gso off tx off rx off; done')



    info( '*** Routing Table on Router\n' )
    #print net[ 'r1' ].cmd( 'route' )
    if args.cli:
        CLI( net )
    elif args.get:
        sleep(1)
        if args.ifdown:
            h1 = net.getNodeByName('h1')
            h1.cmd('(sleep 1 ; ip link set h1-eth%s down)&' % args.ifdown)

        h1.sendCmd('mget --delete-after http://%s/%s' % (net.getNodeByName('s1').IP(), args.get))
        
        
        print "waiting for the sender to finish"
        h1.waitOutput()
        sleep(1)

    net.stop()
    topo.end_mptcp()

if __name__ == '__main__':
    setLogLevel( 'info' )
    parser = argparse.ArgumentParser(description="Topology bandwith and TCP tests")
     
    parser.add_argument('--dir', '-d',
                        help="Directory to store outputs",
                        default="results")
    
    parser.add_argument('--cli', '-c',
                        action='store_true',
                        help='Run CLI for topology debugging purposes')

    parser.add_argument('--get', '-g', help="HTTP get file")

    parser.add_argument('--ifdown', '-i', help="get down some interface in h1")

    
    
    # Expt parameters
    args = parser.parse_args()
    
    if not os.path.exists(args.dir):
        os.makedirs(args.dir)
        
    run()
        
