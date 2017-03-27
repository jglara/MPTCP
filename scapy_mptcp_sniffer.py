#!/usr/bin/env python
import sys
from scapy.all import *
from optparse import OptionParser

from Queue import Queue
from threading import Thread
import time, random

import argparse


parser = argparse.ArgumentParser(description="scapy sniffer and forwarding tool")

parser.add_argument('--up', '-u',
                    help="uplink dev",
                    dest="uplink",
                    default='r1-eth1',
                    type=str)

parser.add_argument('--up2', '-v',
                    help="uplink dev 2",
                    dest="uplink2",
                    default='r1-eth2',
                    type=str)


parser.add_argument('--down', '-d',
                    help="downlink dev",
                    dest="downlink",
                    default='r1-eth3',
                    type=str)

parser.add_argument('--fup', 
                    help="uplink filter",
                    dest="fuplink",
                    default='src net 10.0.0.0/24',
                    type=str)

parser.add_argument('--fup2', 
                    help="uplink filter 2",
                    dest="fuplink2",
                    default='src net 10.0.1.0/24',
                    type=str)


parser.add_argument('--fdown',
                    help="downlink filter",
                    dest="fdownlink",
                    default='src net 10.0.2.0/24',
                    type=str)


args = parser.parse_args()

sUp = conf.L2socket(iface=args.uplink)
sUp2 = conf.L2socket(iface=args.uplink2)
sDown = conf.L2socket(iface=args.downlink)

ADD_ADDR_SENT = 0

def action_on_dev_up(pkt):
    if IP in pkt:
        if TCP in pkt:
#            print "Pkt received in uplink %s:%s -> %s:%s (%s,%s,%s). Sending downlink side" % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, pkt[IP].id, pkt[TCP].seq, pkt[TCP].ack)

            l4 = pkt[TCP]
            for o in l4.options:
                if o.kind == 30:
                    opt = o.mptcp
                    s = MPTCP_subtypes[opt.subtype] 
                    print "uplink MPTCP message %s" % s
                    if s == "MP_CAPABLE":
                        print "Found MP_CAPABLE tcp.flags=%s sender_key=%s checksum_req=%s hmac_sha1=%s" %(l4.flags, opt.snd_key, opt.checksum_req, opt.hmac_sha1)
#                        if (tcp.flags & 0x02) and (tcp.flags & 0x10): # SYNACK
                            
                    elif s == "MP_JOIN":
                        print "Found MP_JOIN tcp.flags=%s" %(l4.flags)
                    elif s == "MP_ADD_ADDR":
                        print "Found ADD_ADDR"
                    elif s == "DSS":
                        print "Found DSS"
            

        for p in fragment(pkt[IP]):
            sDown.send(Ether()/p)        

def action_on_dev_down(pkt):

    if IP in pkt:
        if TCP in pkt:
#            print "Pkt received in downlink %s:%s -> %s:%s (%s,%s,%s). Sending downlink side" % (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport, pkt[IP].id, pkt[TCP].seq, pkt[TCP].ack)

            l4 = pkt[TCP]
            for o in l4.options:
                if o.kind == 30:
                    opt = o.mptcp
                    s = MPTCP_subtypes[opt.subtype] 
                    print "downlink MPTCP message %s" % s
                    if s == "MP_CAPABLE":
                        print "Found MP_CAPABLE tcp.flags=%s sender_key=%s checksum_req=%s hmac_sha1=%s" %(l4.flags, opt.snd_key, opt.checksum_req, opt.hmac_sha1)
#                        if (tcp.flags & 0x02) and (tcp.flags & 0x10): # SYNACK
                            
                    elif s == "MP_JOIN":
                        print "Found MP_JOIN tcp.flags=%s" %(l4.flags)
                    elif s == "MP_ADD_ADDR":
                        print "Found ADD_ADDR"

                    elif s == "DSS":
                        global ADD_ADDR_SENT
                        if ADD_ADDR_SENT == 0:
                            print "Adding ADD_ADDR in DSS"
                            
#                            newpkt = Ether() / IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack, options=[TCPOption_MP(mptcp=MPTCP_AddAddr(ipver=4, address_id=1, adv_addr="10.0.1.20"))])
#                            sUp.send(newpkt)

##
#                            pkt[TCP].options.append(TCPOption_MP(mptcp=MPTCP_AddAddr(ipver=4, address_id=1, adv_addr="10.0.1.20")))
#                            pkt[TCP].options.append(TCPOption_NOP())
#                            pkt[TCP].chksum=None
#                            str(pkt)
                            ADD_ADDR_SENT=1

        if pkt[IP].dst == "10.0.0.10":
            for p in fragment(pkt[IP]):
                sUp.send(Ether()/p)
        else:
            for p in fragment(pkt[IP]):
                sUp2.send(Ether()/p)
            

def sniff_up():
    sniff(iface=args.uplink, filter = args.fuplink, prn = action_on_dev_up)

def sniff_up_2():
    sniff(iface=args.uplink2, filter = args.fuplink2, prn = action_on_dev_up)

def sniff_down():
    sniff(iface=args.downlink, filter = args.fdownlink, prn = action_on_dev_down)


if __name__ == '__main__':

    print "Sniffing dev-Up"
    p_up = Thread(target=sniff_up)
    p_up.setDaemon(True)
    p_up.start()

    print "Sniffing dev-Up"
    p_up2 = Thread(target=sniff_up_2)
    p_up2.setDaemon(True)
    p_up2.start()



    print "Sniffing dev-down"
    p_down = Thread(target=sniff_down)
    p_down.setDaemon(True)
    p_down.start()

    threads = []
    [threads.append(t) for t in [p_up, p_up2, p_down]]

    for t in threads:
        t.join()


