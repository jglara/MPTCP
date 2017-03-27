#!/usr/bin/python2

"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

import nfqueue
from scapy.all import *
import os
import hashlib
import hmac
import math


# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
#iptablesr = "iptables -A OUTPUT -j NFQUEUE"

# If you want to use it for MITM :
iptablesr = "iptables -A FORWARD -j NFQUEUE"

print("Adding iptable rules :")
print(iptablesr)
os.system(iptablesr)


def key2tokenAndDSN(key):
    """Returns the token and dsn from a key
    Generate a simple SHA1 hash of the key

    key is a 64bits integer
    Token is a 32bits integer, dsn is a 64bits integer
    """
    import binascii
    keystr = struct.pack("!Q", key)
    h = hashlib.sha1(keystr.rjust(8,'\00'))
    shastr=h.digest() # binary
    #shastr = struct.pack("!IIIII", *struct.unpack("@IIIII",shastr)) #to net
    token, dsn = shastr[0:4], shastr[-8:]
    #print "raw: %s (len=%i)"%(shastr,len(shastr)) 
    #print "hex: %s"% binascii.hexlify(token), "%s"%binascii.hexlify(dsn)
    d1, d2 = struct.unpack("!II",dsn)
    token, dsn = (struct.unpack("!I",token)[0], (long(d2)<<32)+d1)
    #print "token: %x"% token
    #print "dsn: %x" % dsn
    return (token, dsn)

def randintb(n):
    """Picks a n-bits value at random"""
    return random.randrange(0, 1L<<n)



class DSSMapList(object):
    def __init__(self):
        self.map= []
        
    def add(self, dssmap):
        self.map.append(dssmap)

    def find(self,x):
        next( n for n in self.map if n[0].check(x) )        
        

class DSSMap(object):
    def __init__(self,range_from, range_to):
        self.range_from= range_from
        self.range_to = range_to
        assert len(range(range_from[0], range_from[1])) == \
            len(range(range_to[0], range_to[1]))

    def check(self,x):
        return x in range(range_from[0],range_from[1]+1)

    def transform(self,x):
        return range_to[0] + (x-range_from[0])
    


class MPTCPProxy(object):
    states = ['init', 'wait_syn_ack', 'wait_ack', 'established']

    def __init__(self):
        self.rcv_token = 0
        self.snd_token = 0
        self.snd_key = 0
        self.rcv_key = 0


        self.ms_port = 0 # UE side port
        self.last_seq = 0
        self.last_ack = 0

        self.state = 'init'

    def run(self, payload):
        data = payload.get_data()
        pkt = IP(data)

        print "Pkt rcv"

        if TCP in pkt:
            l4 = pkt[TCP]
            if self.state == 'init':
                self.init_state(payload, pkt)
            elif self.state == 'wait_syn_ack':
                self.wait_syn_ack(payload, pkt)
            elif self.state == 'wait_ack':
                self.wait_ack(payload, pkt)
            elif self.state == 'established':
                self.established(payload, pkt)
                        
        #payload.set_verdict(nfqueue.NF_ACCEPT)
        return 1

    def remove_mptcp(self, pkt):
        l3 = pkt[IP]
        l4 = pkt[TCP]

        newPkt = IP( version=l3.version,tos=l3.tos,id=l3.id, flags=l3.flags, frag=l3.frag, ttl=l3.ttl, proto=l3.proto, src=l3.src, dst=l3.dst, options=l3.options) / \
                 TCP(sport=l4.sport,dport=l4.dport,seq=l4.seq,ack=l4.ack,flags=l4.flags,window=l4.window,options=[opt for opt in l4.options if opt.kind != 30]) /\
                 l4.payload

        return newPkt

    def add_mptcp(self, pkt, opt):
        l3 = pkt[IP]
        l4 = pkt[TCP]

        newPkt = IP( version=l3.version,tos=l3.tos,id=l3.id, flags=l3.flags, frag=l3.frag, ttl=l3.ttl, proto=l3.proto, src=l3.src, dst=l3.dst, options=l3.options) / \
                 TCP(sport=l4.sport,dport=l4.dport,seq=l4.seq,ack=l4.ack,flags=l4.flags,window=l4.window,options=l4.options) /\
                 l4.payload

        newPkt[TCP].options.append(opt)
        
        return newPkt
        

    def init_state(self, payload, pkt):
        print "init state"

        # look for MP_CAPABLE
        try:
            opt = next(o.mptcp for o in pkt[TCP].options if o.kind == 30 and o.mptcp.subtype == 0x00)

            self.rcv_key = opt.snd_key
            self.rcv_token,dsn = key2tokenAndDSN(self.rcv_key)
            self.ms_port = pkt[TCP].sport

            # 
            newPkt = self.remove_mptcp(pkt)
            newPkt.show2()
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(newPkt), len(newPkt))
            self.state = 'wait_syn_ack'

        except StopIteration:
            payload.set_verdict(nfqueue.NF_ACCEPT)


    def wait_syn_ack(self, payload, pkt):
        print "wait syn ack"
        # TODO: check flags & ack number

        # Generate snd_key
        self.snd_key = randintb(64)
        self.rcv_token,dsn = key2tokenAndDSN(self.snd_key)

        # Add MpTcp option
        newPkt = self.add_mptcp(pkt, TCPOption_MP(mptcp=MPTCP_CapableSYNACK(snd_key= self.snd_key)))
        newPkt.show2()
        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(newPkt), len(newPkt))
        self.state = 'wait_ack'

    def wait_ack(self, payload, pkt):
        print "wait_ack"

        # check MP_CAPABLE existence
        try:
            opt = next(o.mptcp for o in pkt[TCP].options if o.kind == 30 and o.mptcp.subtype == 0x00)
        except StopIteration:
            payload.set_verdict(nfqueue.NF_DROP)

        # check DSS


        # remove MpTcp option
        newPkt = self.remove_mptcp(pkt)
        newPkt.show2()
        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(newPkt), len(newPkt))

        self.state = 'established'
        
    def established(self, payload, pkt):
        print "established"

        if not TCP in packet:
            return 1

        # packet comes from UE side
        if pkt[TCP].dport == self.ms_port:
            print "packet comes from ue side"

            # check for DSS
            try:
                opt = next(o.mptcp for o in pkt[TCP].options if o.kind == 30 and o.mptcp.subtype == 0x02)                
                # DSS 
                if (mptcp_dss_contains_flag(opt.flags, 'M') or mptcp_dss_contains_flag(opt.flags, 'm')):
                    dsn_init = opt.sdn
                    dsn_end = opt.sdn + opt.datalevel_len
                    
                    ssn_init= pkt[TCP].seq
                    ssn_end = pkt[TCP].seq + len(pkt[TCP].payload)
                    

                

                dack = opt.data_ack
                

            except StopIteration:            
                pass

            # transform seq/ack 
        
            newPkt = self.remove_mptcp(pkt)
            newPkt.show2()
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(newPkt), len(newPkt))

        
            


def main():
    proxy = MPTCPProxy()
    # This is the intercept
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(lambda i,payload: proxy.run(payload))
    q.create_queue(0)
    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')


if __name__ == "__main__":
    main()


