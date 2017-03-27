#!/usr/bin/python2

"""
    Use scapy to modify packets going through your machine.
    Based on nfqueue to block packets in the kernel and pass them to scapy for validation
"""

import nfqueue
from scapy.all import *
import os

# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
#iptablesr = "iptables -A OUTPUT -j NFQUEUE"

# If you want to use it for MITM :
iptablesr = "iptables -A FORWARD -j NFQUEUE"

print("Adding iptable rules :")
print(iptablesr)
os.system(iptablesr)



# If you want to use it for MITM attacks, set ip_forward=1 :
#print("Set ipv4 forward settings : ")
#os.system("sysctl net.ipv4.ip_forward=1")

def callback(i,payload):
    # Here is where the magic happens.
    data = payload.get_data()
    pkt = IP(data)
#    print("Got a packet ! source ip : " + str(pkt.src))
#    if pkt.src == "192.168.1.2":
#        # Drop all packets coming from this IP
#        print("Dropped it. Oops")
#        payload.set_verdict(nfqueue.NF_DROP)
#    else:
#        # Let the rest go it's way
#        payload.set_verdict(nfqueue.NF_ACCEPT)
    # If you want to modify the packet, copy and modify it with scapy then do :
    # print "packet src=%s dst=%s" %(pkt[IP].src, pkt[IP].dst)
    if TCP in pkt:
        l4 = pkt[TCP]
            
        add_addr=False
        for o in l4.options:
            if o.kind == 30:
                opt = o.mptcp
                s = MPTCP_subtypes[opt.subtype] 
                print "%s->%s MPTCP message %s" % (pkt[IP].src, pkt[IP].dst, s)
                if pkt[IP].src == "10.0.2.30" and s == "DSS":
                    add_addr=True
                elif pkt[IP].dst == "10.0.1.99" and s == "MP_JOIN":
                    print "Received MP_JOIN"
                    # drop it for the time being
                    payload.set_verdict(nfqueue.NF_DROP)
                    


        if add_addr:
            print "Sending ADD_ADDR"
            
            l3 = pkt[IP]
            newPkt = IP( version=l3.version,tos=l3.tos,id=l3.id, flags=l3.flags, frag=l3.frag, ttl=l3.ttl, proto=l3.proto, src=l3.src, dst=l3.dst, options=l3.options) / TCP(sport=l4.sport,dport=l4.dport,seq=l4.seq,ack=l4.ack,flags=l4.flags,window=l4.window,options=l4.options) / l4.payload
            newPkt[TCP].options.append(TCPOption_MP(mptcp=MPTCP_AddAddr(ipver=4, address_id=10, adv_addr="10.0.1.99")))


            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(newPkt), len(newPkt))
            return 1
#                    # 

#
    payload.set_verdict(nfqueue.NF_ACCEPT)
    return 1

def main():
    # This is the intercept
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
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
