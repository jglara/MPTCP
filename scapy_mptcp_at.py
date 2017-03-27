from scapy.packet import *
from scapy.fields import *
from scapy.automaton import *
from scapy.layers.inet import *
from scapy.sendrecv import *


def getMpOption(tcp):
    """Return a generator of mptcp options from a scapy TCP() object"""
    for opt in tcp.options:
        if opt.kind == 30:
            yield opt.mptcp
            
def getMpSubkind(pkt, kind):
    """Return a generator of mptcp kind suboptions from pkt"""
    l4 = pkt.getlayer("TCP")
    for o in getMpOption(l4):
        if MPTCP_subtypes[o.subtype] == kind:
            yield (l4, o)

def checkAndGetMPOption(pkt, kind):
    """Return the first option of subkind kind in pkt
    If no such option exist, an exception is raised"""
    try:
        return getMpSubkind(pkt, kind).next()
    except StopIteration:
        raise Exception("MPTCP option of kind %s not found."%kind)


class MPTCP_Proxy(Automaton):
    def parse_args(self, **kargs):
        Automaton.parse_args(self, **kargs)
        

    def master_filter(self, pkt):
        if (TCP in pkt):
            if (getMpOption(pkt[TCP])):
                return True

    # STATES
    @ATMT.state(initial=1)
    def WAIT_FOR_MPCAPABLE(self):
        print "WAIT for MP_CAPABLE"
        pass

    @ATMT.receive_condition(WAIT_FOR_MPCAPABLE, prio=1)
    def received_packet(self, pkt):
        print "received_packet"
        try:
            (l4, opt) = checkAndGetMPOption(pkt, "MP_CAPABLE")
            print "received MP_CAPABLE snd_key=%s" % opt.snd_key

            # send to the other interface
            sendp(Ether()/pkt[IP], iface="r1-eth3")

            raise self.CAPABLE_RCVD(l4,opt)
        except Exception as e:
            pass
            
            
    @ATMT.state()
    def CAPABLE_RCVD(self,l4,opt):
        print "received MP_CAPABLE snd_key=%s" % opt.snd_key
        raise self.END()


    @ATMT.state(final=1)
    def END(self):
        print "Finishing"


if __name__ == '__main__':
    proxy= MPTCP_Proxy()
    proxy.run()
