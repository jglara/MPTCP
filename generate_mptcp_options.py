from scapy.all import *

def print_c_string(tcphdr):
    print "".join(["\\x%02x" % ord(c) for c in str(tcphdr)[20:] ])

# CAPABLE SYN
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_CapableSYN(checksum_req=1, snd_key=1111111))]))

# CAPABLE ACK
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_CapableACK(checksum_req=1, snd_key=1111111, rcv_key=999999999))]))

# JOIN SYN
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_JoinSYN(addr_id=55, backup_flow=0, rcv_token=222222,snd_nonce=1234567))]))

# JOIN SYN_ACK
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_JoinSYNACK(addr_id=66, backup_flow=1, snd_mac64=123456789,snd_nonce=7654321))]))

# JOIN ACK
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_JoinACK(snd_mac=123456789685968))]))

# DSS ACK 32
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_DSS_Ack(data_ack=1234567))]))
          
# DSS ACK 64
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_DSS_Ack64(data_ack=9876543211111))]))

# DSS MAP 32
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_DSS_Map64_AckMap(flags="Mm", dsn=7654321, subflow_seqnum=12345, datalevel_len=1400))]))

# DSS MAP 2 cksum
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_DSS_Map64_AckMapCsum(flags="Mm", dsn=7654321, subflow_seqnum=12345, datalevel_len=1400, checksum=54321))]))


# alltogether

# DSS MAP 2 cksum
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_DSS_Ack64Map64Csum(flags="AaMmF", data_ack=999999111111, dsn=111111999999, subflow_seqnum=1234567, datalevel_len=9999, checksum=54321))]))

# DSS Add ADDR
#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_AddAddrPort(ipver=4, address_id=55, adv_addr="192.168.1.4", port=5050))]))

#print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_RemoveAddr(addr_ids=[55,66,77]))]))

print_c_string( TCP(options=[TCPOption_MP(mptcp=MPTCP_Fastclose(rcv_key=111111999999))]))




