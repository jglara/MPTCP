#!/usr/bin/env python2
import traceback, sys
from scapy.all import *
from tests.core import *
import hashlib
import hmac
import math
import socket



pkt = IP(version=4L,dst="10.0.2.30", src="10.0.0.10")/ \
      TCP(dport=5001,
          sport=1000,
          flags="S",
          seq=1000,
          options=[TCPOption_MP(mptcp=MPTCP_CapableSYN(checksum_req=1, snd_key=1111))]
      )

pkt[TCP].options.append(TCPOption_MP(mptcp=MPTCP_AddAddr(ipver=4, address_id=1, adv_addr="10.0.1.20")))

sendp(Ether()/pkt, iface="h1-eth1")
