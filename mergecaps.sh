#!/bin/bash 

sudo tshark -r /tmp/r3-eth1.cap -Y "tcp.dstport == 80" -w mptcp_1.cap
sudo tshark -r /tmp/r3-eth2.cap -Y "tcp.dstport == 80" -w mptcp_1_2.cap
sudo tshark -r /tmp/r3-eth3.cap -Y "tcp.srcport == 80" -w mptcp_2.cap
mergecap -Fpcap mptcp_1.cap mptcp_1_2.cap mptcp_2.cap -w mptcp.cap
chown mininet:mininet mptcp.cap

rsync -avz --append-verify --progress mptcp.cap ejogarv@eselnts1339.mo.sw.ericsson.se:/home/ejogarv/tests/MPTCP/$1

sudo rm mptcp_1.cap mptcp_2.cap mptcp.cap

