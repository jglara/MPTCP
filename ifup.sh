#/bin/bash

echo "Up iface $1"
ip link set h1-eth$1 up

if [ "$1" == "1" ]; then
    ip route add 10.0.1.0/24 dev h1-eth1 scope link table 1
    ip route add default via 10.0.1.20 dev h1-eth1 table 1    
else
    ip route add 10.0.4.0/24 via 10.0.2.30 dev h1-eth2
    ip route add 10.0.2.0/24 dev h1-eth2 scope link table 2
    ip route add default via 10.0.2.30 dev h1-eth2 table 2    
fi

