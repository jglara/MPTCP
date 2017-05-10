#/bin/bash

echo "Down iface $1"
ip link set h1-eth$1 down
