#!/bin/bash

DPISIM_HOME=/home/mininet/git/MPTCP/sasn

CONFIG=$DPISIM_HOME/$1
SS=$2

#SS=ss-ccc-1
#CONFIG=$DPISIM_HOME/ce_tfo.xml
#CONFIG=$DPISIM_HOME/tfo_redirect.xml

DEV_UP=r3-eth1
DEV_UP2=r3-eth2
DEV_DOWN=r3-eth3


CELL_IP=10.0.1.10
PLAT=SASN

LOGFILE=$DPISIM_HOME/dpi.logfile.log

rm $LOGFILE

#REDIR="--redir-si=112 --redir-uri=http://172.16.0.100/http/show_me_the_money.html --redir-ind=1"


#POC_ARGS="--seed=100 --oqueue-p=0.3 --oqueue-q=0.7 --oqueue-avg=120 --oqueue-maxdev=1000 --oqueue-size=15"

#LOGSPARS="--enable-logs=true --dpi-all-logs=true --save-piscinfo=$DPISIM_HOME/piscinfo.out"
LOGSPARS="--enable-logs=false --dpi-all-logs=false"
#taskset -c 0
#echo LD_LIBRARY_PATH=$DPISIM_HOME/dpisim_libs  $DPISIM_HOME/dpisim --routing --flavour=$PLAT --backend-config-file=$CONFIG --service-set=$SS --filter-down=\"src net 172.16.51.0/24\" --filter-up=\"src net 192.168.12.0/24\" -c=$CELL_IP -k=255.255.0.0 --devDown=$DEV_DOWN --devUp=$DEV_UP --log-file=$LOGFILE --imsi=56000000056 --msisdn=1234567890 --sgsn=1.2.2.1 --ggsn=1.2.3.4 --charging-id=978  $LOGSPARS $POC_ARGS

LD_LIBRARY_PATH=$DPISIM_HOME/dpisim_libs $DPISIM_HOME/dpisim --routing --flavour=$PLAT --backend-config-file=$CONFIG --service-set=$SS  --filter-up="tcp and src net 10.0.1.0/24" --filter-up="tcp or src net 10.0.2.0/24" --filter-down="tcp and src net 10.0.5.0/24" -c=$CELL_IP -k=255.255.255.0 --devUp=$DEV_UP,$DEV_UP2 --devUpId=10,20 --devDown=$DEV_DOWN --devDownId=30  --log-file=$LOGFILE --imsi=56000000056 --msisdn=1234567890 --sgsn=1.2.2.1 --ggsn=1.2.3.4 --charging-id=978  $LOGSPARS --routing-timer=true 


