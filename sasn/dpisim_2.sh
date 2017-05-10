#!/bin/bash

DPISIM_HOME=/home/mininet/git/MPTCP/sasn

CONFIG=$DPISIM_HOME/$1
rm $DPISIM_HOME/dpi.logfile.log

LD_LIBRARY_PATH=$DPISIM_HOME/dpisim_libs $DPISIM_HOME/dpisim --dpisim-config-file=$CONFIG


