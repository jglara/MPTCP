#!/bin/bash -x


./filter_bw.pl --flow=1 sasn/dpi.logfile.log > /tmp/bw.txt
./filter_bw.pl --flow=2/filter_bw.pl --flow=1 sasn/dpi.logfile.log sasn/dpi.logfile.log > /tmp/bw2.txt

# set data style linespoints                                                                                              
gnuplot -persist <<EOF

 show timestamp                                                                                                          
 set title "BW"                                                                                                          
 set ylabel "pkts"                                                                                                      
 plot "/tmp/bw.txt" using 1:5 title 'BW #1' with lines, "/tmp/bw2.txt" using 1:5 title 'BW #2' with lines
EOF

