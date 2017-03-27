#!/usr/bin/perl -w

my $i=0;
my $read_next=0;

while (<>) {
    my ($rtt,$rto,$cwnd,$ssthresh,$unacked, $retrans) = (0,0,0,0,0,0);

    if (/rtt:(.*?)\/(\d*)/) {
	$rtt=$1;
    }
    
    if (/rto:(\d*)/) {
	$rto=$1;
    }
    
    if (/cwnd:(\d*)/) {
	$cwnd=$1;
    }
    
    if (/ssthresh:(\d*)/) {
	$ssthresh=$1;
    }
    
    if (/unacked:(\d*)/) {
	$unacked=$1;
    }
    
    if (/retrans:(\d*)\/(\d*)/) {
	$retrans=$1;
    }
    
	
    print "$i $rtt $rto $cwnd $ssthresh $unacked $retrans\n";
    $i=$i+1;
  

}
