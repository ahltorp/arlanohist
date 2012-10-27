#!/usr/bin/perl
#
# output a simple test script for dummer
#
# $WORKDIR needs to be set in the environment
#

use strict;

my $ifile = "/afs/stacken.kth.se/ftp/pub/OpenBSD/3.8/src.tar.gz";
my $ofile;
my $command = "dd bs=1 if=$ifile";

my ($i, $j);
my ($offset, $length);
my $bsize = 8192;
my $fsize = 104553952;
my $hashval;
my $zerohash;
my $zerolen = 8;
my $olength;
my @valid; #ranges of valid data

sub gethash {
    my $off = shift;
    my $len = shift;
    my $res = `$command skip=$off count=$len 2> /dev/null |sha1sum`;
    $res =~ /^([0-9a-f]+)/ and return $1;
}

sub getzerohash {
    my $res = `dd bs=1 if=/dev/zero count=$zerolen 2> /dev/null |sha1sum`;
    $res =~ /^([0-9a-f]+)/ and return $1;
}

sub blockoffset {
    my $off = shift;
    return $off - ($off % $bsize);
}

# add (offset,length) to list of valid ranges, and return (head, tail)
#to indicate whether data before/after the range is expected to be
#zeros: 0 for zeros, 1 for anything else.

sub updatevalid {
    my $start = shift;
    my $length = shift;
    my $finish = $start + $length;

    my $zerohead = 0;
    my $zerotail = 0;

    if ($start < $zerolen) {
	$zerohead = 1;
    }

    if ($finish > ($olength - $zerolen)) {
	$zerotail = 1;
    }

    foreach (@valid) {
	my ($off, $len) = @$_;
	my $begin = $off - $zerolen;
	my $end = $off + $len + $zerolen;

	if ($begin < 0) {
	    $begin = 1;
	}

	if ($end <= $start || $begin >= $finish) {
	    next; #we're all clear of this range
	} else {
	    if ($off < $start) {
		$zerohead = 1;
	    }
	    
	    if (($off + $len) > $finish) {
		$zerotail = 1;
	    }
	}
    }
    
    push(@valid, [$start, $length]);

    return ($zerohead, $zerotail);
}


$ofile = $ENV{'WORKDIR'} or die "please set WORKDIR\n";
$ofile = "$ofile/fil";

#make sure that the target file exists, dummer doesn't do create yet
open(OFILE, ">$ofile") || die "couldn't modify $ofile\n";
close(OFILE);
print STDERR "working in $ofile\n";



$zerohash = getzerohash();

#offsets and lengths
my @offs = (
	    [$bsize, 1],
	    [$bsize - 1, 1],
	    [$bsize - 1, 2],
	    [1, $bsize * 2 - 1],
	    [$bsize * 32, 1],
	    [int($fsize/2), 3],
	    [int($fsize/2), $bsize * 2 + 15],
	    [$fsize - 12, 12],
	    [$fsize - 2*$bsize - 1, 2*$bsize]
	    );
my @hashes;

#generate list with content hashes
foreach (@offs) {
    ($offset, $length) = @$_;
    $hashval = gethash($offset, $length);
    push(@hashes, [$offset, $length, $hashval]);
}

#try reading all our regions
print "open $ifile 0 1\n";
foreach(@hashes) {
    ($offset, $length, $hashval) = @$_;
    print "read 1 $offset $length $hashval 0\n";
}
print "close 1\n";

print "flush $ifile\n";

#try reading all our regions, flushing in between
foreach(@hashes) {
    ($offset, $length, $hashval) = @$_;

    print "open $ifile 0 1\n";
    print "assertnodata 1 0 " . $fsize . "\n";
    print "read 1 $offset $length $hashval 0\n";
    print "flush $ifile\n";
    print "close 1\n";
}

#start writing w/ empty file
print "open $ofile 1 2\n";
print "truncate 2 0\n";
print "close 2\n";

print "open $ifile 0 1\n";

#do some individual writes, truncates, ...
foreach(@hashes) {
    ($offset, $length, $hashval) = @$_;

    print "flush $ofile\n";

    print "open $ofile 1 2\n";
    print "assertnodata 2 0 " . $fsize . "\n";

    print "truncate 2 $offset\n";
    print "assertlen 2 $offset\n";
    print "copy 1 $offset 2 $offset $length\n";
    print "assertlen 2 " . ($offset + $length) . "\n";

    #make sure we get the correct data when reading back
    print "read 2 $offset $length $hashval 0\n";
    print "assertnodata 2 0 " . blockoffset($offset) . "\n";
    print "assertnodata 2 "
	. blockoffset($offset + $length + $bsize) . " "
	. $fsize . "\n";
    
    print "close 2\n";
}

#reset output file
print "open $ofile 1 2\n";
print "truncate 2 0\n";
print "close 2\n";
print "flush $ofile\n";
$olength = 0;

#do a series of writes
print "open $ofile 1 2\n";

for $i (0..$#hashes) {
    ($offset, $length, $hashval) = @{$hashes[$i]};
    
    if ($olength < $offset) {
	print "truncate 2 $offset\n";
	$olength = $offset;
    }
    print "assertlen 2 $olength\n";
    print "copy 1 $offset 2 $offset $length\n";
    if ($olength < ($offset + $length)) {
	$olength = $offset + $length;
    }
    print "assertlen 2 $olength\n";
    
    for $j (0..$i) {
	($offset, $length, $hashval) = @{$hashes[$j]};
	
	#make sure we get the correct data when reading back
	print "read 2 $offset $length $hashval 0\n";
    }

    #make sure we get zeros around the new range when appropriate
    my ($pre, $post) = updatevalid($offset, $length);
    print "read 2 " . (($offset - $zerolen) < 0 ? 0 : ($offset - $zerolen))
	. " $zerolen $zerohash $pre\n";
    print "read 2 " . ($offset + $length) . " $zerolen $zerohash $post\n";
}
print "close 2\n";


#try reading all our regions from the new file
print "open $ofile 1 2\n";
foreach(@hashes) {
    ($offset, $length, $hashval) = @$_;
    print "read 2 $offset $length $hashval 0\n";
}

#truncate and make sure reads beyond EOF fail
$olength = int($fsize/2);
print "truncate 2 $olength\n";
foreach(@hashes) {
    ($offset, $length, $hashval) = @$_;
    print "read 2 $offset $length $hashval "
	. ($olength > ($offset + $length) ? 0 : 1)
	. "\n";
}

#check that we get zeros on extending ftruncate
print "truncate 2 0\n";
print "truncate 2 " . 2*$bsize . "\n";

print "read 2 0 $zerolen $zerohash 0\n";
print "read 2 " . ($bsize - 4) . " $zerolen $zerohash 0\n";
print "read 2 $bsize $zerolen $zerohash 0\n";
print "read 2 " . (2 * $bsize - $zerolen) . " $zerolen $zerohash 0\n";

print "truncate 2 $bsize\n";
print "assertlen 2 $bsize\n";

print "truncate 2 0\n";
print "close 2\n";

print "close 1\n";
