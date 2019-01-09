#!/usr/bin/env perl
use warnings;
use strict;
use lib '.';

use English;
use Net::Pcap qw/:datalink :functions/;
use NetPacket::LinuxSLL;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::UDP;
use NetPacket::TCP;
use Net::SIP::Packet;
use Net::SIP::Request;
use Net::SIP::Response;

use Data::Dumper;

my $filter_string = 'port 5060';
my $skip_provisional = 1;

my $infile = $ARGV[0];
my $outfile = $ARGV[1];
my $mapping = $ARGV[2];

unless (defined $infile && defined $outfile) {
    die "Usage: $PROGRAM_NAME <infile.pcap> <outfile.md> [mapping]\n";
}

my $ret;
my $err = '';
my $filter;
my @sip_packets = ();
my $filter_unmapped = 0;
my %host2name = ();

if (defined $mapping) {
    $filter_unmapped = 1;
    my @hosts = split /,/, $mapping;
    foreach my $h (@hosts) {
        my ($host, $name) = split /=/, $h;
        unless (defined $host && defined $name) {
            die "Invalid mapping, must be comma-separated list of '<ip>:<port>=<name>' elements\n";
        }
        $host2name{$host} = $name;
    }
    print Dumper \%host2name;
}

my $pcap = Net::Pcap::open_offline($infile, \$err)
    or die "Failed to open pcap input file '$infile': $err\n";

open my $outfh, ">", $outfile
    or die "Failed to open mermaid output file '$outfile': $!\n";
    
my $linktype = Net::Pcap::datalink($pcap);
if ($linktype == DLT_LINUX_SLL) {
    print "link type is linux ssl\n";
} elsif ($linktype == DLT_EN10MB) {
    print "link type is ether\n";
} else {
    die "Invalid data link type in pcap file, must be linux sll or ethernet\n";
}

$ret = Net::Pcap::compile($pcap, \$filter, $filter_string, 1, 0);
if ($ret == -1) {
    die "Failed to compile filter string '$filter_string'\n";
}
Net::Pcap::setfilter($pcap, $filter);

$ret = Net::Pcap::loop($pcap, -1, \&process_packet, '');
if ($ret == 0) {
    print "packets successfully processed, pcap finished\n";
} elsif ($ret == -1) {
    print "packets processed until error\n";
} elsif ($ret == -2) {
    print "packets processed until manual abort\n";
}

Net::Pcap::pcap_close($pcap);

print $outfh "sequenceDiagram\n";
foreach my $pkt (@sip_packets) {
    my $a = $pkt->{src};
    my $b = $pkt->{dst};
    if ($filter_unmapped && (!exists $host2name{$a} || !exists $host2name{$b})) {
        next;
    } elsif ($filter_unmapped) {
        $a = $host2name{$a};
        $b = $host2name{$b};
    }
    my $arrow = $pkt->{req} ? '->>' : '-->>';
    print $outfh "    $a$arrow$b: $$pkt{text}\n"
}

close $outfh;

sub process_packet {
    my ($user_data, $header, $packet) = @_;

    my $l2;
    if ($linktype == DLT_LINUX_SLL) {
       $l2 = NetPacket::LinuxSLL->decode($packet);
    } else {
       $l2 = NetPacket::Ethernet->decode($packet);
    }

    my $l3 = NetPacket::IP->decode($l2->{data});

    my $l4;
    if ($l3->{proto} == 17) {
       $l4 = NetPacket::UDP->decode($l3->{data});
    } elsif ($l3->{proto} == 6) {
       $l4 = NetPacket::TCP->decode($l3->{data});
    } else {
        print "unsupported l4 protocol, must be udp or tcp\n";
        return;
    }

    my $sip;
    eval { $sip = Net::SIP::Packet->new($l4->{data}); };
    if ($@) {
        print "invalid sip packet: $@\n";
        return;
    }

    if ($sip->is_request) {
        push @sip_packets, {
            req => 1,
            text => $sip->method,
            src => "$$l3{src_ip}:$$l4{src_port}",
            dst => "$$l3{dest_ip}:$$l4{dest_port}",
        };
    } else {
        return if ($skip_provisional && $sip->code < 180);
        push @sip_packets, {
            req => 0,
            text => $sip->code . " (" . $sip->method . ")",
            src => "$$l3{src_ip}:$$l4{src_port}",
            dst => "$$l3{dest_ip}:$$l4{dest_port}",
        };
    }
}
