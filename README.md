# pcap2mermaid - Display SIP call flows from PCAP as Mermaid flow chart

This tool parses a pcap file (e.g. captured by tcpdump) and converts it to
a mermaid flow chart.

## Usage

PERL5LIB=./lib:./local/lib/perl5 ./pcap2mermaid.pl test.pcap /tmp/out "10.15.17.98:46849=DUT,10.15.17.237:5060=SSW"
