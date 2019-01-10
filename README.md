# pcap2mermaid - Display SIP call flows from PCAP as Mermaid flow chart

This tool parses a pcap file (e.g. captured by tcpdump) and converts it to
a mermaid flow chart.

## Installing prerequisites

### Debian

```
$ sudo apt install libnet-pcap-perl libnetpacket-perl libnet-sip-perl
```

### Other

```
$ sudo yum install libpcap-devel # or any other way to install the libpcap development package
$ sudo cpan -i Carton
$ carton install
```

### Running the tool

__Usage__: `./pcap2mermaid.pl <input.pcap> <output.txt> [mapping string]`

```
PERL5LIB=./lib:./local/lib/perl5 ./pcap2mermaid.pl /tmp/test.pcap /tmp/out "10.15.17.98:46849=DUT,10.15.17.237:5060=SSW"
```

## Options

### Pre-Filtering traffic by port 5060

The tool only considers packets from or to port 5060 hardcodedly. If you want to capture traffic between different ports,
you have to adapt the variable **$filter_string**, which is in standard pcap filter syntax.

Also note that all provisional responses with a response code smaller than 180 are automatically ignored. To change this
behavior, the **$skip_provisional** variable must be set to 0.

### Mapping addresses to names

If no optional _mapping string_ argument is given, every single leg of all SIP packets are displayed. The name of the
endpoints are the `<ip>:<port>` tuples. This can take a long time.

A mapping string accomplishes two things:

1. Display a custom name for an endpoint instead of `<ip>:<port>` in the flow chart
2. Ignore all endpoints that do not have a mapping string
