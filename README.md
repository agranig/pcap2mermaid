# pcap2mermaid - Convert SIP call flows from PCAP traces to Mermaid sequence diagrams

This tool parses a pcap file (e.g. captured by tcpdump), extracts SIP
packets from it and converts the flow to a mermaid sequence diagram
while filtering unwanted packets.

![pcap to sequence
diagram](https://github.com/agranig/pcap2mermaid/raw/master/doc/pcap-to-seqdia.png
"PCAP to Mermaid sequence diagram")

## Motivation and Use Case

When documenting SIP call flows, a sequence diagram can greatly improve
the understanding of SIP packets going back and forth between involved
endpoints.  However, managing pictures or other binary formats produced
by tools like Visio or Dia are a pain to track via version control, and
they are cumbersome to maintain e.g in Markdown documentation.

[Mermaid](https://mermaidjs.github.io/) is a nice tool you can run
locally to generate such sequence diagrams from simple text based
syntax. When using Pandoc to generate documentation out of markdown
file, you can even use
[mermaid-filter](https://github.com/raghur/mermaid-filter) to embed
mermaid code directly in your documentation and generate the diagrams on
the fly when the markdown is rendered to html or pdf.

However, manually writing those sequence diagrams can be a quite
repetitive and boring task when documenting a large number of call
flows.  Therefore, this tool aims to help automizing this process by
letting you do an actual SIP call (or registration, or any other SIP
scenario), capture a pcap file using tcpdump while doing so, then
generate the sequence diagram automatically using this pcap call trace.
What's left is pasting it into your documentation, and potentially
annotating it with some notes.

## Installation and Usage

### Debian

```
$ sudo apt install libnet-pcap-perl libnetpacket-perl libnet-sip-perl
```

### Other

```
$ sudo yum install libpcap-devel \
  # or any other way to install the libpcap development package
$ sudo cpan -i Carton
$ carton install
```

### Running the tool

__Usage__: `./pcap2mermaid.pl <input.pcap> <output.txt> [mapping string]`

```
PERL5LIB=./lib:./local/lib/perl5 ./pcap2mermaid.pl \
  /tmp/test.pcap /tmp/out.txt \
  "10.15.17.98:46849=DUT,10.15.17.237:5060=SSW"
```

### Converting the output to a mermaid sequence diagram

To quickly verify the result without installing mermaid, you can use the
[mermaid live editor](https://mermaidjs.github.io/mermaid-live-editor)
where you can paste the output of the tool for a preview.

Eventually, you might want to Install the
[mermaid-cli](https://github.com/mermaidjs/mermaid.cli) for a quick
test, then execute:

``` $ cat /tmp/mermaid-config.json { "theme": "forest", "themeCSS": "",
"cloneCssStyles": false, "sequence": { "mirrorActors": false,
"useMaxWidth": false } }

$ mmdc -i /tmp/out.txt -o /tmp/out.svg -c /tmp/mermaid-config.json ```

A final solution would also integrate the mermaid-filter to the
documentation generation tool-chain, which is out of scope of this
document.

## Options

### Pre-Filtering traffic by port 5060

The tool only considers packets from or to port 5060 hardcodedly. If you
want to capture traffic between different ports, you have to adapt the
variable **$filter_string**, which is in standard pcap filter syntax.

Also note that all provisional responses with a response code smaller
than 180 are automatically ignored. To change this behavior, the
**$skip_provisional** variable must be set to 0.

### Mapping addresses to names

If no optional _mapping string_ argument is given, every single leg of
all SIP packets are displayed. The name of the endpoints are the
`<ip>:<port>` tuples.  This can take a long time.

To optimize this and make the flow chart more readable, a mapping string
accomplishes two things:

1. Display a custom name for an endpoint instead of `<ip>:<port>` in the
   flow chart
2. Ignore all endpoints that do not have a mapping string

The format of the mapping string is a comma-separated list of elements,
each containing a string `<ip>:<port>=<name>`.

__Example__: 192.168.0.10:12345=Alice,192.168.0.20:54321=Bob,192.168.0.30=Proxy
