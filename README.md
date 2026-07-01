# crapy-traceroute

`crapy-traceroute` is a small traceroute tool for literal IPv4 and IPv6 addresses with ICMP, UDP, and TCP probe modes. It prints each hop with RTT, reply TTL/hop-limit, the TTL/hop-limit quoted inside ICMP errors, and optional ASN and location enrichment from local MMDB files.

## Requirements

- Go 1.25 or newer
- Linux or another system that permits raw ICMP sockets
- Permission to open raw sockets, usually by running as root or assigning the built binary `cap_net_raw`
- Optional IPinfo/MaxMind-compatible MMDB files for enrichment:
  - `ipinfo_asn.mmdb` for ASN lookup
  - `ipinfo_location.mmdb` for country/city lookup

## Setup

Build the tool:

```sh
make
```

This creates `go-traceroute` in the repository directory.

If you do not want to run as root, grant raw socket capability after building:

```sh
sudo setcap cap_net_raw+ep ./go-traceroute
```

Place optional MMDB files in the repository as `ipinfo_asn.mmdb` and `ipinfo_location.mmdb`, or pass custom paths with `-geo-asn-mmdb` and `-geo-city-mmdb`.

If no MMDB path is provided and the default file is not present, the tool skips that lookup and logs this on startup.

## Features

- IPv4 and IPv6 traceroute with ICMP, UDP, and TCP probes
- Optional outbound interface and source IP selection
- Multiple targets in one run
- Target list input from a file with one literal IP address per line
- CSV output for later analysis
- Optional ASN, country, and city enrichment from local MMDB files
- Reply TTL/hop-limit and quoted TTL/hop-limit reporting
- `-mode icmp` by default, with `-mode udp` and `-mode tcp` available
- TTL rewrite identification mode for CSV workflows

## Examples

Trace one target with the default ICMP mode:

```sh
./go-traceroute 8.8.8.8
```

Trace with UDP probes:

```sh
./go-traceroute -mode udp 8.8.8.8
```

Trace with TCP probes to a destination port:

```sh
./go-traceroute -mode tcp -port 443 8.8.8.8
```

Trace multiple targets from a file:

```sh
./go-traceroute -input-file targets.txt
```

Send probes on a specific interface:

```sh
./go-traceroute -iface eth0 8.8.8.8
```

Bind probes to a specific source address:

```sh
./go-traceroute -iface eth0 -src 192.0.2.10 8.8.8.8
```

Write normal CSV output:

```sh
./go-traceroute -csv -output-file traces.csv -input-file targets.txt
```

Use custom MMDB files:

```sh
./go-traceroute -geo-asn-mmdb ./asn.mmdb -geo-city-mmdb ./location.mmdb 8.8.8.8
```

## Probe Modes

`-mode` selects the probe type:

- `icmp`: ICMP echo probes. This is the default.
- `udp`: UDP probes. If `-port` is omitted, UDP starts at port `33434` and increments the destination port per hop.
- `tcp`: TCP connect probes. `-port` is required and is used as the destination port for every hop.

Examples:

```sh
./go-traceroute -mode icmp 2001:4860:4860::8888
./go-traceroute -mode udp -port 33434 8.8.8.8
./go-traceroute -mode tcp -port 443 -iface eth0 8.8.8.8
```

## TTL Rewrite Mode

`-identify-ttl-rewrites` enables CSV mode and writes only likely TTL/hop-limit rewrite observations. It looks at the final observed hop for a target and checks the quoted TTL/hop-limit from the packet embedded in the ICMP response. If that final quoted value is greater than `1`, the tool writes the previous observed hop as the candidate row and adds trigger columns describing the final hop.

This is useful when looking for devices or middleboxes that rewrite TTL/hop-limit values before forwarding traffic. In a normal traceroute, the final quoted TTL/hop-limit is expected to be depleted. A value greater than `1` can be a signal that the packet's TTL/hop-limit was rewritten along the path.

Example:

```sh
./go-traceroute -identify-ttl-rewrites -output-file ttl-rewrites.csv -input-file targets.txt
```

## CSV Columns

Normal CSV output includes target, hop, address, ASN fields, location fields, RTT, reply TTL/hop-limit, quoted TTL/hop-limit, timeout status, done status, and late-arrival status.

TTL rewrite mode adds:

- `trigger_final_hop`
- `trigger_final_address`
- `trigger_final_quoted_ttl_hlim`

## AI Note

Most parts of this project were built with assistance from GPT-5 Codex.

