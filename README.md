# `scuttle6`

Convince `traceroute6` to resolve to arbitrary reverse DNS records.

[![asciicast](https://asciinema.org/a/29I76bMZCdy4tnThMmTt58HpG.png)](https://asciinema.org/a/29I76bMZCdy4tnThMmTt58HpG)

Inspired from [Karla Burnett's amazing talk at Bang Bang Con 2018][talk]

## Connect to tracefun.nickhs.com

* Try it out!

    On Mac OS:

        $ traceroute6 -I tracefun.nickhs.com

    On Linux:

        $ traceroute -6 -I tracefun.nickhs.com

Your machine will need to support IPv6. I use
[test-ipv6.com](https://test-ipv6.com/) or
[ipv6.google.com](https://ipv6.google.com/) to check.

## How it works

`traceroute6` works by sending a series of packets (could be ICMP, UDP or TCP)
with a hop limit starting at one; and then increasing it by one until it
reaches it's destination (or gives up). Each line in the traceroute output
represents a packet with an increasing hop limit.

When a router receives a packet, it checks what the hop limit is set to on the
packet. If it's zero it returns an ICMP Time Exceeded message back, notifying
the sender that it's not forwarding the packet onwards. If it's greater than
zero, it subtracts one from the hop limit and forwards it on to where it
believes the packet needs to go. This was designed to idenify loops in router's
routing tables.

Traceroute takes these Time Exceeded messages, and then displays the IP address
of the router that sent them. By starting at a low hop limit, traceroute can
show every server on the way (that sends back a Time Exceeded message). It
can then do a reverse DNS lookup to display the hostname of the machine sending the
Time Exceeded message, rather than just the IP address.

`scuttle6` works by pretending to be a router. When it receives an ICMP packet
(see Limitations below) it matches up the hop limit to an IP that was provided
to it. It sends back a Time Exceeded message to `traceroute6` _but_ spoofs the
source IP address in the returning packat as defined by the IP addresses fed to
it.

`traceroute6` will get the spoofed IP and believe the packet flowed through
that router before getting to its destination. It'll perform a reverse DNS
lookup for the spoofed IP allowing you to render whatever hostname you'd like.

## Setup your own server

### What you will need to have

* You will need to find a host that supports:
    * IPv6 and gives you plenty of IPv6 addresses.
    * modifying iptables rules to block outgoing ICMP responses
    * `CAP_NET_RAW` to allow crafting and returning raw packets

  I personally use [prgmr.com](https://prgmr.com). Note you'll have to ask
  their support to grant you a `/64` block of IPv6 addresses, it's not
  automatic.

* You will need to find a DNS nameserver that's willing to host reverse DNS
  records. I like [Hurricane Electric's free DNS service](https://dns.he.net/).

### Running

* Disable ICMP6 responses from the kernel with these two iptables rules:

    $ ip6tables -A OUTPUT -p ipv6-icmp -m owner --uid-owner 0 -j ACCEPT
    $ ip6tables -A OUTPUT -p ipv6-icmp -m icmp6 --icmpv6-type 129 -j DROP

The first rule allows ICMP6 traffic from UID zero (root), if you're running your application under a different UID change it accordingly.
The second rule drops all other outgoing ICMP6 type 129 (Echo Reply) messages from the host.

* Download the [latest release][latest-release] onto your host.

* Create a newline delimited file with the IPv6 IP's to return. See [the example in the docs][example-ips].

* Run the binary

    $ scuttle6 ips.txt

* Try it out! From another machine (the client) traceroute to your host (the server).

    On Mac OS:

        $ traceroute6 -I <your host>

    On Linux:

        $ traceroute -6 -I <your host>

Your client machine will need to support IPv6. I use
[test-ipv6.com](https://test-ipv6.com/) or
[ipv6.google.com](https://ipv6.google.com/) to check.

If it works you should see the the IPs defined in `ips.txt` being returned in
consecutive order.

* Setup your reverse DNS records. This will map the IPs to a DNS name, allowing
  you to send messages. How to setup those reverse DNS records is dependent on
  your DNS name server. If you use Hurricane Electric, this completely
  undocumented [script may be helpful][he-script].

## Debugging

`scuttle6` makes use of Rust's [env\_logger][env_logger] crate. Changing the
`RUST_LOG` environment variable between `warn`, `info` and `debug` will have
the server spout out more information accordingly.

    $ RUST_LOG=info scuttle6 ips.txt
    INFO 2018-06-30T01:19:51Z: scuttle6: ICMP Echo Request from 2604:2000:14c5:c417:e9d8:422d:49a0:ef95 hop limit 13

Otherwise tcpdump and wireshark are going to be your best friends to work out
what's being sent and what's being received.

## Building

You can grab the [latest release from Github][latest-release], or build it
yourself.

To build it from scratch you'll need the Rust toolchain and Rust stable. From
there it's a:

    $ cargo build --release

## Limitations

- Only supports ICMPv6, not TCP or UDP. Mainly because I don't want to break
  the either two on my shared host.

[talk](https://www.youtube.com/watch?v=NgKI7-3j2h)
[latest-release](http://example.net)
