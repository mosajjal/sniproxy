SNI Proxy with Embedded DNS Server
==============

Continuation of [byosh](https://github.com/mosajjal/byosh) and [SimpleSNIProxy](https://github.com/ziozzang/SimpleSNIProxy)

Installation
============

```
Usage of sniproxy:
      --allDomains                           Route all HTTP(s) traffic through the SNI proxy
      --bindDnsOverQuic                      enable DNS over QUIC as well as UDP
      --bindDnsOverTcp                       enable DNS over TCP as well as UDP
      --bindDnsOverTls                       enable DNS over TLS as well as UDP
      --bindIP string                        Bind 443 and 80 to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0 (default "0.0.0.0")
  -c, --config string                        path to JSON configuration file
      --domainListPath string                Path to the domain list. eg: /tmp/domainlist.csv
      --domainListRefreshInterval duration   Interval to re-fetch the domain list (default 1h0m0s)
      --publicIP string                      Public IP of the server, reply address of DNS queries (default "122.57.162.2")
      --tlsCert string                       Path to the certificate for DoH, DoT and DoQ. eg: /tmp/mycert.pem
      --tlsKey string                        Path to the certificate key for DoH, DoT and DoQ. eg: /tmp/mycert.key
      --upstreamDNS string                   Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853, https://dns.google/dns-query (default "udp://8.8.8.8:53")
```      

Docker/Podman

```
docker run -d --pull always -p 80:80 -p 443:443 -p 53:53/udp -v "$(pwd):/tmp/" ghcr.io/mosajjal/sniproxy:latest --domainListPath https://raw.githubusercontent.com/mosajjal/sniproxy/master/domains.csv 
```

In order for `sniproxy` to work properly, ports 80, 443 and 53 need to be open. if you're using ubuntu, there's a good chance that `systemd-resolved` is using port 53. to disable it, follow [these instructions](https://gist.github.com/zoilomora/f7d264cefbb589f3f1b1fc2cea2c844c)

if you would like to keep `systemd-resolved` and disable the builtin resolver, you can use the following:
```bash
sed -i 's/#DNS=/DNS=9.9.9.9/; s/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 
systemctl restart systemd-resolved
```
above will replace the builtin resolver with 9.9.9.9

Issue
=====

There's no security options. so, you must use firewall(ex:iptables..).
