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
      --dnsPort uint                         HTTP Port to listen on. Should remain 53 in most cases (default 53)
      --domainListPath string                Path to the domain list. eg: /tmp/domainlist.csv
      --domainListRefreshInterval duration   Interval to re-fetch the domain list (default 1h0m0s)
      --geoipExclude strings                 Exclude countries to be allowed to connect. example: US,CA
      --geoipInclude strings                 Include countries to be allowed to connect. example: US,CA
      --geoipPath string                     path to MMDB URL/path
                                             Example: https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb
      --geoipRefreshInterval duration        MMDB refresh interval (default 1h0m0s)
      --httpPort uint                        HTTP Port to listen on. Should remain 80 in most cases (default 80)
      --httpsPort uint                       HTTPS Port to listen on. Should remain 443 in most cases (default 443)
      --interface string                     Interface used for outbound TLS connections. uses OS prefered one if empty
      --publicIP string                      Public IP of the server, reply address of DNS queries (default "")
      --reverseProxy string                  SNI and upstream URL. example: www.example.com::http://127.0.0.1:4001
      --reverseProxyCert string              Path to the certificate for reverse proxy. eg: /tmp/mycert.pem
      --reverseProxyKey string               Path to the certificate key for reverse proxy. eg: /tmp/mycert.key
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
