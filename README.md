SNI Proxy with Embedded DNS Server
==============

Continuation of [byosh](https://github.com/mosajjal/byosh) and [SimpleSNIProxy](https://github.com/ziozzang/SimpleSNIProxy)

Installation
============

```
Usage of sniproxy:
  -allDomains
    	Route all HTTP(s) traffic through the SNI proxy
  -bindDnsOverTcp
    	enable DNS over TCP as well as of UDP
  -bindDnsOverTls
    	enable DNS over TLS as well as of UDP
  -bindIP string
    	Bind 443 and 80 to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0 (default "0.0.0.0")
  -domainListPath string
    	Path to the domain list. eg: /tmp/domainlist.log
  -domainListRefreshInterval duration
    	Interval to re-fetch the domain list (default 1m0s)
  -publicIP string
    	Public IP of the server, reply address of DNS queries
  -upstreamDNS string
    	Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853 (default "udp://1.1.1.1:53")
```      

Docker/Podman

```
PUB_IP=`curl ifconfig.me`
docker run -it --rm -p 80:80 -p 443:443 -p 53:53/udp -v "$(pwd):/tmp/" ghcr.io/mosajjal/sniproxy:master -domainListPath https://raw.githubusercontent.com/mosajjal/sniproxy/master/domains.csv -publicIP $PUB_IP
```

Issue
=====

There's no security options. so, you must use firewall(ex:iptables..).
