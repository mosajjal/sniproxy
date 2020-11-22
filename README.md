SNI Proxy with Embedded DNS Server
==============

Continuation of [byosh](https://github.com/mosajjal/byosh) and [SimpleSNIProxy](https://github.com/ziozzang/SimpleSNIProxy)

Installation
============

```
Usage of ./sniproxy:
  -bindip string
    	Bind to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0 (default "0.0.0.0")
  -domainlist string
    	domain list path. eg: /tmp/domainlist.log
  -publicip string
    	Public IP of this server, reply address of DNS queries
  -upstreamdns string
    	Upstream DNS IP (default "1.1.1.1")
```      

or Use Dockerfile to build and run

```
docker build -t sniproxy .
docker run -d -p 80:80 -p 443:443 -p 53:53 -v "$(pwd):/tmp/" sniproxy -domainlist /tmp/domains -publicip (YOUR Public IP)
```


Issue
=====

There's no security options. so, you must use firewall(ex:iptables..).



