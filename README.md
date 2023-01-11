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
      --prometheus string                    Enable prometheus endpoint on IP:PORT. example: 127.0.0.1:8080. Always exposes /metrics and only supports HTTP
      --publicIP string                      Public IP of the server, reply address of DNS queries (default "YOUR_PUBLIC_IP")
      --reverseProxy string                  SNI and upstream URL. example: www.example.com::http://127.0.0.1:4001
      --reverseProxyCert string              Path to the certificate for reverse proxy. eg: /tmp/mycert.pem
      --reverseProxyKey string               Path to the certificate key for reverse proxy. eg: /tmp/mycert.key
      --tlsCert string                       Path to the certificate for DoH, DoT and DoQ. eg: /tmp/mycert.pem
      --tlsKey string                        Path to the certificate key for DoH, DoT and DoQ. eg: /tmp/mycert.key
      --upstreamDNS string                   Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853, https://dns.google/dns-query (default "udp://8.8.8.8:53")
      --upstreamSOCKS5 string                Use a SOCKS proxy for upstream HTTP/HTTPS traffic. (default "socks5://admin:admin@127.0.0.1:1080")
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


Setting Up an SNI Proxy Using Vultr
============

In this tutorial, we will go over the steps to set up an SNI proxy using Vultr as a service provider. This will allow you to serve multiple SSL-enabled websites from a single IP address.

Prerequisites
- A Vultr account. If you don't have one, you can sign up for free [here](https://www.vultr.com/?ref=9292202).

## Step 1: Create a Vultr Server
First, log in to your Vultr account and click on the "Instances" tab in the top menu. Then, click the "+" button to deploy a new server.

On the "Deploy New Instance" page, select the following options:

- Choose Server: Choose "Cloud Compute" 
- CPU & Storage Technology: Any of the choices should work perfectly fine
- Server Location: Choose the location of the server. This will affect the latency of your website, so it's a good idea to choose a location that is close to your target audience.
- Server Image: Any OS listed there is supported. If you're not sure what to choose, Ubuntu is a good option
- Server Size: Choose a server size that is suitable for your needs. A small or medium-sized server should be sufficient for most SNI proxy setups. Pay attention to the monthly bandwidth usage as well
- "Add Auto Backups": not strictly needed for sniproxy. 
- "SSH Keys": choose a SSH key to facilitate logging in later on. you can always use Vultr's builtin console as well. 
- Server Hostname: Choose a hostname for your server. This can be any name you like.
After you have selected the appropriate options, click the "Deploy Now" button to create your server.

## Step 2: Install the SNI Proxy
Once your server has been created, log in to the server using SSH or console. The root password is available under the "Overview" tab in instances list.

once you have a shell in front of you, run the following (assuming you're on Ubuntu 22.04)
```bash
bash <(curl -L https://raw.githubusercontent.com/mosajjal/sniproxy/master/install.sh)
```
