/*
Continuation of [byosh] and [SimpleSNIProxy] projects.

# pre-requisites

To ensure that Sniproxy works correctly, it's important to have ports 80, 443, and 53 open.
However, on Ubuntu, it's possible that port 53 may be in use by systemd-resolved.
To disable systemd-resolved and free up the port, follow [these instructions].

If you prefer to keep systemd-resolved and just disable the built-in resolver, you can use the following command:

	sed -i 's/#DNS=/DNS=9.9.9.9/; s/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
	systemctl restart systemd-resolved

# How to Install

The simplest way to install the software is by utilizing the pre-built binaries available on the releases page.
Alternatively, there are other ways to install, which include:

Using "go install" command:

	go install github.com/mosajjal/sniproxy@latest

Using Docker or Podman:

	docker run -d --pull always -p 80:80 -p 443:443 -p 53:53/udp -v "$(pwd):/tmp/" ghcr.io/mosajjal/sniproxy:latest --domainListPath https://raw.githubusercontent.com/mosajjal/sniproxy/master/domains.csv

Using the installer script:

	bash <(curl -L https://raw.githubusercontent.com/mosajjal/sniproxy/master/install.sh)

# How to Run

sniproxy can be configured using a configuration file or command line flags.
The configuration file is a JSON file, and an example configuration file can be found under config.sample.json.

Flags:

	    --allDomains                           Route all HTTP(s) traffic through the SNI proxy
	    --bindDnsOverQuic                      enable DNS over QUIC as well as UDP
	    --bindDnsOverTcp                       enable DNS over TCP as well as UDP
	    --bindDnsOverTls                       enable DNS over TLS as well as UDP
	    --bindIP string                        Bind 443 and 80 to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0 (default "0.0.0.0")
	-c, --config string                        path to JSON configuration file
	    --dnsPort uint                         DNS Port to listen on. Should remain 53 in most cases (default 53)
	    --domainListPath string                Path to the domain list. eg: /tmp/domainlist.csv. Look at the example file for the format.
	    --domainListRefreshInterval duration   Interval to re-fetch the domain list (default 1h0m0s)
	    --geoipExclude strings                 Exclude countries to be allowed to connect. example: US,CA
	    --geoipInclude strings                 Include countries to be allowed to connect. example: US,CA
	    --geoipPath string                     path to MMDB URL/path
	                                           Example: https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb
	    --geoipRefreshInterval duration        MMDB refresh interval (default 1h0m0s)
	-h, --help                                 help for sniproxy
	    --httpPort uint                        HTTP Port to listen on. Should remain 80 in most cases (default 80)
	    --httpsPort uint                       HTTPS Port to listen on. Should remain 443 in most cases (default 443)
	    --interface string                     Interface used for outbound TLS connections. uses OS prefered one if empty
	    --prometheus string                    Enable prometheus endpoint on IP:PORT. example: 127.0.0.1:8080. Always exposes /metrics and only supports HTTP
	    --publicIPv4 string                    Public IP of the server, reply address of DNS A queries (default "YOUR_IPv4")
	    --publicIPv6 string                    Public IPv6 of the server, reply address of DNS AAAA queries (default "YOUR_IPv6")
	    --reverseProxy string                  enable reverse proxy for a specific FQDN and upstream URL. example: www.example.com::http://127.0.0.1:4001
	    --reverseProxyCert string              Path to the certificate for reverse proxy. eg: /tmp/mycert.pem
	    --reverseProxyKey string               Path to the certificate key for reverse proxy. eg: /tmp/mycert.key
	    --tlsCert string                       Path to the certificate for DoH, DoT and DoQ. eg: /tmp/mycert.pem
	    --tlsKey string                        Path to the certificate key for DoH, DoT and DoQ. eg: /tmp/mycert.key
	    --upstreamDNS string                   Upstream DNS URI. examples: udp://1.1.1.1:53, tcp://1.1.1.1:53, tcp-tls://1.1.1.1:853, https://dns.google/dns-query (default "udp://8.8.8.8:53")
	    --upstreamSOCKS5 string                Use a SOCKS proxy for upstream HTTP/HTTPS traffic. Example: socks5://admin:admin@127.0.0.1:1080

# Setting Up an SNI Proxy Using Vultr

In this tutorial, we will go over the steps to set up an SNI proxy using Vultr as a service provider. This will allow you to serve multiple SSL-enabled websites from a single IP address.

# Prerequisites

- A Vultr account. If you don't have one, you can sign up for free using my [Vultr referal link]

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

Ensure the firewall (firewalld, ufw or iptables) is allowing connectivity to ports 80/TCP, 443/TCP and 53/UDP. For `ufw`, allow these ports with:

	sudo ufw allow 80/tcp
	sudo ufw allow 443/tcp
	sudo ufw allow 53/udp
	sudo ufw reload

once you have a shell in front of you, run the following (assuming you're on Ubuntu 22.04)

	bash <(curl -L https://raw.githubusercontent.com/mosajjal/sniproxy/master/install.sh)

above script is an interactive installer, it will ask you a few questions and then install sniproxy for you. it also installs sniproxy as a systemd servers, and enables it to start on boot.

# step 3: customize your configuration

above wizard will set up execution arguments for sniproxy. you can edit them by running

	sudo systemctl edit --full sniproxy

and then edit the execStart line to your liking. for example, if you want to use a different port for HTTP, you can edit the line to

	ExecStart=/opt/sniproxy/sniproxy httpPort 8080

[byosh]: https://github.com/mosajjal/byosh
[SimpleSNIProxy]: https://github.com/ziozzang/SimpleSNIProxy
[these instructions]: https://gist.github.com/zoilomora/f7d264cefbb589f3f1b1fc2cea2c844c
[Vultr referal link]: https://www.vultr.com/?ref=8578601
*/
package main
