# sniproxy

An SNI proxy with a built-in DNS server. It intercepts DNS queries, responds with its own IP address, then proxies the incoming TLS/HTTP connections to the real destination by reading the SNI (Server Name Indication) or Host header.

This is useful when you want to selectively proxy traffic for specific domains through a server, without needing to set up a full VPN. Point your DNS at sniproxy, and it handles the rest.

Continuation of [byosh](https://github.com/mosajjal/byosh) and [SimpleSNIProxy](https://github.com/ziozzang/SimpleSNIProxy).

## How it works

1. Client sends a DNS query for `example.com`
2. sniproxy checks the domain against its ACL rules
3. If the domain should be proxied, sniproxy responds with its own public IP
4. Client connects to sniproxy on port 443 (or 80)
5. sniproxy reads the SNI from the TLS ClientHello (or Host header for HTTP), connects to the real server, and pipes traffic both ways

For domains that shouldn't be proxied, sniproxy forwards the DNS query upstream and returns the real IP.

## Features

DNS server supporting UDP, TCP, DNS-over-TLS, DNS-over-QUIC, and DNS-over-HTTPS. HTTP and HTTPS proxying with multi-port listeners. ACL system with domain lists, CIDR ranges, GeoIP filtering (MaxMind MMDB), and per-FQDN destination overrides. Optional SOCKS5 upstream proxy. Source IP rotation across multiple interface addresses. IPv4/IPv6 with configurable preference. Prometheus metrics endpoint.

## Install

Grab a binary from the [releases page](https://github.com/mosajjal/sniproxy/releases), or:

```bash
go install github.com/mosajjal/sniproxy/v2@latest
```

Docker:

```bash
docker run -d --pull always \
  -p 80:80 -p 443:443 -p 53:53/udp \
  -v "$(pwd)/config.yaml:/tmp/config.yaml" \
  ghcr.io/mosajjal/sniproxy:latest --config /tmp/config.yaml
```

There's also an installer script that sets up systemd and everything:

```bash
bash <(curl -L https://raw.githubusercontent.com/mosajjal/sniproxy/master/install.sh)
```

## Configuration

sniproxy uses a YAML config file. Dump the defaults with:

```bash
sniproxy --defaultconfig > config.yaml
```

Then edit to taste. The config covers upstream DNS, bind addresses, ACL rules, TLS certs, and SOCKS5 proxy settings. See [config.defaults.yaml](cmd/sniproxy/config.defaults.yaml) for the full reference with comments.

You can also override any setting with environment variables using the `SNIPROXY_` prefix. Double underscores separate nested keys:

```bash
SNIPROXY_GENERAL__BIND_DNS_OVER_UDP=0.0.0.0:5555
```

## Ports

sniproxy needs ports 80, 443, and 53 by default. On Ubuntu, systemd-resolved often squats on port 53. Either disable it or change its stub listener:

```bash
sed -i 's/#DNS=/DNS=9.9.9.9/; s/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
systemctl restart systemd-resolved
```

## Usage

```
sniproxy [flags]

Flags:
  -c, --config string   path to YAML configuration file
      --defaultconfig    write the default config yaml file to stdout
  -h, --help            help for sniproxy
  -v, --version         show version info and exit
```

## API docs

[pkg.go.dev/github.com/mosajjal/sniproxy/v2/pkg](https://pkg.go.dev/github.com/mosajjal/sniproxy/v2/pkg)
