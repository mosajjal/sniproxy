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
go install github.com/mosajjal/sniproxy/v2/cmd/sniproxy@latest
```

Docker:

```bash
docker run -d --pull always \
  -p 80:80 -p 443:443 -p 53:53/udp \
  -v "$(pwd)/config.yaml:/tmp/config.yaml" \
  ghcr.io/mosajjal/sniproxy:latest --config /tmp/config.yaml
```

If you use source-IP based ACLs (`cidr`, `geoip`), prefer `--network host` over `-p` port mappings: docker's bridge NAT can rewrite the client source IP to the docker gateway, which breaks IP filtering. Also remember IPv4 CIDRs don't match IPv6 clients — a full catch-all needs both `0.0.0.0/0` and `::/0`.

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
      --prof string     write a profile on exit. one of: cpu, mem, block, mutex,
                        trace, threadcreate, goroutine, goroutineleak, clock
  -h, --help            help for sniproxy
  -v, --version         show version info and exit
```

## Profiling and goroutine leaks

sniproxy builds on Go 1.26 with two opt-in experiments, both of which become the default in Go
1.27:

```bash
GOEXPERIMENT=goroutineleakprofile,jsonv2 go build ./cmd/sniproxy
```

`goroutineleakprofile` turns on the runtime's goroutine leak profile. A goroutine counts as
leaked when it is blocked on a channel, mutex or condition variable that is unreachable from
anything that could still unblock it, so the runtime can prove it will never wake up.
`jsonv2` swaps `encoding/json` for the v2 implementation; the DoH JSON responses are
byte-identical either way.

The release binaries and the container image are built with both. A plain `go install` is not,
and there the leak options report that the profile is missing instead of failing to build.

Three ways to use it, from cheapest to most invasive:

**Live, over HTTP.** Set `bind_pprof` in the config and fetch the profile on demand:

```bash
curl 'http://127.0.0.1:6060/debug/pprof/goroutineleak?debug=1'   # readable stacks
go tool pprof http://127.0.0.1:6060/debug/pprof/goroutineleak    # binary profile
```

The rest of the standard `/debug/pprof/` handlers are on the same listener. Anyone who can reach
that port can read stack traces and start expensive profiles, so bind it to loopback.

**As a metric.** Set `goroutine_leak_interval` (e.g. `15m`) and sniproxy checks periodically,
publishing the count as the `goroutines.leaked` gauge and logging a warning when it is non-zero.
On the Prometheus endpoint that shows up as `sniproxy_<public_ipv4>_goroutines_leaked`, following
the same namespace/subsystem scheme as the other metrics. Each check forces a full GC, so keep the
interval coarse.

**On exit.** `sniproxy --prof goroutineleak` writes `goroutineleak.pprof` to the temp directory
when the process shuts down.

Detection is reachability based, so a goroutine parked on a primitive still reachable from a
global, or from a running goroutine's locals, will not be reported even if nothing will ever
signal it. In practice that means it catches abandoned per-connection goroutines well, and
misses anything still wired to a long-lived registry. Fetching the profile is what runs
detection; it forces a GC and briefly stops the world, so treat it as a diagnostic rather than
something to poll aggressively.

## API docs

[pkg.go.dev/github.com/mosajjal/sniproxy/v2/pkg](https://pkg.go.dev/github.com/mosajjal/sniproxy/v2/pkg)
