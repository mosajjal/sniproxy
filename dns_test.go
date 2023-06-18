package main

import (
	"net"
	"testing"
)

func TestDNSClient_lookupDomain4(t *testing.T) {
	dnsClients := []*DNSClient{}
	// tmp, err := NewDNSClient("https://dns.google/dns-query", true, "")
	// dnsClients = append(dnsClients, tmp)
	// tmp, err = NewDNSClient("https://cloudflare-dns.com/dns-query", true, "")
	// dnsClients = append(dnsClients, tmp)
	tmp, err := NewDNSClient("quic://dns.adguard-dns.com:8853", true, "")
	if err != nil {
		t.Errorf("failed to set up DNS client")
	}
	dnsClients = append(dnsClients, tmp)
	tmp, err = NewDNSClient("tcp://1.1.1.1:53", true, "")
	if err != nil {
		t.Errorf("failed to set up DNS client")
	}
	dnsClients = append(dnsClients, tmp)
	tmp, err = NewDNSClient("udp://1.1.1.1:53", true, "")
	if err != nil {
		t.Errorf("failed to set up DNS client")
	}
	tests := []struct {
		name    string
		domain  string
		want    net.IP
		wantErr bool
	}{
		{name: "test1", domain: "ident.me", want: net.IPv4(49, 12, 234, 183), wantErr: false},
		{name: "test1", domain: "ifconfig.me", want: net.IPv4(34, 160, 111, 145), wantErr: false},
	}
	for _, dnsClient := range dnsClients {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, err := dnsClient.lookupDomain4(tt.domain)
				if (err != nil) != tt.wantErr {
					t.Errorf("DNSClient.lookupDomain4() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !got.Equal(tt.want) {

					t.Errorf("DNSClient.lookupDomain4() = %v, want %v", got, tt.want)
				}
			})
		}
	}
}
