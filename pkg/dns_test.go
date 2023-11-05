package sniproxy

import (
	"net"
	"testing"
)

func TestDNSClient_lookupDomain4(t *testing.T) {
	c := Config{
		UpstreamDNS: "tcp://1.1.1.1:53",
	}
	dnsc, err := NewDNSClient(&c, c.UpstreamDNS, true, "")
	if err != nil {
		t.Errorf("failed to set up DNS client")
	}
	tests := []struct {
		client  *DNSClient
		name    string
		domain  string
		want    net.IP
		wantErr bool
	}{
		{client: dnsc, name: "test1", domain: "ident.me", want: net.IPv4(49, 12, 234, 183), wantErr: false},
		{client: dnsc, name: "test1", domain: "ifconfig.me", want: net.IPv4(34, 160, 111, 145), wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.client.lookupDomain4(tt.domain)
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
