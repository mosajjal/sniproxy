package main

import (
	"net"
	"testing"

	"github.com/mosajjal/dnsclient"
)

func TestDNSClient_lookupDomain4(t *testing.T) {
	tmp, err := dnsclient.New("udp://1.1.1.1:53", true, "")
	if err != nil {
		t.Errorf("failed to set up DNS client")
	}
	dnsc := DNSClient{C: tmp}
	tests := []struct {
		client  DNSClient
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
