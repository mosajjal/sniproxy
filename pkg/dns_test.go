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
		want    []net.IP
		wantErr bool
	}{
		{client: dnsc, name: "test1", domain: "dns.google", want: []net.IP{net.IPv4(8, 8, 8, 8), net.IPv4(8, 8, 4, 4)}, wantErr: false},
		{client: dnsc, name: "test2", domain: "one.one.one.one", want: []net.IP{net.IPv4(1, 1, 1, 1), net.IPv4(1, 0, 0, 1)}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTmp, err := tt.client.lookupDomain4(tt.domain)
			got := net.IP(gotTmp.AsSlice())
			if (err != nil) != tt.wantErr {
				t.Errorf("DNSClient.lookupDomain4() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			// check if the returned IP is in the list of expected IPs
			found := false
			for _, w := range tt.want {
				if got.Equal(w) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("DNSClient.lookupDomain4() = %v, want %v", got, tt.want)
			}
		})
	}
}
