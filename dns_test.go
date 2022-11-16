package main

import (
	"net"
	"testing"

	"github.com/mosajjal/dnsclient"
)

func Test_reverse(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{name: "test1", s: "abc", want: "cba"},
		{name: "test2", s: "a", want: "a"},
		{name: "test3", s: "aab", want: "baa"},
		{name: "test4", s: "zzZ", want: "Zzz"},
		{name: "test5", s: "ab2", want: "2ba"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reverse(tt.s); got != tt.want {
				t.Errorf("reverse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDNSClient_lookupDomain4(t *testing.T) {
	tmp, err := dnsclient.New("udp://1.1.1.1:53", true)
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
