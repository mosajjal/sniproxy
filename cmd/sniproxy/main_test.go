package main

import (
	"errors"
	"slices"
	"testing"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/rawbytes"
)

func TestIsLoopbackAddr(t *testing.T) {
	for _, tc := range []struct {
		bind string
		want bool
	}{
		{"127.0.0.1:6060", true},
		{"127.1.2.3:6060", true},
		{"localhost:6060", true},
		{"[::1]:6060", true},
		{"0.0.0.0:6060", false},
		{"[::]:6060", false},
		{":6060", false}, // every interface
		{"192.168.1.10:6060", false},
		{"example.com:6060", false}, // could resolve anywhere
		{"6060", false},             // not host:port at all
		{"", false},
	} {
		if got := isLoopbackAddr(tc.bind); got != tc.want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", tc.bind, got, tc.want)
		}
	}
}

func TestPortList(t *testing.T) {
	for _, tc := range []struct {
		yaml string
		want []string
	}{
		{`ports: [8443, "8444-8446"]`, []string{"8443", "8444-8446"}},
		{`ports: "8443,8444-8446"`, []string{"8443", "8444-8446"}},
		{`ports: "8443, 8444-8446"`, []string{"8443", "8444-8446"}},
		{`ports: 8443`, []string{"8443"}},
		{`ports:`, []string{}},
	} {
		k := koanf.New(".")
		if err := k.Load(rawbytes.Provider([]byte(tc.yaml)), yaml.Parser()); err != nil {
			t.Fatal(err)
		}
		if got := portList(k, "ports"); !slices.Equal(got, tc.want) {
			t.Errorf("portList(%s) = %q, want %q", tc.yaml, got, tc.want)
		}
	}
}

func TestPublicIP(t *testing.T) {
	detected := func() (string, error) { return "192.0.2.1", nil }
	unreachable := func() (string, error) { return "", errors.New("network is unreachable") }

	for _, tc := range []struct {
		name       string
		configured string
		detect     func() (string, error)
		want       string
	}{
		{"configured", "198.51.100.1", unreachable, "198.51.100.1"},
		{"detected", "", detected, "192.0.2.1"},
		{"detection fails", "", unreachable, ""},
	} {
		if got := publicIP(tc.configured, tc.detect, "IPv6"); got != tc.want {
			t.Errorf("%s: publicIP() = %q, want %q", tc.name, got, tc.want)
		}
	}
}
