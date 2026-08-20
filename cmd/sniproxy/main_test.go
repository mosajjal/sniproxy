package main

import "testing"

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
