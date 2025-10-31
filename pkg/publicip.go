package sniproxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// GetPublicIPv4 tries to determine the IPv4 address of the host
// method 1: establish a udp connection to a known DNS server and see if we can get lucky by having a non-RFC1918 address on the interface
// method 2: use a public HTTP service to get the public IP
// note that neither of these methods are bulletproof, so there is always a chance that you need to enter the public IP manually
func GetPublicIPv4() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	ipaddr := localAddr[0:idx]
	if !net.ParseIP(ipaddr).IsPrivate() {
		return ipaddr, nil
	}
	externalIP := ""
	// trying to get the public IP from multiple sources to see if they match.
	resp, err := http.Get("https://4.ident.me")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			externalIP = string(body)
		}

		if externalIP != "" {
			return externalIP, nil
		}
	}
	return "", fmt.Errorf("could not determine the public IPv4 address, please specify it in the configuration")
}

// cleanIPv6 removes the brackets from an IPv6 address
func cleanIPv6(ip string) string {
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	return ip
}

// GetPublicIPv6 tries to determine the IPv6 address of the host
// method 1: establish a udp connection to a known DNS server and see if we can get lucky by having a non-RFC1918 address on the interface
// method 2: use a public HTTP service to get the public IP
// method 3: send a DNS query to OpenDNS to get the public IP. DISABLED
// note that neither of these methods are bulletproof, so there is always a chance that you need to enter the public IP manually
func GetPublicIPv6() (string, error) {
	conn, err := net.Dial("udp6", "[2001:4860:4860::8888]:53")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().String()
	idx := strings.LastIndex(localAddr, ":")
	ipaddr := localAddr[0:idx]
	if !net.ParseIP(ipaddr).IsPrivate() {
		return cleanIPv6(ipaddr), nil
	}
	externalIP := ""
	// trying to get the public IP from multiple sources to see if they match.
	resp, err := http.Get("https://6.ident.me")
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			externalIP = string(body)
		}

		if externalIP != "" {
			return cleanIPv6(externalIP), nil
		}
	}
	return "", fmt.Errorf("could not determine the public IPv6 address, please specify it in the configuration")
}
