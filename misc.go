package main

import (
	"net"
	"strings"
)

func getFFIP(fwdAddress string) string {
	ip := fwdAddress
	// If we got an array... grab the first IP
	ips := strings.Split(fwdAddress, ", ")
	if len(ips) > 1 {
		ip = ips[0]
	}

	ip = strings.TrimSpace(ip)
	ip = strings.ReplaceAll(ip, "[", "")
	ip = strings.ReplaceAll(ip, "]", "")

	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}

	return i.String()
}
