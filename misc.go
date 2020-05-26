package main

import (
	"net"
	"strings"
)

func getFFIP(fwdAddress string) string {
	XFFip := strings.Split(fwdAddress, ",")
	ip := strings.TrimSpace(XFFip[len(XFFip)-1])

	ip = strings.ReplaceAll(ip, "[", "")
	ip = strings.ReplaceAll(ip, "]", "")

	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}

	return i.String()
}
