package consulkvipset

import (
	"fmt"
	"net"
	"time"

	consul "github.com/hashicorp/consul/api"
)

// AddIpsetRecord ads an ip to the consul KV store at the given path
func AddIpsetRecord(client *consul.Client, path string, label string, ip string) (IP, error) {
	r := NewRecord(client, path, label)

	a := net.ParseIP(ip)
	if a == nil {
		return nil, fmt.Errorf("could not format ip: %s", ip)
	}

	return r.Add(a)
}

// ListEffectiveIPs list all currently effective IPs
func ListEffectiveIPs(client *consul.Client, path string, index uint64) ([]IpsetEntry, uint64, error) {
	var (
		ips     []IP
		entries []IpsetEntry
		err     error
		now     time.Time
		s       = NewIpset(client, path)
	)

	ips, now, index, err = s.IPs(index)
	if err != nil {
		return nil, index, err
	}

	entries, err = ToIpsetEntries(ips, now)

	return entries, index, err
}
