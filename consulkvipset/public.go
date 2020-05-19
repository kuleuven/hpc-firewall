package consulkvipset

import (
	"fmt"
	"time"

	consul "github.com/hashicorp/consul/api"
)

const (
	// Retries specifies the maximum retries of the AddConsulIpsetRecord function to put a value in the kv store
	Retries = 10
)

// AddIpsetRecord ads an ip to the consul KV store at the given path
func AddIpsetRecord(client *consul.Client, path string, label string, ip string) (*KVIpsetAddress, error) {
	r := newKVIpsetRecord(client, path+"/"+label)

	var (
		err     error
		address *KVIpsetAddress
		success bool
	)

	for i := 0; i < Retries; i++ {
		err = r.read()
		if err != nil {
			return nil, err
		}

		address, err = r.add(ip)
		if err != nil {
			return nil, err
		}

		success, err = r.write()
		if err != nil {
			return nil, err
		}

		if success {
			return address, nil
		}
	}

	return nil, fmt.Errorf("tried %d times, retry limit exceeded", Retries)
}

// ListEffectiveIPs list all currently effective IPs
func ListEffectiveIPs(client *consul.Client, path string, index uint64) ([]IpsetEntry, uint64, error) {
	now := time.Now()

	s := newKVIpset(client, path)

	if err := s.read(index); err != nil {
		return nil, 0, err
	}

	entries, err := s.effectiveIPs(now)

	return entries, s.LastIndex, err
}
