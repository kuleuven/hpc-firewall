package consulkvipset

import (
	"time"

	consul "github.com/hashicorp/consul/api"
)

// A KVIpset represents a consul kv ipset
type KVIpset struct {
	kv        *consul.KV
	path      string
	Records   []*KVIpsetRecord
	LastIndex uint64
}

// NewKVIpset returns a new KVIpset
func newKVIpset(client *consul.Client, path string) *KVIpset {
	return &KVIpset{
		kv:   client.KV(),
		path: path,
	}
}

// Read a KVIpset completely
func (s *KVIpset) read(index uint64) error {
	queryoptions := &consul.QueryOptions{}

	if index != 0 {
		queryoptions.WaitIndex = index
	}

	pairs, meta, err := s.kv.List(s.path, queryoptions)
	if err != nil {
		return err
	}

	newRecords := []*KVIpsetRecord{}

	var record *KVIpsetRecord

	for _, pair := range pairs {
		record = &KVIpsetRecord{
			kv:   s.kv,
			path: pair.Key,
		}

		err = record.readData(pair)
		if err != nil {
			return err
		}

		newRecords = append(newRecords, record)
	}

	s.Records = newRecords
	s.LastIndex = meta.LastIndex

	return nil
}

// EffectiveIPs returns a list of ips that are now in the ipset (regarding since and expiration)
func (s *KVIpset) effectiveIPs(now time.Time) ([]IpsetEntry, error) {
	var (
		entries = []IpsetEntry{}
	)

	for _, record := range s.Records {
		e, err := record.effectiveIPs(now)
		if err != nil {
			return nil, err
		}

		entries = append(entries, e...)
	}

	return entries, nil
}
