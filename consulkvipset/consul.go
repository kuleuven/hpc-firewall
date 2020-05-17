package consulkvipset

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	consul "github.com/hashicorp/consul/api"
)

const (
	// Retries specifies the maximum retries of the AddConsulIpsetRecord function to put a value in the kv store
	Retries = 10
	// IpsetTimeout specifies the expiration of the ipset entry
	IpsetTimeout = 5 * time.Minute
)

// A KVIpset represents a consul kv ipset
type KVIpset struct {
	KV      *consul.KV
	Path    string
	records []KVIpsetRecord
	index   uint64
}

// A KVIpsetRecord represents an IP in the consul kv store to be used for an ipset
type KVIpsetRecord struct {
	Since      time.Time `json:"since"`
	Expiration time.Time `json:"expiration"`
	IP         string    `json:"ip"`
}

// NewKVIpset returns a new KVIpset
func NewKVIpset(client *consul.Client, path string) *KVIpset {
	return &KVIpset{
		KV:   client.KV(),
		Path: path,
	}
}

// Read ipset
func (s *KVIpset) Read() error {
	pair, _, err := s.KV.Get(s.Path, nil)
	if err != nil {
		return fmt.Errorf("could not get key: %s", err)
	}

	if pair == nil {
		s.records = []KVIpsetRecord{}
		s.index = 0
	} else {
		s.index = pair.ModifyIndex

		err = json.Unmarshal(pair.Value, &s.records)
		if err != nil {
			log.Printf("could not parse current value: %s", err)
			s.records = []KVIpsetRecord{}
		}
	}

	return nil
}

// Add an ip to the ipset in memory
func (s *KVIpset) Add(ip string) (*KVIpsetRecord, error) {
	var (
		now    = time.Now()
		record = KVIpsetRecord{
			Since:      now,
			Expiration: now.Add(IpsetTimeout),
			IP:         ip,
		}
	)

	newRecords := []KVIpsetRecord{}

	for _, r := range s.records {
		if now.Before(r.Expiration) {
			if r.IP == record.IP {
				record.Since = r.Since
			} else {
				newRecords = append(newRecords, r)
			}
		}
	}

	newRecords = append(newRecords, record)

	s.records = newRecords

	return &record, nil
}

// Write ipset back using CAS
func (s *KVIpset) Write() (bool, error) {
	data, err := json.Marshal(s.records)
	if err != nil {
		return false, fmt.Errorf("could not format as json: %s", err)
	}

	pair := &consul.KVPair{
		Key:         s.Path,
		Value:       data,
		ModifyIndex: s.index,
	}

	var success bool

	success, _, err = s.KV.CAS(pair, nil)
	if err != nil {
		return false, fmt.Errorf("consul operation failed: %s", err)
	}

	return success, nil
}

// AddConsulIpsetRecord ads an ip to the consul KV store at the given path
func AddIpsetRecord(client *consul.Client, path string, ip string) (*KVIpsetRecord, error) {
	s := NewKVIpset(client, path)

	var (
		err     error
		record  *KVIpsetRecord
		success bool
	)

	for i := 0; i < Retries; i++ {
		err = s.Read()
		if err != nil {
			return nil, err
		}

		record, err = s.Add(ip)
		if err != nil {
			return nil, err
		}

		success, err = s.Write()
		if err != nil {
			return nil, err
		}

		if success {
			return record, nil
		}
	}

	return nil, fmt.Errorf("tried %d times, retry limit exceeded", Retries)
}
