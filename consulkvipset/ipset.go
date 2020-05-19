package consulkvipset

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	consul "github.com/hashicorp/consul/api"
)

const (
	// Retries specifies the maximum retries of the AddConsulIpsetRecord function to put a value in the kv store
	Retries = 10
	// IpsetTimeout specifies the expiration of the ipset entry
	IpsetTimeout = 5 * time.Minute
	// IpsetMaxTimeout specifies max ipset timeout of values from consul
	IpsetMaxTimeout uint = 86400
)

// A KVIpset represents a consul kv ipset
type KVIpset struct {
	kv        *consul.KV
	path      string
	Records   []*KVIpsetRecord
	LastIndex uint64
}

// A KVIpsetRecord represents a collection of addresses in the consul kv store to be used for an ipset
type KVIpsetRecord struct {
	kv        *consul.KV
	path      string
	Addresses []KVIpsetAddress
	Index     uint64
}

// A KVIpsetAddress represents an IP in the consul kv store to be used for an ipset
type KVIpsetAddress struct {
	Since      time.Time `json:"since"`
	Expiration time.Time `json:"expiration"`
	IP         string    `json:"ip"`
}

// NewKVIpset returns a new KVIpset
func NewKVIpset(client *consul.Client, path string) *KVIpset {
	return &KVIpset{
		kv:   client.KV(),
		path: path,
	}
}

// Read a KVIpset completely
func (s *KVIpset) Read(index uint64) error {
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

// An IpsetEntry describes an entry to be added to some ipset
type IpsetEntry struct {
	Addr    string
	Timeout uint
	Comment string
}

// EffectiveIPs returns a list of ips that are now in the ipset (regarding since and expiration)
func (s *KVIpset) EffectiveIPs(now time.Time) ([]IpsetEntry, error) {
	var (
		entries = []IpsetEntry{}
	)

	for _, record := range s.Records {
		e, err := record.EffectiveIPs(now)
		if err != nil {
			return nil, err
		}

		entries = append(entries, e...)
	}

	return entries, nil
}

// NewKVIpsetRecord returns a new KVIpsetRecord
func NewKVIpsetRecord(client *consul.Client, path string) *KVIpsetRecord {
	return &KVIpsetRecord{
		kv:   client.KV(),
		path: path,
	}
}

// Read ipset record
func (r *KVIpsetRecord) Read() error {
	pair, _, err := r.kv.Get(r.path, nil)
	if err != nil {
		return fmt.Errorf("could not get key: %s", err)
	}

	return r.readData(pair)
}

func (r *KVIpsetRecord) readData(pair *consul.KVPair) error {
	if pair == nil {
		r.Addresses = []KVIpsetAddress{}
		r.Index = 0
	} else {
		r.Index = pair.ModifyIndex

		if err := json.Unmarshal(pair.Value, &r.Addresses); err != nil {
			log.Printf("could not parse current value: %s", err)
			r.Addresses = []KVIpsetAddress{}
		}
	}

	return nil
}

// EffectiveIPs returns a list of ips that are now in the ipset (regarding since and expiration)
func (r *KVIpsetRecord) EffectiveIPs(now time.Time) ([]IpsetEntry, error) {
	var (
		entries = []IpsetEntry{}
	)

	for _, address := range r.Addresses {
		expires := address.Expiration
		starts := address.Since

		if (expires.IsZero() || now.Before(expires)) && (starts.IsZero() || now.After(starts)) {
			var timeout uint

			if expires.IsZero() {
				timeout = IpsetMaxTimeout
			} else {
				timeout = uint(expires.Sub(now).Seconds())
				if timeout > IpsetMaxTimeout {
					timeout = IpsetMaxTimeout
				} else if timeout == 0 {
					continue
				}
			}

			addr := net.ParseIP(address.IP)

			if addr == nil {
				return nil, fmt.Errorf("invalid address %s", address.IP)
			}

			entries = append(entries, IpsetEntry{
				Addr:    addr.String(),
				Timeout: timeout,
				Comment: r.path,
			})
		}
	}

	return entries, nil
}

// Add an ip to the ipset in memory
func (r *KVIpsetRecord) Add(ip string) (*KVIpsetAddress, error) {
	var (
		now     = time.Now()
		address = KVIpsetAddress{
			Since:      now,
			Expiration: now.Add(IpsetTimeout),
			IP:         ip,
		}
	)

	newAddresses := []KVIpsetAddress{}

	for _, a := range r.Addresses {
		if now.Before(a.Expiration) {
			if a.IP == address.IP {
				address.Since = a.Since
			} else {
				newAddresses = append(newAddresses, a)
			}
		}
	}

	newAddresses = append(newAddresses, address)

	r.Addresses = newAddresses

	return &address, nil
}

// Write ipset back using CAS
func (r *KVIpsetRecord) Write() (bool, error) {
	data, err := json.Marshal(r.Addresses)
	if err != nil {
		return false, fmt.Errorf("could not format as json: %s", err)
	}

	pair := &consul.KVPair{
		Key:         r.path,
		Value:       data,
		ModifyIndex: r.Index,
	}

	var success bool

	success, _, err = r.kv.CAS(pair, nil)
	if err != nil {
		return false, fmt.Errorf("consul operation failed: %s", err)
	}

	return success, nil
}

// ListEffectiveIPs list all currently effective IPs
func ListEffectiveIPs(client *consul.Client, path string, index uint64) ([]IpsetEntry, uint64, error) {
	now := time.Now()

	s := NewKVIpset(client, path)

	if err := s.Read(index); err != nil {
		return nil, 0, err
	}

	entries, err := s.EffectiveIPs(now)

	return entries, s.LastIndex, err
}

// AddIpsetRecord ads an ip to the consul KV store at the given path
func AddIpsetRecord(client *consul.Client, path string, label string, ip string) (*KVIpsetAddress, error) {
	r := NewKVIpsetRecord(client, path+"/"+label)

	var (
		err     error
		address *KVIpsetAddress
		success bool
	)

	for i := 0; i < Retries; i++ {
		err = r.Read()
		if err != nil {
			return nil, err
		}

		address, err = r.Add(ip)
		if err != nil {
			return nil, err
		}

		success, err = r.Write()
		if err != nil {
			return nil, err
		}

		if success {
			return address, nil
		}
	}

	return nil, fmt.Errorf("tried %d times, retry limit exceeded", Retries)
}
