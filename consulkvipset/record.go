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
	// IpsetTimeout specifies the expiration of the ipset entry
	IpsetTimeout = 5 * time.Minute
	// IpsetMaxTimeout specifies max ipset timeout of values from consul
	IpsetMaxTimeout uint = 86400
)

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

// NewKVIpsetRecord returns a new KVIpsetRecord
func newKVIpsetRecord(client *consul.Client, path string) *KVIpsetRecord {
	return &KVIpsetRecord{
		kv:   client.KV(),
		path: path,
	}
}

// Read ipset record
func (r *KVIpsetRecord) read() error {
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

// An IpsetEntry describes an entry to be added to some ipset
type IpsetEntry struct {
	Addr    string
	Timeout uint
	Comment string
}

// EffectiveIPs returns a list of ips that are now in the ipset (regarding since and expiration)
func (r *KVIpsetRecord) effectiveIPs(now time.Time) ([]IpsetEntry, error) {
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
func (r *KVIpsetRecord) add(ip string) (*KVIpsetAddress, error) {
	// validate address
	if addr := net.ParseIP(ip); addr == nil {
		return nil, fmt.Errorf("invalid address: %s", ip)
	}

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
func (r *KVIpsetRecord) write() (bool, error) {
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
