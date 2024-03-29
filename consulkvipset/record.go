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
)

// A Record represents a consul kv ipset record
type Record interface {
	IPs(uint64) ([]IP, time.Time, uint64, error)
	IPsAtTime(time.Time, uint64) ([]IP, uint64, error)
	Add(net.IP) (IP, error)
}

type kvRecord struct {
	kv        *consul.KV
	path      string
	addresses []*kvIP
	index     uint64
	lastIndex uint64
}

// NewRecord returns a new Record
func NewRecord(client *consul.Client, path string, label string) Record {
	return &kvRecord{
		kv:   client.KV(),
		path: path + "/" + label,
	}
}

// IPs returns a list of addresses that are currently valid
func (r *kvRecord) IPs(index uint64) ([]IP, time.Time, uint64, error) {
	if err := r.read(index); err != nil {
		return nil, time.Time{}, 0, err
	}

	now := time.Now()

	return r.effective(now), now, r.lastIndex, nil
}

// IPsAtTime returns a list of addresses that are valid at a given time
func (r *kvRecord) IPsAtTime(now time.Time, index uint64) ([]IP, uint64, error) {
	if err := r.read(index); err != nil {
		return nil, 0, err
	}

	return r.effective(now), r.lastIndex, nil
}

// Add an ip to the record
func (r *kvRecord) Add(ip net.IP) (IP, error) {
	var (
		err     error
		address IP
		success bool
	)

	for i := 0; i < Retries; i++ {
		err = r.read(0)
		if err != nil {
			return nil, err
		}

		address = r.add(ip)

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

func (r *kvRecord) read(index uint64) error {
	queryoptions := &consul.QueryOptions{}

	if index != 0 {
		queryoptions.WaitIndex = index
	}

	pair, meta, err := r.kv.Get(r.path, queryoptions)
	if err != nil {
		return fmt.Errorf("could not get key: %s", err)
	}

	r.lastIndex = meta.LastIndex

	return r.readData(pair)
}

func (r *kvRecord) readData(pair *consul.KVPair) error {
	if pair == nil {
		r.addresses = []*kvIP{}
		r.index = 0
	} else {
		r.index = pair.ModifyIndex

		if err := json.Unmarshal(pair.Value, &r.addresses); err != nil {
			log.Printf("could not parse current value: %s", err)
			r.addresses = []*kvIP{}
		}
	}

	return nil
}

func (r *kvRecord) effective(now time.Time) []IP {
	entries := []IP{}

	for _, address := range r.addresses {
		if address.addr == nil {
			continue
		}

		expires := address.expiration
		starts := address.since

		if (expires.IsZero() || now.Before(expires)) && (starts.IsZero() || now.Add(time.Second).After(starts)) {
			entries = append(entries, address)
		}
	}

	return entries
}

func (r *kvRecord) add(ip net.IP) IP {
	var (
		now          = time.Now()
		newAddresses = []*kvIP{}
	)

	a := newIP(ip, now, r.path)

	aIP := a.IP()

	for _, b := range r.addresses {
		if b.addr == nil {
			continue
		}

		if now.Before(b.Expiration()) {
			if b.IP().Equal(aIP) {
				if b.since.Before(a.since) {
					a.since = b.since
				}
			} else {
				newAddresses = append(newAddresses, b)
			}
		}
	}

	newAddresses = append(newAddresses, a)

	r.addresses = newAddresses

	return a
}

// Write ipset back using CAS
func (r *kvRecord) write() (bool, error) {
	data, err := json.Marshal(r.addresses)
	if err != nil {
		return false, fmt.Errorf("could not format as json: %s", err)
	}

	pair := &consul.KVPair{
		Key:         r.path,
		Value:       data,
		ModifyIndex: r.index,
	}

	var success bool

	success, _, err = r.kv.CAS(pair, nil)
	if err != nil {
		return false, fmt.Errorf("consul operation failed: %s", err)
	}

	return success, nil
}
