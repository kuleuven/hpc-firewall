package consulkvipset

import (
	"time"

	consul "github.com/hashicorp/consul/api"
)

// A Ipset represents a consul kv ipset
type Ipset interface {
	Records(uint64) ([]Record, uint64, error)
	IPs(uint64) ([]IP, time.Time, uint64, error)
	IPsAtTime(time.Time, uint64) ([]IP, uint64, error)
}

type kvIpset struct {
	kv        *consul.KV
	path      string
	records   []*kvRecord
	lastIndex uint64
}

// NewIpset returns a new KVIpset
func NewIpset(client *consul.Client, path string) Ipset {
	return &kvIpset{
		kv:   client.KV(),
		path: path,
	}
}

// Records retrieves all records of a KVIpset
func (s *kvIpset) Records(index uint64) ([]Record, uint64, error) {
	err := s.read(index)
	if err != nil {
		return nil, 0, err
	}

	result := []Record{}

	for _, record := range s.records {
		result = append(result, record)
	}

	return result, s.lastIndex, nil
}

// IPs returns a list of ips that are now in the ipset (regarding since and expiration)
func (s *kvIpset) IPs(index uint64) ([]IP, time.Time, uint64, error) {
	err := s.read(index)
	if err != nil {
		return nil, time.Time{}, 0, err
	}

	now := time.Now()

	var entries = []IP{}

	for _, record := range s.records {
		e := record.effective(now)
		entries = append(entries, e...)
	}

	return entries, now, s.lastIndex, nil
}

// IPsAtTime returns a list of ips that are in the ipset at a given time (regarding since and expiration)
func (s *kvIpset) IPsAtTime(now time.Time, index uint64) ([]IP, uint64, error) {
	err := s.read(index)
	if err != nil {
		return nil, 0, err
	}

	var entries = []IP{}

	for _, record := range s.records {
		e := record.effective(now)
		entries = append(entries, e...)
	}

	return entries, s.lastIndex, nil
}

func (s *kvIpset) read(index uint64) error {
	queryoptions := &consul.QueryOptions{}

	if index != 0 {
		queryoptions.WaitIndex = index
	}

	pairs, meta, err := s.kv.List(s.path, queryoptions)
	if err != nil {
		return err
	}

	newRecords := []*kvRecord{}

	var record *kvRecord

	for _, pair := range pairs {
		record = &kvRecord{
			kv:   s.kv,
			path: pair.Key,
		}

		err = record.readData(pair)
		if err != nil {
			return err
		}

		newRecords = append(newRecords, record)
	}

	s.records = newRecords
	s.lastIndex = meta.LastIndex

	return nil
}
