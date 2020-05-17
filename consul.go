package main

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

// A ConsulKVIpsetRecord represents an IP in the consul kv store to be used for an ipset
type ConsulKVIpsetRecord struct {
	Since      time.Time `json:"since"`
	Expiration time.Time `json:"expiration"`
	IP         string    `json:"ip"`
}

// AddConsulIpsetRecord ads an ip to the consul KV store at the given path
// golint:ignore
func AddConsulIpsetRecord(kv *consul.KV, path string, ip string) (*ConsulKVIpsetRecord, error) {
	var (
		now    = time.Now()
		record = ConsulKVIpsetRecord{
			Since:      now,
			Expiration: now.Add(IpsetTimeout),
			IP:         ip,
		}
		index uint64
	)

	for i := 0; i < Retries; i++ {
		pair, _, err := kv.Get(path, nil)
		if err != nil {
			return nil, fmt.Errorf("could not get key: %s", err)
		}

		oldRecords := []ConsulKVIpsetRecord{}

		if pair != nil {
			index = pair.ModifyIndex

			err = json.Unmarshal(pair.Value, &oldRecords)
			if err != nil {
				log.Printf("could not parse current value: %s", err)
			}
		}

		newRecords := []ConsulKVIpsetRecord{record}

		for _, r := range oldRecords {
			if r.Expiration.After(now) {
				if r.IP == record.IP {
					record.Since = r.Since
				} else {
					newRecords = append(newRecords, record)
				}
			}
		}

		var data []byte

		data, err = json.Marshal(newRecords)
		if err != nil {
			return nil, fmt.Errorf("could not format as json: %s", err)
		}

		pair = &consul.KVPair{
			Key:         path,
			Value:       data,
			ModifyIndex: index,
		}

		var success bool

		success, _, err = kv.CAS(pair, nil)
		if err != nil {
			return nil, fmt.Errorf("consul operation failed: %s", err)
		}

		if success {
			return &record, nil
		}
	}

	return nil, fmt.Errorf("tried %d times, retry limit exceeded", Retries)
}
