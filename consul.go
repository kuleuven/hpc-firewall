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
	Expiration time.Time `json:"expiration"`
	IP         string    `json:"ip"`
}

// AddConsulIpsetRecord ads an ip to the consul KV store at the given path
func AddConsulIpsetRecord(kv *consul.KV, path string, ip string) error {
	var (
		now    = time.Now()
		record = ConsulKVIpsetRecord{
			Expiration: now.Add(IpsetTimeout),
			IP:         ip,
		}
		oldRecords []ConsulKVIpsetRecord
		newRecords []ConsulKVIpsetRecord
		pair       *consul.KVPair
		newData    []byte
		index      uint64
		err        error
	)

	for i := 0; i < Retries; i++ {
		pair, _, err = kv.Get(path, nil)
		if err != nil {
			return fmt.Errorf("could not get key: %s", err)
		}

		if pair == nil {
			oldRecords = []ConsulKVIpsetRecord{}
		} else {
			index = pair.ModifyIndex

			err = json.Unmarshal(pair.Value, &oldRecords)
			if err != nil {
				log.Printf("could not parse current value: %s", err)
				oldRecords = []ConsulKVIpsetRecord{}
			}
		}

		// Update records
		newRecords = []ConsulKVIpsetRecord{record}

		for _, r := range oldRecords {
			if r.Expiration.After(now) && r.IP != record.IP {
				newRecords = append(newRecords, record)
			}
		}

		// Save records
		newData, err = json.Marshal(newRecords)
		if err != nil {
			return fmt.Errorf("could not format as json: %s", err)
		}

		pair = &consul.KVPair{
			Key:         path,
			Value:       newData,
			ModifyIndex: index,
		}

		_, err = kv.Put(pair, nil)
		if err == nil {
			break
		}
	}

	return err
}
