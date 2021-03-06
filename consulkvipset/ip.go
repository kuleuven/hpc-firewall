package consulkvipset

import (
	"encoding/json"
	"net"
	"time"
)

var (
	// IpsetMaxTimeout specifies max ipset timeout of values from consul
	IpsetMaxTimeout = 86400 * time.Second

	// IpsetTimeout specifies the expiration of the ipset entry
	IpsetTimeout = 5 * time.Minute
)

// A IP represent a single address in a Record
type IP interface {
	IP() net.IP
	Since() time.Time
	Expiration() time.Time
	Timeout(time.Time) time.Duration
	Comment() string
}

type kvIP struct {
	addr       net.IP
	since      time.Time
	expiration time.Time
	comment    string
}

func newIP(ip net.IP, now time.Time, comment string) *kvIP {
	return &kvIP{
		addr:       ip,
		since:      now,
		expiration: now.Add(IpsetTimeout),
		comment:    comment,
	}
}

// IP of IP
func (a *kvIP) IP() net.IP {
	return a.addr
}

// Since represents the start date the ip was active
func (a *kvIP) Since() time.Time {
	return a.since
}

// Expiration represents the end date until which the ip is active
func (a *kvIP) Expiration() time.Time {
	return a.expiration
}

// Timeout calculates the timeout of the ip
func (a *kvIP) Timeout(now time.Time) time.Duration {
	var timeout time.Duration

	if a.expiration.IsZero() {
		timeout = IpsetMaxTimeout
	} else {
		timeout = a.expiration.Sub(now)
		if timeout > IpsetMaxTimeout {
			timeout = IpsetMaxTimeout
		} else if timeout < 0 {
			timeout = 0
		}
	}

	return timeout
}

// Comment represents a string
func (a *kvIP) Comment() string {
	return a.comment
}

type ipJSON struct {
	Addr       string    `json:"ip"`
	Since      time.Time `json:"since"`
	Expiration time.Time `json:"expiration"`
	Comment    string    `json:"comment"`
}

// Implement json.Unmarshaller
func (a *kvIP) UnmarshalJSON(b []byte) error {
	d := ipJSON{}

	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}

	a.addr = net.ParseIP(d.Addr)
	a.since = d.Since
	a.expiration = d.Expiration
	a.comment = d.Comment

	return nil
}

// Implement json.Marshaller
func (a *kvIP) MarshalJSON() ([]byte, error) {
	return json.Marshal(ipJSON{
		Addr:       a.addr.String(),
		Since:      a.since,
		Expiration: a.expiration,
		Comment:    a.comment,
	})
}

// An IpsetEntry describes an entry to be added to some ipset
type IpsetEntry struct {
	IP      net.IP `json:"ip"`
	Timeout int    `json:"timeout"`
	Comment string `json:"comment"`
}

// ToIpsetEntries converts a list of ips to ipset entries, calculating timeout values
func ToIpsetEntries(ips []IP, now time.Time) ([]IpsetEntry, error) {
	var (
		entries = []IpsetEntry{}
		timeout int
	)

	for _, address := range ips {
		timeout = int(address.Timeout(now).Seconds())

		if timeout > 0 {
			entries = append(entries, IpsetEntry{
				IP:      address.IP(),
				Timeout: timeout,
				Comment: address.Comment(),
			})
		}
	}

	return entries, nil
}
