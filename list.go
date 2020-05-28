package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gitea.icts.kuleuven.be/hpc/hpc-firewall/consulkvipset"
	echo "github.com/labstack/echo/v4"
)

// An ListResponse serves as structure for add responses
type ListResponse struct {
	NeedsRefresh bool      `json:"session_expired"`
	IPs          []*ListIP `json:"records"`
	LastIndex    uint64    `json:"last_index"`
}

// A ListIP represents a single ip
type ListIP struct {
	IP       string `json:"ip"`
	Since    string `json:"since"`
	Until    string `json:"until"`
	Lifetime uint   `json:"lifetime"`
	Message  string `json:"message"`
}

func (f *Firewall) handleList(c echo.Context) error {
	info, _ := f.checkAuthenticated(c)

	if info != nil {
		return f.handleListAuthenticated(c, info)
	}

	// Redirect if not valid
	r := &ListResponse{
		NeedsRefresh: true,
	}

	return c.JSON(http.StatusOK, r)
}

func (f *Firewall) handleListAuthenticated(c echo.Context, info *UserInfo) error {
	var (
		record     = consulkvipset.NewRecord(f.ConsulClient, f.ConsulPath, info.ID)
		givenIndex = c.FormValue("index")
		index      uint64
		err        error
		ts         []consulkvipset.IP
		now        time.Time
	)

	// Parse index
	if givenIndex != "" {
		index, err = strconv.ParseUint(givenIndex, 10, 64)
		if err != nil {
			return err
		}
	}

	ts, now, index, err = record.IPs(index)
	if err != nil {
		return err
	}

	r := &ListResponse{
		IPs:       []*ListIP{},
		LastIndex: index,
	}

	for _, t := range ts {
		r.IPs = append(r.IPs, &ListIP{
			IP:       t.IP().String(),
			Since:    t.Since().Format("2006-01-02 15:04:05"),
			Until:    t.Expiration().Format("15:04:05"),
			Lifetime: uint(t.Expiration().Sub(now).Seconds()),
			Message:  fmt.Sprintf("IP is granted access since %s [valid until %s]", t.Since().Format("2006-01-02 15:04:05"), t.Expiration().Format("15:04:05")),
		})
	}

	return c.JSON(http.StatusOK, r)
}
