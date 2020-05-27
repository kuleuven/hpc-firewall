package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gitea.icts.kuleuven.be/hpc/hpc-firewall/consulkvipset"
	echo "github.com/labstack/echo/v4"
)

func (f *Firewall) handleIpset(c echo.Context) error {
	_, payload := f.checkAuthenticated(c)

	if payload != nil && payload.Admin {
		return f.handleIpsetAuthenticated(c)
	}

	return c.JSON(http.StatusUnauthorized, nil)
}

func (f *Firewall) handleIpsetAuthenticated(c echo.Context) error {
	var (
		givenIndex = c.FormValue("index")
		result     []consulkvipset.IpsetEntry
		index      uint64
		err        error
	)

	// Parse index
	if givenIndex != "" {
		index, err = strconv.ParseUint(givenIndex, 10, 64)
		if err != nil {
			return err
		}
	}

	// Rate limit
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = f.RateLimit.Wait(ctx)
	if err == context.DeadlineExceeded {
		return c.JSON(http.StatusTooManyRequests, nil)
	} else if err != nil {
		return err
	}

	// List effective ips
	result, index, err = consulkvipset.ListEffectiveIPs(f.ConsulClient, f.ConsulPath, index)
	if err != nil {
		return err
	}

	// Send response
	c.Response().Header().Set("X-Last-Index", fmt.Sprintf("%d", index))
	c.Response().WriteHeader(http.StatusOK)

	return json.NewEncoder(c.Response()).Encode(&result)
}
