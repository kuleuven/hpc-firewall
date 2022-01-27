package main

import (
	"fmt"
	"net/http"

	"gitea.icts.kuleuven.be/hpc/hpc-firewall/consulkvipset"
	echo "github.com/labstack/echo/v4"
)

// An AddResponse serves as structure for add responses
type AddResponse struct {
	NeedsRefresh bool   `json:"session_expired"`
	Message      string `json:"message"`
	IP           string `json:"ip"`
}

func (f *Firewall) handleAdd(c echo.Context) error {
	info, _ := f.checkAuthenticated(c)

	if info != nil {
		return f.handleAddAuthenticated(c, info)
	}

	// Redirect if not valid
	r := &AddResponse{
		NeedsRefresh: true,
		Message:      "Not authenticated, please refresh the page",
	}

	return c.JSON(http.StatusOK, r)
}

func (f *Firewall) handleAddAuthenticated(c echo.Context, info *UserInfo) error {
	ip := getFFIP(c.Request().Header.Get("X-LB-Forwarded-For"))

	for _, trustedIP := range f.TrustedProxies {
		if ip == trustedIP {
			ip = getFFIP(c.Request().Header.Get("X-Orig-Forwarded-For"))
		}
	}

	t, err := consulkvipset.AddIpsetRecord(f.ConsulClient, f.ConsulPath, info.ID, ip)
	if err != nil {
		return fmt.Errorf("could not add ip to consul kv store: %s", err)
	}

	// Return response
	r := &AddResponse{
		IP:      ip,
		Message: fmt.Sprintf("IP is granted access since %s [valid until %s]", t.Since().Format("2006-01-02 15:04:05"), t.Expiration().Format("15:04:05")),
	}

	return c.JSON(http.StatusOK, r)
}
