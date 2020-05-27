package main

import (
	"fmt"
	"net/http"

	echo "github.com/labstack/echo/v4"
)

func (f *Firewall) handleRoot(c echo.Context) error {
	info, payload := f.checkAuthenticated(c)

	if info != nil {
		return f.handleRootAuthenticated(c, info, payload)
	}

	// Redirect if not valid
	stateString, err := f.NewOauthSessionToken()
	if err != nil {
		return err
	}

	url := f.OauthConfig.AuthCodeURL(stateString)
	return c.Redirect(http.StatusTemporaryRedirect, url)
}

// RootPayload serves as payload for the root.html template
type RootPayload struct {
	ID        string
	Endpoints []string
	Bearer    string
	Endpoint  string
}

func (f *Firewall) handleRootAuthenticated(c echo.Context, info *UserInfo, payload *CookiePayload) error {
	endpoints := []string{}
	for _, s := range f.Subdomains {
		endpoints = append(endpoints, fmt.Sprintf("https://%s.%s/add", s, f.Domain))
	}

	encoded, err := f.SecureCookie.Encode(CookieName, payload)
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("https://%s/add", f.Domain)

	response := RootPayload{
		ID:        info.ID,
		Endpoints: endpoints,
		Bearer:    encoded,
		Endpoint:  endpoint,
	}

	return c.Render(http.StatusOK, "root", response)
}
