package main

import (
	"fmt"
	"net/http"
	"strings"

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
	ID               string
	Bearer           string
	AddURL           string
	ListURL          string
	AddURLSubdomains []string
}

func (f *Firewall) handleRootAuthenticated(c echo.Context, info *UserInfo, payload *CookiePayload) error {
	endpoints := []string{}
	for _, s := range f.Endpoints {
		switch {
		case strings.Contains(s, "/"):
			endpoints = append(endpoints, fmt.Sprintf("https://%s", s))
		case strings.Contains(s, "."):
			endpoints = append(endpoints, fmt.Sprintf("https://%s/add", s))
		default:
			endpoints = append(endpoints, fmt.Sprintf("https://%s.%s/add", s, f.Domain))
		}
	}

	encoded, err := f.SecureCookie.Encode(CookieName, payload)
	if err != nil {
		return err
	}

	response := RootPayload{
		ID:               info.ID,
		ListURL:          fmt.Sprintf("https://%s/list", f.Domain),
		AddURL:           fmt.Sprintf("https://%s/add", f.Domain),
		AddURLSubdomains: endpoints,
		Bearer:           encoded,
	}

	return c.Render(http.StatusOK, "root", response)
}
