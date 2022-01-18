//go:generate rice embed-go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"gitea.icts.kuleuven.be/ceif-lnx/go/webapp/framework"
	rice "github.com/GeertJohan/go.rice"
	"github.com/gorilla/securecookie"
	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2"
	"golang.org/x/time/rate"
)

const (
	OauthAuthURL       = "https://account.vscentrum.be/django/oauth/authorize/"
	OauthTokenURL      = "https://account.vscentrum.be/django/oauth/token/"
	OauthIntrospectURL = "https://apivsc.ugent.be/django/oauth/current_vsc_user"
	OauthCallbackURL   = "https://%s/callback"
	CookieName         = "hpc-firewall"
)

// A FirewallConfig object represents all firewall paramters
type FirewallConfig struct {
	OauthClientID     string
	OauthClientSecret string
	ConsulURL         string
	ConsulToken       string
	ConsulPath        string
	HashKey           string
	BlockKey          string
	AddIPSecret       string
	Domain            string
	Subdomains        []string
}

// A Firewall object represents a firewall service
type Firewall struct {
	FirewallConfig
	OauthConfig  *oauth2.Config
	ConsulClient *consul.Client
	RateLimit    *rate.Limiter
	HashKey      []byte
	BlockKey     []byte
	AddIPSecret  []byte
	SecureCookie *securecookie.SecureCookie
}

// NewFirewall creates a new firewall
func NewFirewall(config FirewallConfig) (*Firewall, error) {
	// Oauth config
	oauthConfig := &oauth2.Config{
		RedirectURL:  fmt.Sprintf(OauthCallbackURL, config.Domain),
		ClientID:     config.OauthClientID,
		ClientSecret: config.OauthClientSecret,
		Scopes:       []string{"read"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  OauthAuthURL,
			TokenURL: OauthTokenURL,
		},
	}

	// Consul client
	consulConfig := consul.DefaultConfig()
	if config.ConsulURL != "" {
		consulConfig.Address = config.ConsulURL
	}
	if config.ConsulToken != "" {
		consulConfig.Token = config.ConsulToken
	}

	consulClient, err := consul.NewClient(consulConfig)
	if err != nil {
		return nil, err
	}

	// Hash and block keys
	hashKeyBytes := []byte(config.HashKey)
	if len(hashKeyBytes) < 32 {
		return nil, fmt.Errorf("hash key should be at least 32 bytes long, got %s", hashKeyBytes)
	}

	var blockKeyBytes []byte
	if config.BlockKey != "" {
		blockKeyBytes = []byte(config.BlockKey)
		if len(blockKeyBytes) != 16 && len(blockKeyBytes) != 32 {
			return nil, fmt.Errorf("block key should be 16 or 32 bytes long, got %s", blockKeyBytes)
		}
	}

	// SecureCookie
	s := securecookie.New(hashKeyBytes, blockKeyBytes)

	s.MaxAge(0)

	return &Firewall{
		FirewallConfig: config,
		OauthConfig:    oauthConfig,
		ConsulClient:   consulClient,
		RateLimit:      rate.NewLimiter(rate.Every(250*time.Millisecond), 500),
		HashKey:        hashKeyBytes,
		BlockKey:       blockKeyBytes,
		AddIPSecret:    []byte(config.AddIPSecret),
		SecureCookie:   s,
	}, nil
}

// A CookiePayload represents the value of a secure cookie
type CookiePayload struct {
	Admin bool   `json:"admin"`
	Token string `json:"token"`
}

// LogAdminPass logs an administrative password
func (f *Firewall) LogAdminPass() error {
	for i := 1; i < 6; i++ {
		// Payload
		payload := &CookiePayload{
			Admin: true,
			Token: fmt.Sprintf("admin%d", i),
		}

		// Encode cookie
		encoded, err := f.SecureCookie.Encode(CookieName, payload)
		if err != nil {
			return err
		}

		log.Printf("Admin token %d: %s\n", i, encoded)
	}

	return nil
}

// Run the firewall
func (f *Firewall) Run() error {
	l := hclog.New(&hclog.LoggerOptions{
		Name:  "webapp",
		Level: hclog.LevelFromString("INFO"),
	})

	c := &framework.Config{
		Logger:       l,
		TemplatesBox: rice.MustFindBox("templates"),
	}
	e := framework.New(c)

	domains := []string{fmt.Sprintf("https://%s", f.Domain)}

	for _, s := range f.Subdomains {
		domains = append(domains, fmt.Sprintf("https://%s.%s", s, f.Domain))
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     domains,
		AllowCredentials: true,
	}))

	assetHandler := http.FileServer(rice.MustFindBox("static").HTTPBox())

	e.GET("/", f.handleRoot)
	e.GET("/callback", f.handleOauthCallback)
	e.GET("/add", f.handleAdd)
	e.GET("/list", f.handleList)
	e.GET("/ipset", f.handleIpset)
	e.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	return e.Start(":80")
}

func (f *Firewall) checkAuthenticated(c echo.Context) (*UserInfo, *CookiePayload) {
	var payload *CookiePayload

	// Read cookie
	if cookie, err := c.Cookie(CookieName); err == nil {
		payload = &CookiePayload{}

		if err = f.SecureCookie.Decode(CookieName, cookie.Value, payload); err != nil {
			log.Printf("Decoding cookie resulted in error: %s", err)

			payload = nil
		}
	} else {
		log.Printf("Retrieving cookie resulted in error: %s", err)
	}

	// Read authorization
	reqToken := c.Request().Header.Get("Authorization")
	if reqToken != "" {
		payload = &CookiePayload{}

		if err := f.SecureCookie.Decode(CookieName, reqToken, payload); err != nil {
			log.Printf("Decoding authorization header resulted in error: %s", err)

			payload = nil
		}

		// Old style
		value := make(map[string]string)
		if err := f.SecureCookie.Decode(CookieName, reqToken, &value); err == nil {
			if value["admin"] == "true" {
				log.Printf("Using legacy token")

				payload = &CookiePayload{
					Admin: true,
				}
			}
		}
	}

	// Check whether token is valid
	if payload != nil && !payload.Admin && payload.Token != "" {
		info, err := f.getUserInfo(payload.Token)

		if err == nil {
			return info, payload
		}

		log.Printf("Fetching user info resulted in error: %s", err)
	}

	return nil, payload
}
