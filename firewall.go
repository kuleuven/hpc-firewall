//go:generate rice embed-go
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"gitea.icts.kuleuven.be/ceif-lnx/go/webapp/framework"
	"gitea.icts.kuleuven.be/hpc/hpc-firewall/consulkvipset"
	rice "github.com/GeertJohan/go.rice"
	"github.com/gorilla/securecookie"
	consul "github.com/hashicorp/consul/api"
	"github.com/hashicorp/go-hclog"
	echo "github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/oauth2"
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
	Domain            string
	Subdomains        []string
}

// A Firewall object represents a firewall service
type Firewall struct {
	FirewallConfig
	OauthConfig  *oauth2.Config
	ConsulClient *consul.Client
	HashKey      []byte
	BlockKey     []byte
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

	return &Firewall{
		FirewallConfig: config,
		OauthConfig:    oauthConfig,
		ConsulClient:   consulClient,
		HashKey:        hashKeyBytes,
		BlockKey:       blockKeyBytes,
		SecureCookie:   s,
	}, nil
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
		domains = append(domains, fmt.Sprintf("https://%s.%s/endpoint", s, f.Domain))
	}

	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     domains,
		AllowCredentials: true,
	}))

	assetHandler := http.FileServer(rice.MustFindBox("static").HTTPBox())

	e.GET("/", f.handleRoot)
	e.GET("/callback", f.handleOauthCallback)
	e.GET("/endpoint", f.handleEndpoint)
	e.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", assetHandler)))

	return e.Start(":80")
}

func (f *Firewall) handleRoot(c echo.Context) error {
	var token string

	// Read cookie
	if cookie, err := c.Cookie(CookieName); err == nil {
		value := make(map[string]string)
		if err = f.SecureCookie.Decode(CookieName, cookie.Value, &value); err == nil {
			token = value["token"]
		} else {
			log.Printf("Decoding cookie resulted in error: %s", err)
		}
	} else {
		log.Printf("Retrieving cookie resulted in error: %s", err)
	}

	// Check whether token is valid
	if token != "" {
		info, err := f.getUserInfo(token)

		if err == nil {
			return f.handleRootAuthenticated(c, info)
		}

		log.Printf("Fetching user info resulted in error: %s", err)
	}

	// Redirect if not valid
	stateString, err := GenerateState()
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
}

func (f *Firewall) handleRootAuthenticated(c echo.Context, info *UserInfo) error {
	endpoints := []string{}
	for _, s := range f.Subdomains {
		endpoints = append(endpoints, fmt.Sprintf("https://%s.%s/endpoint", s, f.Domain))
	}

	payload := RootPayload{
		ID:        info.ID,
		Endpoints: endpoints,
	}
	return c.Render(http.StatusOK, "root", payload)
}

// An EndpointResponse serves as structure for endpoint responses
type EndpointResponse struct {
	NeedsRefresh bool   `json:"needs_refresh"`
	Message      string `json:"message"`
	IP           string `json:"ip"`
}

func (f *Firewall) handleEndpoint(c echo.Context) error {
	var token string

	// Read cookie
	if cookie, err := c.Cookie(CookieName); err == nil {
		value := make(map[string]string)
		if err = f.SecureCookie.Decode(CookieName, cookie.Value, &value); err == nil {
			token = value["token"]
		}
	}

	// Check whether token is valid
	if token != "" {
		info, err := f.getUserInfo(token)

		if err == nil {
			return f.handleEndpointAuthenticated(c, info)
		}
	}

	// Redirect if not valid
	r := &EndpointResponse{
		NeedsRefresh: true,
		Message:      "Not authenticated, please refresh the page",
	}

	return c.JSON(http.StatusOK, r)
}

func (f *Firewall) handleEndpointAuthenticated(c echo.Context, info *UserInfo) error {
	var (
		path = f.ConsulPath + "/" + info.ID
		IP   = getFFIP(c.Request().Header.Get("X-LB-Forwarded-For"))
	)

	t, err := consulkvipset.AddIpsetRecord(f.ConsulClient, path, IP)
	if err != nil {
		return fmt.Errorf("could not add ip to consul kv store: %s", err)
	}

	// Return response
	r := &EndpointResponse{
		IP:      IP,
		Message: fmt.Sprintf("IP is granted access since %s [valid until %s]", t.Since.Format("2006-01-02 15:04:05"), t.Expiration.Format("15:04:05")),
	}

	return c.JSON(http.StatusOK, r)
}

func (f *Firewall) handleOauthCallback(c echo.Context) error {
	var (
		token   string
		encoded string
		err     error
	)

	// Retrieve oauth token
	token, err = f.getToken(c.FormValue("state"), c.FormValue("code"))
	if err != nil {
		return err
	}

	// Cookie payload
	payload := map[string]string{
		"token": token,
	}

	// Encode cookie
	encoded, err = f.SecureCookie.Encode(CookieName, payload)
	if err != nil {
		return err
	}

	// Set cookie
	cookie := &http.Cookie{
		Name:     CookieName,
		Value:    encoded,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		Domain:   f.Domain,
	}
	c.SetCookie(cookie)

	// Redirect to main page
	return c.Redirect(http.StatusTemporaryRedirect, "/")
}

func (f *Firewall) getToken(state string, code string) (string, error) {
	err := VerifyState(state)
	if err != nil {
		return "", fmt.Errorf("invalid oauth state: %s", err.Error())
	}

	token, err := f.OauthConfig.Exchange(oauth2.NoContext, code)
	if err != nil {
		return "", fmt.Errorf("code exchange failed: %s", err.Error())
	}

	return token.AccessToken, nil
}

// UserInfo returned by oauth introspect url
type UserInfo struct {
	FirstName string `json:"first_name"`
	Email     string `json:"email"`
	ID        string `json:"id"`
}

func (f *Firewall) getUserInfo(token string) (*UserInfo, error) {
	var bearer = "Bearer " + token

	req, err := http.NewRequest("GET", OauthIntrospectURL, nil)

	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status: %s", response.Status)
	}

	defer response.Body.Close()
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %s", err.Error())
	}

	var u UserInfo

	err = json.Unmarshal(contents, &u)
	if err != nil {
		return nil, fmt.Errorf("failed parsing response body: %s", err.Error())
	}

	return &u, nil
}
