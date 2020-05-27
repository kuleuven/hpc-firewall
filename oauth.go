package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	echo "github.com/labstack/echo/v4"
	"golang.org/x/oauth2"
)

func (f *Firewall) handleOauthCallback(c echo.Context) error {
	var (
		token   string
		encoded string
		err     error
	)

	_, err = f.ParseOauthSessionToken(c.FormValue("state"))
	if err != nil {
		return JwtError(c, err)
	}

	// Retrieve oauth token
	token, err = f.getToken(c.FormValue("code"))
	if err != nil {
		return err
	}

	// Cookie payload
	payload := &CookiePayload{
		Token: token,
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

func (f *Firewall) getToken(code string) (string, error) {
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
