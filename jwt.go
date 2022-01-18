package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	echo "github.com/labstack/echo/v4"
)

// ErrInvalidToken error
var ErrInvalidToken = fmt.Errorf("invalid token")

// OauthSessionClaim represents a jwt token to prove an authentication request is made
type OauthSessionClaim struct {
	jwt.StandardClaims
}

// NewOauthSessionToken generates a new jwt token to validate an oauth login
func (f *Firewall) NewOauthSessionToken() (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	// Create the JWT claims, which includes the username and expiry time
	claims := &OauthSessionClaim{
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(f.BlockKey)
}

// ParseOauthSessionToken parses an oauth session jwt token
func (f *Firewall) ParseOauthSessionToken(tknStr string) (*OauthSessionClaim, error) {
	claims := &OauthSessionClaim{}

	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return f.BlockKey, nil
	})
	if err != nil {
		return nil, err
	}
	if !tkn.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// A JwtErrorResponse is returned when a jwt error occurred
type JwtErrorResponse struct {
	Message string `json:"message"`
}

// JwtError handles a jwt error nicely
func JwtError(c echo.Context, err error) error {
	response := &JwtErrorResponse{
		Message: err.Error(),
	}

	if err == jwt.ErrSignatureInvalid || err == ErrInvalidToken {
		return c.JSON(http.StatusUnauthorized, response)
	}
	return c.JSON(http.StatusBadRequest, response)
}
