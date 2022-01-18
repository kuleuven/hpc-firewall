package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const HPCFirewall = "https://firewall.hpc.kuleuven.be/add"

// AddIPClaim represents a jwt token to request adding of an IP
type AddIPClaim struct {
	IP string
	jwt.StandardClaims
}

// Hello greets the user
func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello\n")
}

// Redirect incoming connections to the firewall application
func Redirect(w http.ResponseWriter, r *http.Request) {
	var ip = getFFIP(r.Header.Get("X-LB-Forwarded-For"))

	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		ip = host
	}

	token, err := NewAddIPToken(ip, []byte(os.Getenv("SECRET")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	redirect := fmt.Sprintf("%s?token=%s", HPCFirewall, token)

	http.Redirect(w, r, redirect, http.StatusFound)
}

// NewAddIPToken generates a new jwt token to add an ip
func NewAddIPToken(ip string, secret []byte) (string, error) {
	expirationTime := time.Now().Add(5 * time.Minute)

	claims := &AddIPClaim{
		IP: ip,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(secret)
}

func main() {
	http.HandleFunc("/", Hello)
	http.HandleFunc("/add", Redirect)

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func getFFIP(fwdAddress string) string {
	XFFip := strings.Split(fwdAddress, ",")
	ip := strings.TrimSpace(XFFip[len(XFFip)-1])

	ip = strings.ReplaceAll(ip, "[", "")
	ip = strings.ReplaceAll(ip, "]", "")

	i := net.ParseIP(ip)
	if i == nil {
		return ""
	}

	return i.String()
}
