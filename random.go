package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
)

var rsaKey *rsa.PrivateKey

func init() {
    var err error
	rsaKey, err = rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		fmt.Println(err.Error)
		os.Exit(1)
	}
}

func GenerateState() (string, error) {
	salt, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	signature, err := sign(salt)
	if err != nil {
		return "", err
	}

	return salt + signature, nil
}

func VerifyState(state string) error {
	if len(state) < 32 {
		return errors.New("state is too short")
	}

	salt := state[0:32]
	signature := state[32:]

	return verify(signature, salt)
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func generateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	bytes, err := generateRandomBytes(n)
	if err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = letters[b%byte(len(letters))]
	}
	return string(bytes), nil
}

func sign(plaintext string) (string, error) {
	rng := rand.Reader
	hashed := sha256.Sum256([]byte(plaintext))
	signature, err := rsa.SignPKCS1v15(rng, rsaKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func verify(signature string, plaintext string) error {
	sig, _ := base64.StdEncoding.DecodeString(signature)
	hashed := sha256.Sum256([]byte(plaintext))
	return rsa.VerifyPKCS1v15(&rsaKey.PublicKey, crypto.SHA256, hashed[:], sig)
}
