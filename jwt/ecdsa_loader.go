package jwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func LoadEcdsaPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("No correct PEM data")
	}

	priKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priKey, ok := priKeyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("Incorrect Private Key type")
	}

	return priKey, nil
}

func LoadEcdsaPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("No correct PEM data")
	}

	pubKeyAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := pubKeyAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Incorrect Public Key type")
	}

	return pubKey, nil
}
