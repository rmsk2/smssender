package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

type HsHmac struct {
	hmacSecret []byte
	hashGen    HashGenType
}

func NewHsHmac(k []byte, gen HashGenType) *HsHmac {
	return &HsHmac{
		hmacSecret: k,
		hashGen:    gen,
	}
}

func (h *HsHmac) Sign(refVal []byte) []byte {
	mac := hmac.New(h.hashGen, h.hmacSecret)
	mac.Write([]byte(refVal))
	hmac := mac.Sum(nil)

	return hmac
}

func (h *HsHmac) Verify(refVal []byte, signature []byte) bool {
	mac := hmac.New(h.hashGen, h.hmacSecret)
	mac.Write([]byte(refVal))
	expectedMAC := mac.Sum(nil)

	return hmac.Equal(signature, expectedMAC)
}

func NewHs256JwtSigner(secret []byte) *JwtSigner {
	t := NewHsHmac(secret, sha256.New)
	return NewJwtSigner(AlgHs256, t)
}

func NewHs256JwtVerifier(secret []byte) *JwtVerifier {
	t := NewHsHmac(secret, sha256.New)
	return NewJwtVerifier(AlgHs256, t)
}

func NewHs384JwtSigner(secret []byte) *JwtSigner {
	t := NewHsHmac(secret, sha512.New384)
	return NewJwtSigner(AlgHs384, t)
}

func NewHs384JwtVerifier(secret []byte) *JwtVerifier {
	t := NewHsHmac(secret, sha512.New384)
	return NewJwtVerifier(AlgHs384, t)
}
