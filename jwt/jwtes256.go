package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"math/big"
)

// Generate private key in PKCS8 format directly
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out private_key.pem
//
// or with a 384 bit ECDSA key
//
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out private_key.pem
//
// Extract the public key
// openssl pkey -in private_key.pem -pubout -out public_key.pem

type HashGenType func() hash.Hash

type EsSigner struct {
	privateKey *ecdsa.PrivateKey
	keyLen     int
	hashGen    HashGenType
}

type EsVerifier struct {
	publicKey *ecdsa.PublicKey
	keyLen    int
	hashGen   func() hash.Hash
}

func NewEsSignerVerified(raw []byte, gen HashGenType, keyLen int) (*EsSigner, error) {
	priKey, err := LoadEcdsaPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("Unable to load private key: %v", err)
	}

	return &EsSigner{
		privateKey: priKey,
		keyLen:     keyLen,
		hashGen:    gen,
	}, nil
}

func NewEs256Signer(raw []byte) *EsSigner {
	res, err := NewEsSignerVerified(raw, sha256.New, 32)
	if err != nil {
		panic(fmt.Errorf("Unable to parse private key: %v", err))
	}

	return res
}

func NewEs384Signer(raw []byte) *EsSigner {
	res, err := NewEsSignerVerified(raw, sha512.New384, 48)
	if err != nil {
		panic(fmt.Errorf("Unable to parse private key: %v", err))
	}

	return res
}

func (e *EsSigner) Sign(refVal []byte) []byte {
	h := e.hashGen()
	h.Write([]byte(refVal))
	hash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, e.privateKey, hash)
	if err != nil {
		panic(fmt.Errorf("Signature error: %v", err))
	}

	sig := r.FillBytes(make([]byte, e.keyLen))
	sig = append(sig, s.FillBytes(make([]byte, e.keyLen))...)

	return sig
}

func NewEsVerifierVerified(raw []byte, gen HashGenType, keyLen int) (*EsVerifier, error) {
	pubKey, err := LoadEcdsaPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("Unableto load public key: %v", err)
	}

	return &EsVerifier{
		publicKey: pubKey,
		hashGen:   gen,
		keyLen:    keyLen,
	}, nil
}

func NewEs256Verifier(raw []byte) *EsVerifier {
	res, err := NewEsVerifierVerified(raw, sha256.New, 32)
	if err != nil {
		panic(fmt.Errorf("Unable to parse public key: %v", err))
	}

	return res
}

func NewEs384Verifier(raw []byte) *EsVerifier {
	res, err := NewEsVerifierVerified(raw, sha512.New384, 48)
	if err != nil {
		panic(fmt.Errorf("Unable to parse public key: %v", err))
	}

	return res
}

func (e *EsVerifier) Verify(refVal []byte, signature []byte) bool {
	if len(signature) != (2 * e.keyLen) {
		return false
	}

	h := e.hashGen()
	h.Write([]byte(refVal))
	hash := h.Sum(nil)

	r := new(big.Int).SetBytes(signature[:e.keyLen])
	s := new(big.Int).SetBytes(signature[e.keyLen:])

	return ecdsa.Verify(e.publicKey, hash, r, s)
}

func NewEs256JwtSigner(raw []byte) *JwtSigner {
	t := NewEs256Signer(raw)
	return NewJwtSigner(AlgEs256, t)
}

func NewEs256JwtVerifier(raw []byte) *JwtVerifier {
	t := NewEs256Verifier(raw)
	return NewJwtVerifier(AlgEs256, t)
}

func NewEs384JwtSigner(raw []byte) *JwtSigner {
	t := NewEs384Signer(raw)
	return NewJwtSigner(AlgEs384, t)
}

func NewEs384JwtVerifier(raw []byte) *JwtVerifier {
	t := NewEs384Verifier(raw)
	return NewJwtVerifier(AlgEs384, t)
}
