package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
)

const AlgHs256 = "HS256"
const AlgHs384 = "HS384"
const AlgEs256 = "ES256"
const AlgEs384 = "ES384"
const TypeJwt = "JWT"

type Signer interface {
	Sign(refVal []byte) []byte
}

type Verifier interface {
	Verify(refVal []byte, signature []byte) bool
}

type JwtSigner struct {
	Alg    string
	Signer Signer
}

type JwtVerifier struct {
	Alg      string
	Verifier Verifier
}

type SignerGen func([]byte) *JwtSigner
type VerifierGen func([]byte) *JwtSigner

func NewJwtSigner(a string, s Signer) *JwtSigner {
	return &JwtSigner{
		Alg:    a,
		Signer: s,
	}
}

func NewJwtVerifier(a string, v Verifier) *JwtVerifier {
	return &JwtVerifier{
		Alg:      a,
		Verifier: v,
	}
}

func (j *JwtSigner) CreateJwt(claims *SimpleClaims) (string, error) {
	headerData, err := json.Marshal(getStdHeader(j.Alg))
	if err != nil {
		return "", err
	}

	header := base64.RawURLEncoding.EncodeToString(headerData)

	claimsData, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	tokenClaims := base64.RawURLEncoding.EncodeToString(claimsData)
	refVal := fmt.Sprintf("%s.%s", header, tokenClaims)

	sig := j.Signer.Sign([]byte(refVal))
	signature := base64.RawURLEncoding.EncodeToString(sig)

	return fmt.Sprintf("%s.%s.%s", header, tokenClaims, signature), nil
}

func parseJsonIntoMap(data []byte) (map[string]string, error) {
	res := map[string]string{}

	var headerResult map[string]any
	json.Unmarshal(data, &headerResult)

	for i, j := range headerResult {
		if val, ok := j.(float64); ok {
			res[i] = fmt.Sprintf("%d", uint64(val))
			continue
		}
		res[i] = fmt.Sprintf("%v", j)
	}

	return res, nil
}

func verifyHeader(parsedHeader map[string]string, refAlg string) error {
	alg, ok := parsedHeader["alg"]
	if !ok {
		return fmt.Errorf("invalid JWT header contents")
	}

	if alg != refAlg {
		return fmt.Errorf("invalid JWT header contents")
	}

	typ, ok := parsedHeader["typ"]
	if !ok {
		return fmt.Errorf("invalid JWT header contents")
	}

	if typ != TypeJwt {
		return fmt.Errorf("invalid JWT header contents")
	}

	return nil
}

func (j *JwtVerifier) VerifyJwt(jwt string) (map[string]string, error) {
	re := regexp.MustCompile(`^([0-9A-za-z_-]+)\.([0-9A-za-z_-]+)\.([0-9A-za-z_-]+)$`)

	matches := re.FindSubmatch([]byte(jwt))
	if matches == nil {
		return nil, fmt.Errorf("invalid JWT structure")
	}

	header, err := base64.RawURLEncoding.DecodeString(string(matches[1]))
	if err != nil {
		return nil, err
	}

	parsedHeader, err := parseJsonIntoMap(header)
	if err != nil {
		return nil, err
	}

	err = verifyHeader(parsedHeader, j.Alg)
	if err != nil {
		return nil, err
	}

	claims, err := base64.RawURLEncoding.DecodeString(string(matches[2]))
	if err != nil {
		return nil, err
	}

	parsedClaims, err := parseJsonIntoMap(claims)
	if err != nil {
		return nil, err
	}

	signature, err := base64.RawURLEncoding.DecodeString(string(matches[3]))
	if err != nil {
		return nil, err
	}

	refVal := fmt.Sprintf("%s.%s", matches[1], matches[2])

	ok := j.Verifier.Verify([]byte(refVal), signature)
	if !ok {
		return nil, fmt.Errorf("Signature verification failure")
	}

	return parsedClaims, nil
}
