package tools

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

const AlgHs256 = "HS256"
const TypeJwt = "JWT"

type hs256Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

func getStdHeader() *hs256Header {
	return &hs256Header{
		Algorithm: AlgHs256,
		Type:      TypeJwt,
	}
}

type SimpleClaims struct {
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Subject  string `json:"sub"`
	Issuer   string `json:"iss"`
	Flags    uint64 `json:"flags"`
}

func MakeClaims(subject string, audience string, issuer string) *SimpleClaims {
	return &SimpleClaims{
		Audience: audience,
		IssuedAt: time.Now().UTC().Unix(),
		Subject:  subject,
		Issuer:   issuer,
		Flags:    0,
	}
}

func NewFromVerifiedClaims(parsedClaims map[string]string) (*SimpleClaims, error) {
	res := MakeClaims("", "", "")
	err := res.SetFromParsedClaims(parsedClaims)

	if err != nil {
		return nil, err
	}

	return res, nil
}

func (s *SimpleClaims) SetFlags(f uint64) {
	s.Flags = f
}

func (s *SimpleClaims) Print() {
	fmt.Printf("iss: %s\n", s.Issuer)
	fmt.Printf("aud: %s\n", s.Audience)
	fmt.Printf("sub: %s\n", s.Subject)
	fmt.Printf("iat: %d\n", s.IssuedAt)
	fmt.Printf("flags: %d\n", s.Flags)
}

func (s *SimpleClaims) SetFromParsedClaims(parsedClaims map[string]string) error {
	if val, ok := parsedClaims["iss"]; ok {
		s.Issuer = val
	}

	if val, ok := parsedClaims["aud"]; ok {
		s.Audience = val
	}

	if val, ok := parsedClaims["sub"]; ok {
		s.Subject = val
	}

	if val, ok := parsedClaims["flags"]; ok {
		newVal, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return err
		}

		s.Flags = newVal
	}

	if val, ok := parsedClaims["iat"]; ok {
		newVal, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}

		if newVal < 0 {
			return fmt.Errorf("time is negative")
		}

		s.IssuedAt = newVal
	}

	return nil
}

type Hs256Jwt struct {
	hmacSecret []byte
}

func NewHs256Jwt(k []byte) *Hs256Jwt {
	return &Hs256Jwt{
		hmacSecret: k,
	}
}

func (h *Hs256Jwt) CreateJwt(claims *SimpleClaims) (string, error) {
	headerData, err := json.Marshal(getStdHeader())
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

	mac := hmac.New(sha256.New, h.hmacSecret)
	mac.Write([]byte(refVal))
	hmac := mac.Sum(nil)

	signature := base64.RawURLEncoding.EncodeToString(hmac)

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

func verifyHeader(parsedHeader map[string]string) error {
	alg, ok := parsedHeader["alg"]
	if !ok {
		return fmt.Errorf("invalid JWT header contents")
	}

	if alg != AlgHs256 {
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

func (h *Hs256Jwt) VerifyJwt(jwt string) (map[string]string, error) {
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

	err = verifyHeader(parsedHeader)
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

	mac := hmac.New(sha256.New, h.hmacSecret)
	mac.Write([]byte(refVal))
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(signature, expectedMAC) {
		return nil, fmt.Errorf("HMAC verification failure")
	}

	return parsedClaims, nil
}
