package jwt

import (
	"fmt"
	"strconv"
	"time"
)

type hs256Header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

func getStdHeader(alg string) *hs256Header {
	return &hs256Header{
		Algorithm: alg,
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
