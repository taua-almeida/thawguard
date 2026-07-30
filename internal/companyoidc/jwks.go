package companyoidc

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math"
	"math/big"
)

const (
	maxJWKSKeys               = 100
	maxJWKKeyIDBytes          = 128
	maxRSAModulusEncodedSize  = 1366
	maxRSAExponentEncodedSize = 6
	minRSAModulusBits         = 2048
	maxRSAModulusBits         = 8192
)

var errInvalidJWKS = errors.New("invalid JWKS")

type trustedJWKS struct {
	keys map[string]*rsa.PublicKey
}

func parseJWKS(body []byte) (trustedJWKS, error) {
	if len(body) > setupCheckMaxBodySize {
		return trustedJWKS{}, errInvalidJWKS
	}

	object, ok := decodeJSONObject(body)
	if !ok {
		return trustedJWKS{}, errInvalidJWKS
	}
	rawKeys, ok := object["keys"]
	if !ok {
		return trustedJWKS{}, errInvalidJWKS
	}
	var keys []jsonRawMessage
	if err := strictJSONUnmarshalWithRootContainerLimit(rawKeys, &keys, maxJWKSKeys); err != nil ||
		len(keys) == 0 || len(keys) > maxJWKSKeys {
		return trustedJWKS{}, errInvalidJWKS
	}

	trusted := trustedJWKS{keys: make(map[string]*rsa.PublicKey)}
	for _, rawKey := range keys {
		keyObject, ok := decodeJSONObject(rawKey)
		if !ok {
			return trustedJWKS{}, errInvalidJWKS
		}
		kid, publicKey, eligible := eligibleRSAKey(keyObject)
		if !eligible {
			continue
		}
		if _, exists := trusted.keys[kid]; exists {
			return trustedJWKS{}, errInvalidJWKS
		}
		trusted.keys[kid] = publicKey
	}
	return trusted, nil
}

func eligibleRSAKey(key map[string]jsonRawMessage) (string, *rsa.PublicKey, bool) {
	kty, ok := requiredJSONString(key, "kty")
	if !ok || kty != "RSA" {
		return "", nil, false
	}
	kid, ok := requiredJSONString(key, "kid")
	if !ok || len(kid) == 0 || len(kid) > maxJWKKeyIDBytes {
		return "", nil, false
	}
	modulusText, ok := requiredJSONString(key, "n")
	if !ok || len(modulusText) > maxRSAModulusEncodedSize {
		return "", nil, false
	}
	modulusBytes, ok := canonicalBase64URLUInt(modulusText)
	if !ok {
		return "", nil, false
	}
	modulus := new(big.Int).SetBytes(modulusBytes)
	if modulus.BitLen() < minRSAModulusBits || modulus.BitLen() > maxRSAModulusBits || modulus.Bit(0) == 0 {
		return "", nil, false
	}

	exponentText, ok := requiredJSONString(key, "e")
	if !ok || len(exponentText) > maxRSAExponentEncodedSize {
		return "", nil, false
	}
	exponentBytes, ok := canonicalBase64URLUInt(exponentText)
	if !ok || len(exponentBytes) > 4 {
		return "", nil, false
	}
	exponent := new(big.Int).SetBytes(exponentBytes).Uint64()
	if exponent < 3 || exponent > math.MaxInt32 || exponent&1 == 0 {
		return "", nil, false
	}

	if value, present := key["alg"]; present && !exactJSONString(value, "RS256") {
		return "", nil, false
	}
	if value, present := key["use"]; present && !exactJSONString(value, "sig") {
		return "", nil, false
	}
	if value, present := key["key_ops"]; present {
		var operations []string
		if err := strictJSONUnmarshal(value, &operations); err != nil ||
			len(operations) != 1 || operations[0] != "verify" {
			return "", nil, false
		}
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, present := key[privateField]; present {
			return "", nil, false
		}
	}

	return kid, &rsa.PublicKey{N: modulus, E: int(exponent)}, true
}

func canonicalBase64URLUInt(value string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || decoded[0] == 0 {
		return nil, false
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}
