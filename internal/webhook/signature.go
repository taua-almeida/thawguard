package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const SignatureSHA256Prefix = "sha256="

func VerifyHMACSHA256(secret string, body []byte, signatureHeader string) bool {
	if secret == "" || signatureHeader == "" {
		return false
	}

	signature := strings.TrimSpace(signatureHeader)
	signature = strings.TrimPrefix(signature, SignatureSHA256Prefix)
	received, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return hmac.Equal(received, expected)
}
