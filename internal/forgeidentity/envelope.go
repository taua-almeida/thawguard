package forgeidentity

import (
	"bytes"
	"errors"
)

// Purpose envelopes version each encrypted plaintext so ciphertext produced
// for any other purpose can never decrypt into a usable value here, and
// vice versa. The headers are private to this package.
const (
	oauthClientSecretEnvelopeHeader = "thawguard/forgeidentity/forgejo/oauth-client-secret/v1"
	pkceVerifierEnvelopeHeader      = "thawguard/forgeidentity/forgejo/link-pkce-verifier/v1"
)

func wrapEnvelope(header, value string) []byte {
	envelope := make([]byte, 0, len(header)+1+len(value))
	envelope = append(envelope, header...)
	envelope = append(envelope, 0)
	envelope = append(envelope, value...)
	return envelope
}

// unwrapEnvelope requires the exact header and returns only the value bytes
// as a fresh copy. The mutable decrypted buffer is cleared on every path.
func unwrapEnvelope(header string, plaintext []byte) ([]byte, error) {
	defer clearBytes(plaintext)
	prefixLength := len(header) + 1
	if len(plaintext) <= prefixLength {
		return nil, errors.New("forge identity envelope is malformed")
	}
	if !bytes.Equal(plaintext[:len(header)], []byte(header)) || plaintext[len(header)] != 0 {
		return nil, errors.New("forge identity envelope has the wrong purpose or version")
	}
	value := make([]byte, len(plaintext)-prefixLength)
	copy(value, plaintext[prefixLength:])
	return value, nil
}

func clearBytes(buffer []byte) {
	for i := range buffer {
		buffer[i] = 0
	}
}
