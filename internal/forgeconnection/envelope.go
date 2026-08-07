package forgeconnection

import (
	"bytes"
	"errors"
)

// servicePATEnvelopeHeader versions the encrypted plaintext so a ciphertext
// produced for another purpose can never decrypt into a usable service PAT
// here, and vice versa. The header is private to this package.
const servicePATEnvelopeHeader = "thawguard/forgeconnection/forgejo/service-pat/v1"

// wrapServicePAT builds the versioned plaintext envelope: header, NUL, PAT.
func wrapServicePAT(pat string) []byte {
	envelope := make([]byte, 0, len(servicePATEnvelopeHeader)+1+len(pat))
	envelope = append(envelope, servicePATEnvelopeHeader...)
	envelope = append(envelope, 0)
	envelope = append(envelope, pat...)
	return envelope
}

// unwrapServicePAT requires the exact envelope header and returns only the
// PAT bytes as a fresh copy. The mutable decrypted buffer is cleared before
// returning on every path.
func unwrapServicePAT(plaintext []byte) ([]byte, error) {
	defer clearBytes(plaintext)
	prefixLength := len(servicePATEnvelopeHeader) + 1
	if len(plaintext) <= prefixLength {
		return nil, errors.New("service PAT envelope is malformed")
	}
	if !bytes.Equal(plaintext[:len(servicePATEnvelopeHeader)], []byte(servicePATEnvelopeHeader)) ||
		plaintext[len(servicePATEnvelopeHeader)] != 0 {
		return nil, errors.New("service PAT envelope has the wrong purpose or version")
	}
	pat := make([]byte, len(plaintext)-prefixLength)
	copy(pat, plaintext[prefixLength:])
	return pat, nil
}

func clearBytes(buffer []byte) {
	for i := range buffer {
		buffer[i] = 0
	}
}
