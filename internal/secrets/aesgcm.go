package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	aesGCMKeySize = 32
	aesGCMVersion = byte(1)
)

type AESGCMStore struct {
	gcm cipher.AEAD
}

func NewAESGCMStore(key []byte) (*AESGCMStore, error) {
	if len(key) != aesGCMKeySize {
		return nil, fmt.Errorf("secret key must be %d bytes", aesGCMKeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM cipher: %w", err)
	}
	return &AESGCMStore{gcm: gcm}, nil
}

func NewAESGCMStoreFromBase64(keyText string) (*AESGCMStore, error) {
	key, err := DecodeBase64Key(keyText)
	if err != nil {
		return nil, err
	}
	return NewAESGCMStore(key)
}

func DecodeBase64Key(keyText string) ([]byte, error) {
	keyText = strings.TrimSpace(keyText)
	if keyText == "" {
		return nil, errors.New("secret key is required")
	}
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var decoded []byte
	for _, encoding := range encodings {
		candidate, err := encoding.DecodeString(keyText)
		if err == nil {
			decoded = candidate
			break
		}
	}
	if len(decoded) != aesGCMKeySize {
		return nil, fmt.Errorf("secret key must decode to %d bytes", aesGCMKeySize)
	}
	key := make([]byte, len(decoded))
	copy(key, decoded)
	return key, nil
}

func (s *AESGCMStore) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	if s == nil || s.gcm == nil {
		return nil, errors.New("AES-GCM secret store is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate AES-GCM nonce: %w", err)
	}
	ciphertext := make([]byte, 0, 1+len(nonce)+len(plaintext)+s.gcm.Overhead())
	ciphertext = append(ciphertext, aesGCMVersion)
	ciphertext = append(ciphertext, nonce...)
	ciphertext = s.gcm.Seal(ciphertext, nonce, plaintext, nil)
	return ciphertext, nil
}

func (s *AESGCMStore) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if s == nil || s.gcm == nil {
		return nil, errors.New("AES-GCM secret store is not configured")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ciphertext) < 1+s.gcm.NonceSize()+s.gcm.Overhead() {
		return nil, errors.New("ciphertext is too short")
	}
	if ciphertext[0] != aesGCMVersion {
		return nil, errors.New("ciphertext version is unsupported")
	}
	nonceStart := 1
	nonceEnd := nonceStart + s.gcm.NonceSize()
	nonce := ciphertext[nonceStart:nonceEnd]
	sealed := ciphertext[nonceEnd:]
	plaintext, err := s.gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, errors.New("decrypt secret ciphertext")
	}
	return plaintext, nil
}
