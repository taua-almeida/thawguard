package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
)

func TestAESGCMStoreEncryptsAndDecrypts(t *testing.T) {
	store := newTestAESGCMStore(t)
	ctx := context.Background()
	plaintext := []byte("example-webhook-secret")

	ciphertext, err := store.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || bytes.Contains(ciphertext, plaintext) {
		t.Fatalf("expected ciphertext not to contain plaintext, got %q", ciphertext)
	}

	decrypted, err := store.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected decrypted plaintext %q, got %q", plaintext, decrypted)
	}
}

func TestAESGCMStoreUsesDistinctNonces(t *testing.T) {
	store := newTestAESGCMStore(t)
	ctx := context.Background()
	plaintext := []byte("example-webhook-secret")

	first, err := store.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("expected repeated encryptions to produce distinct ciphertexts")
	}
}

func TestAESGCMStoreRejectsInvalidKeyAndTamperedCiphertext(t *testing.T) {
	if _, err := NewAESGCMStore([]byte("short")); err == nil {
		t.Fatal("expected invalid key length error")
	}
	if _, err := DecodeBase64Key(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected invalid decoded key length error")
	}

	store := newTestAESGCMStore(t)
	ciphertext, err := store.Encrypt(context.Background(), []byte("example-webhook-secret"))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := store.Decrypt(context.Background(), ciphertext); err == nil {
		t.Fatal("expected tampered ciphertext to fail decryption")
	}
}

func TestNewAESGCMStoreFromBase64(t *testing.T) {
	key := bytes.Repeat([]byte{7}, aesGCMKeySize)
	encoded := base64.StdEncoding.EncodeToString(key)
	store, err := NewAESGCMStoreFromBase64(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		t.Fatal("expected store")
	}
}

func newTestAESGCMStore(t *testing.T) *AESGCMStore {
	t.Helper()
	store, err := NewAESGCMStore(bytes.Repeat([]byte{1}, aesGCMKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
