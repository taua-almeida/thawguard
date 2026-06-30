package app

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
)

func TestSecretStoreFromConfig(t *testing.T) {
	store, err := secretStoreFromConfig(config.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if store != nil {
		t.Fatal("expected nil secret store without configured key")
	}

	encodedKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	store, err = secretStoreFromConfig(config.Config{SecretKey: encodedKey})
	if err != nil {
		t.Fatal(err)
	}
	if store == nil {
		t.Fatal("expected configured secret store")
	}

	if _, err := secretStoreFromConfig(config.Config{SecretKey: "not-base64"}); err == nil {
		t.Fatal("expected invalid secret key error")
	}
}
