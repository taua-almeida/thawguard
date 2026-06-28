package webhook

import "testing"

func TestVerifyHMACSHA256(t *testing.T) {
	body := []byte(`{"action":"opened"}`)
	secret := "test-secret"
	signature := "sha256=6e939b5b3d3e8eba83ff81dde0030a8f2190d965e8bec7a17842863e979c4d7d"

	if !VerifyHMACSHA256(secret, body, signature) {
		t.Fatal("expected valid signature")
	}
	if VerifyHMACSHA256(secret, body, "sha256=deadbeef") {
		t.Fatal("expected invalid signature to fail")
	}
}
