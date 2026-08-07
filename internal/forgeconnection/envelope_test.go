package forgeconnection

import (
	"bytes"
	"testing"
)

func TestServicePATEnvelopeRoundTrip(t *testing.T) {
	envelope := wrapServicePAT("fixture-pat-value")
	want := append([]byte(servicePATEnvelopeHeader), 0)
	want = append(want, "fixture-pat-value"...)
	if !bytes.Equal(envelope, want) {
		t.Fatalf("envelope = %q", envelope)
	}
	pat, err := unwrapServicePAT(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if string(pat) != "fixture-pat-value" {
		t.Fatalf("unwrapped PAT = %q", pat)
	}
	// The mutable envelope buffer is cleared on return.
	for i, value := range envelope {
		if value != 0 {
			t.Fatalf("envelope byte %d was not cleared", i)
		}
	}
}

func TestServicePATEnvelopeRejectsWrongShape(t *testing.T) {
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{name: "empty", plaintext: nil},
		{name: "header only", plaintext: append([]byte(servicePATEnvelopeHeader), 0)},
		{name: "missing NUL", plaintext: []byte(servicePATEnvelopeHeader + "-pat")},
		{name: "wrong purpose", plaintext: append([]byte("thawguard/other/purpose/v1\x00"), "pat"...)},
		{name: "wrong version", plaintext: append([]byte("thawguard/forgeconnection/forgejo/service-pat/v2\x00"), "pat"...)},
		{name: "truncated header", plaintext: []byte("thawguard/forgeconnection\x00pat")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buffer := bytes.Clone(tc.plaintext)
			if _, err := unwrapServicePAT(buffer); err == nil {
				t.Fatal("expected envelope rejection")
			}
			for i, value := range buffer {
				if value != 0 {
					t.Fatalf("rejected buffer byte %d was not cleared", i)
				}
			}
		})
	}
}
