package app

import "testing"

func TestValidateBootstrapLocalBindAcceptsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		if err := validateBootstrapLocalBind(addr); err != nil {
			t.Fatalf("expected %q to be accepted: %v", addr, err)
		}
	}
}

func TestValidateBootstrapLocalBindRejectsNetworkBinds(t *testing.T) {
	for _, addr := range []string{":8080", "0.0.0.0:8080", "192.0.2.1:8080"} {
		if err := validateBootstrapLocalBind(addr); err == nil {
			t.Fatalf("expected %q to be rejected", addr)
		}
	}
}
