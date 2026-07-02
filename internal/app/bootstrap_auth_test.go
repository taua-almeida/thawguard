package app

import (
	"testing"

	"github.com/taua-almeida/thawguard/internal/statuspublication"
)

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

func TestStatusPublisherMode(t *testing.T) {
	for _, raw := range []string{"", "dry_run", " DRY_RUN "} {
		mode, err := statusPublisherMode(raw)
		if err != nil {
			t.Fatalf("expected %q to be accepted: %v", raw, err)
		}
		if mode != statuspublication.AttemptModeDryRun {
			t.Fatalf("expected dry_run mode for %q, got %q", raw, mode)
		}
	}
	mode, err := statusPublisherMode("forgejo_status")
	if err != nil {
		t.Fatal(err)
	}
	if mode != statuspublication.DeliveryModeForgejoStatus {
		t.Fatalf("expected forgejo status mode, got %q", mode)
	}
	if _, err := statusPublisherMode("live"); err == nil {
		t.Fatal("expected invalid publisher mode error")
	}
}
