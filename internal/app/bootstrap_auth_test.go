package app

import (
	"testing"

	"github.com/taua-almeida/thawguard/internal/config"
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

func TestValidateStatusPublisherConfigRequiresLiveOptIn(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode}, mode, true); err == nil {
		t.Fatal("expected forgejo status mode to require explicit live opt-in")
	}
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: "disabled"}, mode, true); err == nil {
		t.Fatal("expected invalid live opt-in value to be rejected")
	}
}

func TestValidateStatusPublisherConfigRequiresSecretKeyForLiveMode(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: "enabled"}, mode, false); err == nil {
		t.Fatal("expected forgejo status mode to require secret key")
	}
}

func TestValidateStatusPublisherConfigAcceptsExplicitLiveMode(t *testing.T) {
	mode := statuspublication.DeliveryModeForgejoStatus
	if err := validateStatusPublisherConfig(config.Config{StatusPublisherMode: mode, LiveStatusPosting: " ENABLED "}, mode, true); err != nil {
		t.Fatalf("expected explicit live mode to pass guardrails: %v", err)
	}
}

func TestValidateStatusPublisherConfigAllowsDryRun(t *testing.T) {
	if err := validateStatusPublisherConfig(config.Config{}, statuspublication.AttemptModeDryRun, false); err != nil {
		t.Fatalf("expected dry-run mode without live guardrails to pass: %v", err)
	}
}
