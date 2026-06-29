package setupcheck

import (
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestEvaluateReportsSetupFailures(t *testing.T) {
	results := Evaluate(Report{CanPostStatuses: true})
	if len(results) != 3 {
		t.Fatalf("expected 3 setup checks, got %d", len(results))
	}
	if results[0].Status != StatusOK {
		t.Fatalf("expected status-posting check to pass, got %s", results[0].Status)
	}
	if results[1].Status != StatusFailed {
		t.Fatalf("expected required-context check to fail, got %s", results[1].Status)
	}
	if !strings.Contains(results[1].Remediation, domain.RequiredStatusContext) {
		t.Fatalf("expected remediation to mention required context, got %q", results[1].Remediation)
	}
}

func TestManualSetupStepsMentionRequiredContext(t *testing.T) {
	steps := strings.Join(ManualSetupSteps(), "\n")
	if !strings.Contains(steps, domain.RequiredStatusContext) {
		t.Fatalf("expected manual setup steps to mention %s", domain.RequiredStatusContext)
	}
}
