package setupcheck

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestServiceRunsInspectorAndPersistsResults(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(NewStore(database), stubInspector{report: Report{CanPostStatuses: true, RequiredContextPresent: true}})

	results, err := service.Run(ctx, domain.Repository{ID: repo.ID, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: repo.DefaultBranch})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	checks, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 3 {
		t.Fatalf("expected 3 persisted checks, got %d", len(checks))
	}
	if checks[0].Branch != repo.DefaultBranch {
		t.Fatalf("expected branch %q, got %q", repo.DefaultBranch, checks[0].Branch)
	}
	checksByName := make(map[string]Check)
	for _, check := range checks {
		checksByName[check.Result.Name] = check
	}
	for _, result := range results {
		check, ok := checksByName[result.Name]
		if !ok {
			t.Fatalf("missing persisted result %q", result.Name)
		}
		if check.Result.Status != result.Status || check.Result.Description != result.Description || check.Result.Remediation != result.Remediation {
			t.Fatalf("persisted result mismatch for %q: got %+v want %+v", result.Name, check.Result, result)
		}
	}
}

func TestServiceDoesNotPersistWhenInspectorFails(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	service := NewService(NewStore(database), stubInspector{err: errors.New("forge unavailable")})

	if _, err := service.Run(ctx, domain.Repository{ID: repo.ID, Owner: "taua-almeida", Name: "thawguard", DefaultBranch: repo.DefaultBranch}); err == nil {
		t.Fatal("expected inspector error")
	}

	checks, err := NewStore(database).ListByRepository(ctx, repo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(checks) != 0 {
		t.Fatalf("expected no persisted checks, got %d", len(checks))
	}
}

type stubInspector struct {
	report Report
	err    error
}

func (i stubInspector) Inspect(ctx context.Context, repo domain.Repository) (Report, error) {
	if i.err != nil {
		return Report{}, i.err
	}
	return i.report, nil
}
