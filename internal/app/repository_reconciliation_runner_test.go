package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
)

func TestRepositoryReconciliationRunnerProcessesClaimsIndependently(t *testing.T) {
	jobStore := &fakeReconciliationJobStore{claims: []jobs.Job{
		{ID: 1, RepositoryID: 11, Generation: 1, Attempts: 1},
		{ID: 2, RepositoryID: 22, Generation: 1, Attempts: 2},
	}}
	processor := &fakeReconciliationJobProcessor{errors: map[int64]error{1: errors.New("secret-token raw forge body")}}
	var logs bytes.Buffer
	runner := newRepositoryReconciliationRunner(jobStore, processor, slog.New(slog.NewTextHandler(&logs, nil)))

	if err := runner.RunDue(context.Background()); err == nil {
		t.Fatal("expected joined failure")
	}
	if len(processor.processed) != 2 || processor.processed[0] != 1 || processor.processed[1] != 2 {
		t.Fatalf("expected second repository after first failure, got %+v", processor.processed)
	}
	logged := logs.String()
	if strings.Contains(logged, "secret-token") || strings.Contains(logged, "raw forge body") {
		t.Fatalf("sensitive cause reached logs: %q", logged)
	}
	for _, want := range []string{"repository_id=11", "job_id=1", "attempt=1", domain.EnforcementFailurePublication} {
		if !strings.Contains(logged, want) {
			t.Fatalf("expected sanitized log field %q in %q", want, logged)
		}
	}
}

func TestRepositoryReconciliationRunnerStartsImmediatelyAndStopsOnCancellation(t *testing.T) {
	jobStore := &fakeReconciliationJobStore{claims: []jobs.Job{{ID: 9, RepositoryID: 7, Generation: 1, Attempts: 1}}}
	ctx, cancel := context.WithCancel(context.Background())
	processor := &fakeReconciliationJobProcessor{onProcess: cancel}
	runner := newRepositoryReconciliationRunner(jobStore, processor, nil)

	runner.Start(ctx)
	if jobStore.claimCalls != 1 || len(processor.processed) != 1 {
		t.Fatalf("expected one immediate startup pass, claims=%d processed=%+v", jobStore.claimCalls, processor.processed)
	}
}

func TestRepositoryReconciliationRunnerCancelledContextDoesNotClaim(t *testing.T) {
	jobStore := &fakeReconciliationJobStore{claims: []jobs.Job{{ID: 9, RepositoryID: 7, Generation: 1, Attempts: 1}}}
	processor := &fakeReconciliationJobProcessor{}
	runner := newRepositoryReconciliationRunner(jobStore, processor, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	runner.Start(ctx)
	if jobStore.claimCalls != 0 || len(processor.processed) != 0 {
		t.Fatalf("expected cancellation before claiming work, claims=%d processed=%+v", jobStore.claimCalls, processor.processed)
	}
}

type fakeReconciliationJobStore struct {
	claims     []jobs.Job
	claimCalls int
	err        error
}

func (s *fakeReconciliationJobStore) ClaimDue(ctx context.Context, limit int) ([]jobs.Job, error) {
	s.claimCalls++
	return s.claims, s.err
}

type fakeReconciliationJobProcessor struct {
	processed []int64
	errors    map[int64]error
	onProcess func()
}

func (p *fakeReconciliationJobProcessor) processReconciliationClaim(ctx context.Context, claim jobs.Job) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	p.processed = append(p.processed, claim.ID)
	if p.onProcess != nil {
		p.onProcess()
	}
	return domain.EnforcementFailurePublication, p.errors[claim.ID]
}
