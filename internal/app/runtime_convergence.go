package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
)

type enforcementConvergence interface {
	Claim(ctx context.Context, repositoryID int64) (jobs.Job, bool, error)
	Complete(ctx context.Context, claim jobs.Job) error
	Fail(ctx context.Context, claim jobs.Job, category string) error
}

type runtimeConvergenceService struct {
	jobs        *jobs.Store
	enforcement *enforcementService
}

func newRuntimeConvergenceService(jobStore *jobs.Store, enforcement *enforcementService) *runtimeConvergenceService {
	return &runtimeConvergenceService{jobs: jobStore, enforcement: enforcement}
}

func (s *runtimeConvergenceService) Claim(ctx context.Context, repositoryID int64) (jobs.Job, bool, error) {
	if s == nil || s.jobs == nil {
		return jobs.Job{}, false, errors.New("runtime convergence has no job store")
	}
	return s.jobs.ClaimRepository(ctx, repositoryID)
}

func (s *runtimeConvergenceService) Enqueue(ctx context.Context, repositoryID int64) error {
	if s == nil || s.jobs == nil {
		return errors.New("runtime convergence has no job store")
	}
	_, err := s.jobs.EnqueueReconciliation(ctx, repositoryID)
	return err
}

func (s *runtimeConvergenceService) Complete(ctx context.Context, claim jobs.Job) error {
	if s == nil || s.jobs == nil {
		return errors.New("runtime convergence has no job store")
	}
	_, err := s.jobs.CompleteClaim(ctx, claim)
	return err
}

func (s *runtimeConvergenceService) Fail(ctx context.Context, claim jobs.Job, category string) error {
	if s == nil || s.enforcement == nil || s.jobs == nil {
		return errors.New("runtime convergence is not configured")
	}
	actor := domain.Actor{Kind: domain.ActorKindSystem, Role: "runtime"}
	recordErr := s.enforcement.recordRuntimeFailure(ctx, claim.RepositoryID, category, actor, true)
	_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, category)
	return errors.Join(recordErr, rescheduleErr)
}

type runtimeConvergenceError struct {
	category string
	cause    error
}

func (e runtimeConvergenceError) Error() string { return e.cause.Error() }
func (e runtimeConvergenceError) Unwrap() error { return e.cause }

func convergenceError(category string, cause error) error {
	return runtimeConvergenceError{category: category, cause: cause}
}

func convergenceFailureCategory(err error) string {
	var convergenceErr runtimeConvergenceError
	if errors.As(err, &convergenceErr) && domain.ValidEnforcementFailureReason(convergenceErr.category) {
		return convergenceErr.category
	}
	return domain.EnforcementFailureRuntime
}

func failRuntimeConvergence(ctx context.Context, convergence enforcementConvergence, claim jobs.Job, err error) error {
	if convergence == nil {
		return err
	}
	if failureErr := convergence.Fail(ctx, claim, convergenceFailureCategory(err)); failureErr != nil {
		return errors.Join(err, fmt.Errorf("record runtime convergence failure: %w", failureErr))
	}
	return err
}
