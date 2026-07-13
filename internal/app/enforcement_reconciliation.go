package app

import (
	"context"
	"database/sql"
	"errors"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/repository"
)

// ReconcileEnforcement proves that current forge state and current Thawguard
// policy converge for an active repository. Failure marks enforcement
// unhealthy and leaves durable automatic recovery work. A successful manual
// reconciliation claims the same durable work used by the background runner.
func (s *enforcementService) ReconcileEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if err := s.configured(); err != nil {
		return domain.Repository{}, err
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return domain.Repository{}, err
	}
	if repo.EnforcementState != domain.EnforcementActive {
		return domain.Repository{}, repository.ValidationError{Message: "Manual reconciliation is only available while repository enforcement is active."}
	}
	if _, err := s.jobs.EnqueueReconciliation(ctx, repo.ID); err != nil {
		return domain.Repository{}, err
	}
	claim, claimed, err := s.jobs.ClaimRepository(ctx, repo.ID)
	if err != nil {
		return domain.Repository{}, err
	}
	if !claimed {
		return domain.Repository{}, repository.ValidationError{Message: "Enforcement reconciliation is already in progress."}
	}
	updated, category, err := s.reconcileEnforcementCore(ctx, repo, actor, true, claim)
	if err != nil {
		if category == "" {
			category = domain.EnforcementFailureRuntime
		}
		_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, category)
		return domain.Repository{}, errors.Join(err, rescheduleErr)
	}
	return updated, nil
}

func (s *enforcementService) reconcileEnforcementCore(ctx context.Context, repo domain.Repository, actor domain.Actor, preserveJobGeneration bool, claim jobs.Job) (domain.Repository, string, error) {
	if err := s.requireVerifiableReadiness(ctx, repo); err != nil {
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementReconcileFail, resultState: domain.EnforcementUnhealthy, reason: domain.EnforcementFailureReadinessChecks, persistFailure: true, preserveJobGeneration: preserveJobGeneration}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, domain.EnforcementFailureReadinessChecks, recordErr
		}
		return domain.Repository{}, domain.EnforcementFailureReadinessChecks, repository.ValidationError{Message: "Reconciliation stopped: readiness checks did not pass, so nothing was synchronized or published. The repository is marked unhealthy. " + err.Error()}
	}
	counts, reason, _, policyErr := s.reconcileCurrentPolicy(ctx, repo, nil, false, claim)
	if policyErr != nil {
		if reason == "" {
			return domain.Repository{}, domain.EnforcementFailureRuntime, policyErr
		}
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementReconcileFail, resultState: domain.EnforcementUnhealthy, reason: reason, counts: &counts, persistFailure: true, preserveJobGeneration: preserveJobGeneration}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, reason, recordErr
		}
		return domain.Repository{}, reason, repository.ValidationError{Message: reconcileFailureMessage(reason)}
	}
	updated, err := s.recordEnforcementSuccess(ctx, repo, actor, audit.ActionRepositoryEnforcementReconciled, map[string]string{
		"default_branch": repo.DefaultBranch,
	}, counts, claim)
	if category, ok := convergenceStateChangeCategory(err); ok {
		return domain.Repository{}, category, err
	}
	if err != nil {
		recordErr := s.recordRuntimeFailure(ctx, repo.ID, domain.EnforcementFailureRuntime, actor, preserveJobGeneration)
		return domain.Repository{}, domain.EnforcementFailureRuntime, errors.Join(err, recordErr)
	}
	return updated, "", err
}

// RecoverEnforcement preserves the admin-only immediate retry while using the
// same durable job, claim fence, backoff, and full recovery proof as automatic
// attempts. A valid worker lease is never bypassed.
func (s *enforcementService) RecoverEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if err := s.configured(); err != nil {
		return domain.Repository{}, err
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return domain.Repository{}, err
	}
	if repo.EnforcementState != domain.EnforcementUnhealthy {
		return domain.Repository{}, repository.ValidationError{Message: "Enforcement recovery is only available for an unhealthy repository."}
	}
	if _, err := s.jobs.MakeDueNow(ctx, repo.ID); err != nil {
		if errors.Is(err, jobs.ErrReconciliationInProgress) {
			return domain.Repository{}, repository.ValidationError{Message: "Enforcement recovery is already in progress."}
		}
		return domain.Repository{}, err
	}
	claim, claimed, err := s.jobs.ClaimRepository(ctx, repo.ID)
	if err != nil {
		return domain.Repository{}, err
	}
	if !claimed {
		return domain.Repository{}, repository.ValidationError{Message: "Enforcement recovery is already in progress."}
	}
	updated, category, recoveryErr := s.recoverEnforcementCore(ctx, repo, actor, true, claim)
	if recoveryErr != nil {
		if category == "" {
			category = domain.EnforcementFailureRuntime
		}
		_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, category)
		return domain.Repository{}, errors.Join(recoveryErr, rescheduleErr)
	}
	return updated, nil
}

func (s *enforcementService) recoverEnforcementCore(ctx context.Context, repo domain.Repository, actor domain.Actor, preserveJobGeneration bool, claim jobs.Job) (domain.Repository, string, error) {
	if err := s.requireVerifiableReadiness(ctx, repo); err != nil {
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementRecoverFail, resultState: domain.EnforcementUnhealthy, reason: domain.EnforcementFailureReadinessChecks, persistFailure: true, preserveJobGeneration: preserveJobGeneration}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, domain.EnforcementFailureReadinessChecks, recordErr
		}
		return domain.Repository{}, domain.EnforcementFailureReadinessChecks, repository.ValidationError{Message: "Recovery stopped: readiness checks did not pass, so no status was posted, synchronized, or published. The repository remains unhealthy. " + err.Error()}
	}
	head, postErr := s.controlledSetupPost(ctx, repo)
	if postErr != nil {
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementRecoverFail, resultState: domain.EnforcementUnhealthy, clearVerification: true, reason: domain.EnforcementFailureSetupStatusPost, persistFailure: true, preserveJobGeneration: preserveJobGeneration}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, domain.EnforcementFailureSetupStatusPost, recordErr
		}
		return domain.Repository{}, domain.EnforcementFailureSetupStatusPost, repository.ValidationError{Message: "Recovery stopped: the controlled thawguard/setup status could not be posted with the stored token. The repository remains unhealthy; fix the token permissions or forge setup and retry."}
	}
	verifiedAt := s.now().UTC()
	counts, reason, _, policyErr := s.reconcileCurrentPolicy(ctx, repo, &verifiedAt, false, claim)
	if policyErr != nil {
		if reason == "" {
			if failureErr := s.recordRuntimeFailure(ctx, repo.ID, domain.EnforcementFailureRuntime, actor, preserveJobGeneration); failureErr != nil {
				return domain.Repository{}, domain.EnforcementFailureRuntime, errors.Join(policyErr, failureErr)
			}
			return domain.Repository{}, domain.EnforcementFailureRuntime, policyErr
		}
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementRecoverFail, resultState: domain.EnforcementUnhealthy, reason: reason, counts: &counts, persistFailure: true, preserveJobGeneration: preserveJobGeneration}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, reason, recordErr
		}
		return domain.Repository{}, reason, repository.ValidationError{Message: recoverFailureMessage(reason)}
	}
	updated, err := s.recordEnforcementSuccess(ctx, repo, actor, audit.ActionRepositoryEnforcementRecovered, map[string]string{
		"default_branch": repo.DefaultBranch,
		"head_sha":       abbreviateSHA(head.SHA),
	}, counts, claim)
	if category, ok := convergenceStateChangeCategory(err); ok {
		return domain.Repository{}, category, err
	}
	if err != nil {
		recordErr := s.recordRuntimeFailure(ctx, repo.ID, domain.EnforcementFailureRuntime, actor, preserveJobGeneration)
		return domain.Repository{}, domain.EnforcementFailureRuntime, errors.Join(err, recordErr)
	}
	return updated, "", err
}

// processReconciliationClaim runs only current repository-wide state. It never
// replays stale branch, PR, SHA, or status payload data from the job.
func (s *enforcementService) processReconciliationClaim(ctx context.Context, claim jobs.Job) (string, error) {
	repo, err := repository.NewStore(s.db).Get(ctx, claim.RepositoryID)
	if errors.Is(err, sql.ErrNoRows) {
		_, completeErr := s.jobs.CompleteClaim(ctx, claim)
		return "", completeErr
	}
	if err != nil {
		return s.rescheduleRuntimeClaim(ctx, claim, domain.EnforcementFailureRuntime, err)
	}
	if !repo.Active || repo.EnforcementState == domain.EnforcementSetupIncomplete || repo.EnforcementState == domain.EnforcementReady {
		_, err := s.jobs.CompleteClaim(ctx, claim)
		return "", err
	}
	actor := domain.Actor{Kind: domain.ActorKindSystem, Role: "reconciliation_runner"}
	var category string
	if repo.EnforcementState == domain.EnforcementUnhealthy {
		_, category, err = s.recoverEnforcementCore(ctx, repo, actor, true, claim)
	} else {
		_, category, err = s.reconcileEnforcementCore(ctx, repo, actor, true, claim)
	}
	if err != nil {
		if category == "" {
			category = domain.EnforcementFailureRuntime
		}
		return s.rescheduleRuntimeClaim(ctx, claim, category, err)
	}
	return "", nil
}

func (s *enforcementService) rescheduleRuntimeClaim(ctx context.Context, claim jobs.Job, category string, cause error) (string, error) {
	if !domain.ValidEnforcementFailureReason(category) {
		category = domain.EnforcementFailureRuntime
	}
	if _, err := s.jobs.RescheduleClaim(ctx, claim, category); err != nil {
		return category, errors.Join(cause, err)
	}
	return category, cause
}

func reconcileFailureMessage(reason string) string {
	switch reason {
	case domain.EnforcementFailureOpenPRSync:
		return "Reconciliation failed: current open pull requests could not be synchronized from the forge. The repository is marked unhealthy and nothing was published from the stale cache."
	case domain.EnforcementFailureEvaluation:
		return "Reconciliation failed while evaluating the current freeze policy. The repository is marked unhealthy."
	default:
		return "Reconciliation failed while republishing thawguard/freeze statuses. The repository is marked unhealthy; statuses already posted were not rolled back."
	}
}

func recoverFailureMessage(reason string) string {
	switch reason {
	case domain.EnforcementFailureOpenPRSync:
		return "Recovery stopped: current open pull requests could not be synchronized from the forge. The repository remains unhealthy and nothing was published from the stale cache."
	case domain.EnforcementFailureEvaluation:
		return "Recovery failed while evaluating the current freeze policy. The repository remains unhealthy."
	default:
		return "Recovery failed while republishing thawguard/freeze statuses. The repository remains unhealthy; statuses already posted were not rolled back."
	}
}
