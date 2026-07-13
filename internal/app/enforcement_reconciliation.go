package app

import (
	"context"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

// ReconcileEnforcement proves that current forge state and current Thawguard
// policy still converge for an active repository: it re-runs the read-only
// readiness checks, synchronizes all current open pull requests, and
// republishes the current thawguard/freeze policy once per repository-wide
// shared head. Publishing the real policy statuses is the status-post proof,
// so no thawguard/setup status is posted. Any failure marks the repository
// unhealthy with a stored sanitized reason; only the explicit recovery action
// can return it to active.
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
	if err := s.requireVerifiableReadiness(ctx, repo); err != nil {
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementReconcileFail, resultState: domain.EnforcementUnhealthy, reason: domain.EnforcementFailureReadinessChecks, persistFailure: true}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, recordErr
		}
		return domain.Repository{}, repository.ValidationError{Message: "Reconciliation stopped: readiness checks did not pass, so nothing was synchronized or published. The repository is marked unhealthy. " + err.Error()}
	}
	counts, reason, policyErr := s.reconcileCurrentPolicy(ctx, repo, nil)
	if policyErr != nil {
		if reason == "" {
			return domain.Repository{}, policyErr
		}
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementReconcileFail, resultState: domain.EnforcementUnhealthy, reason: reason, counts: &counts, persistFailure: true}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, recordErr
		}
		return domain.Repository{}, repository.ValidationError{Message: reconcileFailureMessage(reason)}
	}
	return s.recordEnforcementSuccess(ctx, repo, actor, audit.ActionRepositoryEnforcementReconciled, map[string]string{
		"default_branch": repo.DefaultBranch,
	}, counts)
}

// RecoverEnforcement is the only transition from unhealthy back to active.
// It re-runs every read-only readiness check, re-performs the controlled
// thawguard/setup status-post verification against the current default-branch
// head, synchronizes current open pull requests, and republishes the current
// thawguard/freeze policy. The repository becomes active only after every
// step succeeds; any failure leaves it unhealthy with an updated stored
// reason. Stored readiness or verification evidence is never trusted.
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
	if err := s.requireVerifiableReadiness(ctx, repo); err != nil {
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementRecoverFail, resultState: domain.EnforcementUnhealthy, reason: domain.EnforcementFailureReadinessChecks, persistFailure: true}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, recordErr
		}
		return domain.Repository{}, repository.ValidationError{Message: "Recovery stopped: readiness checks did not pass, so no status was posted, synchronized, or published. The repository remains unhealthy. " + err.Error()}
	}
	head, postErr := s.controlledSetupPost(ctx, repo)
	if postErr != nil {
		// The failed post disproves the stored verification evidence, so it
		// is cleared exactly like a failed pre-activation verification.
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementRecoverFail, resultState: domain.EnforcementUnhealthy, clearVerification: true, reason: domain.EnforcementFailureSetupStatusPost, persistFailure: true}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, recordErr
		}
		return domain.Repository{}, repository.ValidationError{Message: "Recovery stopped: the controlled thawguard/setup status could not be posted with the stored token. The repository remains unhealthy; fix the token permissions or forge setup and retry."}
	}
	verifiedAt := s.now().UTC()
	counts, reason, policyErr := s.reconcileCurrentPolicy(ctx, repo, &verifiedAt)
	if policyErr != nil {
		if reason == "" {
			return domain.Repository{}, policyErr
		}
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementRecoverFail, resultState: domain.EnforcementUnhealthy, reason: reason, counts: &counts, persistFailure: true}
		if recordErr := s.recordEnforcementFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, recordErr
		}
		return domain.Repository{}, repository.ValidationError{Message: recoverFailureMessage(reason)}
	}
	return s.recordEnforcementSuccess(ctx, repo, actor, audit.ActionRepositoryEnforcementRecovered, map[string]string{
		"default_branch": repo.DefaultBranch,
		"head_sha":       abbreviateSHA(head.SHA),
	}, counts)
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
