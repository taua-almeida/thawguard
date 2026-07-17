package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

const statusPostVerificationDescription = "Thawguard status-post verification"

const (
	activeFreezeDeactivationMessage    = "Lift all active freezes before deactivating repository enforcement."
	pendingScheduleDeactivationMessage = "Cancel all pending scheduled freezes before deactivating repository enforcement."
)

type enforcementReadinessRunner interface {
	Run(ctx context.Context, repo domain.Repository, actor domain.Actor) ([]setupcheck.Result, error)
}

type enforcementStatusTokenGetter interface {
	StatusToken(ctx context.Context, repositoryID int64) (string, bool, error)
}

type enforcementForgeClient interface {
	GetBranchHead(ctx context.Context, owner, repo, branch string) (forge.BranchHead, error)
	PostCommitStatus(ctx context.Context, owner, repo string, status forge.CommitStatus) error
}

type enforcementForgeClientFactory func(repository domain.Repository, token string) (enforcementForgeClient, error)

// enforcementService owns the two explicit admin transitions of the
// repository enforcement lifecycle: the controlled thawguard/setup
// status-post verification (setup_incomplete -> ready) and activation with
// initial reconciliation (ready -> active, or unhealthy when the initial
// real-status publication fails). Both deliberately re-run the read-only
// readiness checks instead of trusting stored evidence.
type enforcementService struct {
	db           *sql.DB
	tokens       enforcementStatusTokenGetter
	readiness    enforcementReadinessRunner
	clientFor    enforcementForgeClientFactory
	syncer       *forgeOpenPullRequestSyncer
	pullRequests openPullRequestBranchLister
	statuses     sharedHeadStatusRunner
	publisher    statusPublisher
	jobs         *jobs.Store
	now          func() time.Time
}

func newEnforcementService(db *sql.DB, tokens enforcementStatusTokenGetter, readiness enforcementReadinessRunner, clientFor enforcementForgeClientFactory, syncer *forgeOpenPullRequestSyncer, pullRequests openPullRequestBranchLister, statuses sharedHeadStatusRunner, publisher statusPublisher) *enforcementService {
	return &enforcementService{
		db:           db,
		tokens:       tokens,
		readiness:    readiness,
		clientFor:    clientFor,
		syncer:       syncer,
		pullRequests: pullRequests,
		statuses:     statuses,
		publisher:    publisher,
		jobs:         jobs.NewStore(db),
		now:          func() time.Time { return time.Now().UTC() },
	}
}

// VerifyStatusPosting re-runs the read-only readiness checks and then posts
// one harmless thawguard/setup=success status against the current default
// branch head. Success is the only transition to ready.
func (s *enforcementService) VerifyStatusPosting(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if err := s.configured(); err != nil {
		return domain.Repository{}, err
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return domain.Repository{}, err
	}
	switch repo.EnforcementState {
	case domain.EnforcementSetupIncomplete, domain.EnforcementReady:
	case domain.EnforcementActive:
		return domain.Repository{}, repository.ValidationError{Message: "Repository enforcement is already active. Status-post verification is only available before activation."}
	default:
		return domain.Repository{}, repository.ValidationError{Message: "Repository enforcement is unhealthy. Recovery is not part of status-post verification yet."}
	}
	if err := s.requireVerifiableReadiness(ctx, repo, actor); err != nil {
		return domain.Repository{}, err
	}
	head, postErr := s.controlledSetupPost(ctx, repo)
	if postErr != nil {
		if err := s.recordVerificationFailure(ctx, repo, actor); err != nil {
			return domain.Repository{}, err
		}
		return domain.Repository{}, repository.ValidationError{Message: "Status-post verification failed: the controlled thawguard/setup status could not be posted with the stored token. Fix the token permissions or forge setup, rerun readiness checks, and retry."}
	}
	return s.recordVerificationSuccess(ctx, repo, head, actor)
}

// ActivateEnforcement is the explicit second confirmation: it revalidates
// state, re-runs readiness, re-performs the controlled setup post,
// synchronizes current open pull requests, and only then transitions to
// active and publishes the real thawguard/freeze statuses.
func (s *enforcementService) ActivateEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if err := s.configured(); err != nil {
		return domain.Repository{}, err
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return domain.Repository{}, err
	}
	if repo.EnforcementState != domain.EnforcementReady {
		return domain.Repository{}, repository.ValidationError{Message: "Repository enforcement can only be activated from the ready state. Verify status posting first."}
	}
	if err := s.requireVerifiableReadiness(ctx, repo, actor); err != nil {
		return domain.Repository{}, err
	}
	head, postErr := s.controlledSetupPost(ctx, repo)
	if postErr != nil {
		// The token can no longer prove it posts statuses, so ready is no
		// longer truthful: clear the evidence and return to setup.
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementActivateFail, resultState: domain.EnforcementSetupIncomplete, clearVerification: true, reason: domain.EnforcementFailureSetupStatusPost}
		if err := s.recordEnforcementFailure(ctx, repo, actor, failure); err != nil {
			return domain.Repository{}, err
		}
		return domain.Repository{}, repository.ValidationError{Message: "Activation stopped: the controlled thawguard/setup status could not be posted. The repository returned to setup-incomplete; fix the token or forge setup and verify again."}
	}
	verifiedAt := s.now().UTC()
	counts, reason, claim, policyErr := s.reconcileCurrentPolicy(ctx, repo, &verifiedAt, true, jobs.Job{})
	if policyErr != nil {
		if reason == domain.EnforcementFailureOpenPRSync {
			// The forge cache never refreshed and enforcement never flipped:
			// the repository stays ready and nothing was published.
			failure := enforcementFailure{action: audit.ActionRepositoryEnforcementActivateFail, resultState: domain.EnforcementReady, reason: reason}
			if err := s.recordEnforcementFailure(ctx, repo, actor, failure); err != nil {
				return domain.Repository{}, err
			}
			return domain.Repository{}, repository.ValidationError{Message: "Activation stopped: current open pull requests could not be synchronized from the forge. The repository stays ready and nothing was published."}
		}
		if reason == "" {
			if claim.ID == 0 {
				if errors.Is(policyErr, jobs.ErrReconciliationInProgress) {
					return domain.Repository{}, repository.ValidationError{Message: "Enforcement activation is already in progress."}
				}
				return domain.Repository{}, policyErr
			}
			return domain.Repository{}, s.failClaimedActivation(ctx, repo, actor, claim, domain.EnforcementFailureRuntime, policyErr)
		}
		failure := enforcementFailure{action: audit.ActionRepositoryEnforcementActivateFail, resultState: domain.EnforcementUnhealthy, reason: reason, counts: &counts, persistFailure: true, preserveJobGeneration: true}
		if err := s.recordEnforcementFailure(ctx, repo, actor, failure); err != nil {
			return domain.Repository{}, s.failClaimedActivation(ctx, repo, actor, claim, domain.EnforcementFailureRuntime, err)
		}
		_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, reason)
		return domain.Repository{}, errors.Join(repository.ValidationError{Message: "Activation failed while publishing initial thawguard/freeze statuses. The repository is marked unhealthy; statuses already posted were not rolled back."}, rescheduleErr)
	}
	updated, err := s.recordEnforcementSuccess(ctx, repo, actor, audit.ActionRepositoryEnforcementActivated, map[string]string{
		"default_branch": repo.DefaultBranch,
		"head_sha":       abbreviateSHA(head.SHA),
	}, counts, claim)
	if err != nil {
		if category, ok := convergenceStateChangeCategory(err); ok {
			_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, category)
			return domain.Repository{}, errors.Join(err, rescheduleErr)
		}
		return domain.Repository{}, s.failClaimedActivation(ctx, repo, actor, claim, domain.EnforcementFailureRuntime, err)
	}
	return updated, nil
}

// DeactivateEnforcement converges the current no-freeze policy while holding
// the repository's durable reconciliation claim, then atomically fences that
// exact generation and transitions active to ready. Existing credentials and
// status-post verification evidence are retained for maintenance.
func (s *enforcementService) DeactivateEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error) {
	if err := s.configured(); err != nil {
		return domain.Repository{}, err
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return domain.Repository{}, err
	}
	if repo.EnforcementState != domain.EnforcementActive {
		return domain.Repository{}, repository.ValidationError{Message: "Repository enforcement can only be deactivated while it is active."}
	}
	if err := s.requireNoDeactivationBlockers(ctx, freeze.NewStore(s.db), repo.ID); err != nil {
		return domain.Repository{}, err
	}
	if _, err := s.jobs.EnqueueReconciliation(ctx, repo.ID); err != nil {
		return domain.Repository{}, err
	}
	claim, claimed, err := s.jobs.ClaimRepository(ctx, repo.ID)
	if err != nil {
		return domain.Repository{}, err
	}
	if !claimed {
		return domain.Repository{}, repository.ValidationError{Message: "Repository enforcement reconciliation is already in progress. Retry deactivation after it finishes."}
	}

	counts, reason, _, convergeErr := s.reconcileCurrentPolicy(ctx, repo, nil, false, claim)
	if convergeErr != nil {
		if !domain.ValidEnforcementFailureReason(reason) {
			reason = domain.EnforcementFailureRuntime
		}
		_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, reason)
		return domain.Repository{}, errors.Join(repository.ValidationError{Message: "Deactivation stopped because the current freeze policy could not be reconciled. Repository enforcement remains active and retry work is preserved."}, convergeErr, rescheduleErr)
	}

	updated, err := s.recordEnforcementDeactivation(ctx, repo, actor, counts, claim)
	if err != nil {
		category := domain.EnforcementFailureRuntime
		if changedCategory, ok := convergenceStateChangeCategory(err); ok {
			category = changedCategory
		}
		_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, category)
		return domain.Repository{}, errors.Join(err, rescheduleErr)
	}
	return updated, nil
}

func (s *enforcementService) requireNoDeactivationBlockers(ctx context.Context, store *freeze.Store, repositoryID int64) error {
	active, err := store.HasActiveForRepository(ctx, repositoryID)
	if err != nil {
		return err
	}
	if active {
		return repository.ValidationError{Message: activeFreezeDeactivationMessage}
	}
	scheduled, err := store.HasScheduledForRepository(ctx, repositoryID)
	if err != nil {
		return err
	}
	if scheduled {
		return repository.ValidationError{Message: pendingScheduleDeactivationMessage}
	}
	return nil
}

func (s *enforcementService) recordEnforcementDeactivation(ctx context.Context, repo domain.Repository, actor domain.Actor, counts activationCounts, claim jobs.Job) (domain.Repository, error) {
	var updated domain.Repository
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		repositoryStore := repository.NewStoreTx(tx)
		current, err := repositoryStore.Get(ctx, repo.ID)
		if err != nil {
			return err
		}
		if !current.Active || current.EnforcementState != domain.EnforcementActive {
			return repository.ValidationError{Message: "Repository enforcement changed while deactivation was running. It was not deactivated."}
		}
		if err := s.requireNoDeactivationBlockers(ctx, freeze.NewStoreTx(tx), repo.ID); err != nil {
			return err
		}
		completed, err := jobs.NewStoreTx(tx).CompleteClaim(ctx, claim)
		if err != nil {
			return err
		}
		if !completed {
			return convergenceStateChangeError{category: domain.EnforcementFailureRuntime}
		}
		if err := freeze.NewStoreTx(tx).MarkRepositoryRecomputed(ctx, repo.ID); err != nil {
			return err
		}
		var transitioned bool
		updated, transitioned, err = repositoryStore.TransitionEnforcementState(ctx, repo.ID, domain.EnforcementActive, domain.EnforcementReady)
		if err != nil {
			return err
		}
		if !transitioned {
			return repository.ValidationError{Message: "Repository enforcement changed while deactivation was running. It was not deactivated."}
		}
		updated, err = repositoryStore.ClearEnforcementFailure(ctx, repo.ID)
		if err != nil {
			return err
		}
		event := enforcementEvent(audit.ActionRepositoryEnforcementDeactivated, updated, actor, map[string]string{
			"default_branch": repo.DefaultBranch,
			"maintenance":    "status token or managed branch",
		}, &counts)
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return fmt.Errorf("record repository.enforcement_deactivated audit event: %w", err)
		}
		return nil
	})
	return updated, err
}

// reconcileCurrentPolicy is the one shared implementation of enforcement
// convergence used by activation, unhealthy recovery, and manual
// reconciliation: it synchronizes current open pull requests from the forge,
// groups them by repository-wide shared head, and evaluates and publishes the
// current thawguard/freeze policy once per group. Real publication is gated
// on active enforcement, so when activateVerifiedAt is set the repository
// flips to active (with fresh verification evidence) between the cache
// refresh and the first publication; callers own reverting the state on
// failure. It stops at the first failed group and returns its stable failure
// reason with truthful counts; already-posted statuses are never rolled back.
func (s *enforcementService) reconcileCurrentPolicy(ctx context.Context, repo domain.Repository, activateVerifiedAt *time.Time, enqueueActivationIntent bool, expectedClaim jobs.Job) (activationCounts, string, jobs.Job, error) {
	counts := activationCounts{}
	if err := s.syncer.syncRepository(ctx, repo, ""); err != nil {
		return counts, domain.EnforcementFailureOpenPRSync, jobs.Job{}, err
	}
	openPRs, managedBranches, err := s.openManagedBranchPullRequests(ctx, repo)
	if err != nil {
		return counts, domain.EnforcementFailureOpenPRSync, jobs.Job{}, err
	}
	counts.managedBranches = managedBranches
	counts.openPullRequests = len(openPRs)
	claim := expectedClaim
	if activateVerifiedAt != nil {
		activatedClaim, _, markErr := s.markActive(ctx, repo.ID, *activateVerifiedAt, enqueueActivationIntent)
		err = markErr
		if err != nil {
			return counts, "", jobs.Job{}, err
		}
		if activatedClaim.ID != 0 {
			claim = activatedClaim
		}
	}
	for _, group := range pullRequestsByHead(openPRs) {
		if err := s.requireCurrentReconciliationClaim(ctx, claim); err != nil {
			return counts, "", claim, err
		}
		counts.statusesAttempted++
		result, err := s.statuses.RunForSharedHead(ctx, group, group[0].Index)
		if err != nil {
			counts.statusesFailed++
			return counts, domain.EnforcementFailureEvaluation, claim, err
		}
		if err := s.requireCurrentReconciliationClaim(ctx, claim); err != nil {
			return counts, "", claim, err
		}
		if _, err := s.publisher.Publish(ctx, result); err != nil {
			counts.statusesFailed++
			return counts, domain.EnforcementFailurePublication, claim, err
		}
		counts.statusesPosted++
	}
	return counts, "", claim, nil
}

func (s *enforcementService) requireCurrentReconciliationClaim(ctx context.Context, claim jobs.Job) error {
	current, err := s.jobs.ClaimCurrent(ctx, claim)
	if err != nil {
		return err
	}
	if !current {
		return convergenceStateChangeError{category: domain.EnforcementFailureRuntime}
	}
	return nil
}

func (s *enforcementService) configured() error {
	if s == nil || s.db == nil || s.tokens == nil || s.readiness == nil || s.clientFor == nil || s.syncer == nil || s.pullRequests == nil || s.statuses == nil || s.publisher == nil {
		return errors.New("enforcement service is not configured")
	}
	return nil
}

func (s *enforcementService) loadRepository(ctx context.Context, repositoryID int64) (domain.Repository, error) {
	if repositoryID <= 0 {
		return domain.Repository{}, repository.ValidationError{Message: "repository id is required"}
	}
	repo, err := repository.NewStore(s.db).Get(ctx, repositoryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, repository.ValidationError{Message: "repository not found"}
		}
		return domain.Repository{}, fmt.Errorf("load repository for enforcement transition: %w", err)
	}
	return repo, nil
}

// requireVerifiableReadiness re-runs the read-only readiness checks and
// requires every mandatory check to be OK. The expected "status posting has
// not been tested yet" warning is the only allowed non-OK result; a stale
// webhook warning or any failure blocks before any forge write.
func (s *enforcementService) requireVerifiableReadiness(ctx context.Context, repo domain.Repository, actor domain.Actor) error {
	results, err := s.readiness.Run(ctx, repo, actor)
	if err != nil {
		return repository.ValidationError{Message: "Readiness checks could not be completed. Fix the reported repository setup problems and retry."}
	}
	blockers := readinessBlockers(results)
	if len(blockers) > 0 {
		return repository.ValidationError{Message: "Every read-only readiness check must pass first. Fix and rerun: " + strings.Join(blockers, "; ") + "."}
	}
	return nil
}

func readinessBlockers(results []setupcheck.Result) []string {
	if len(results) == 0 {
		return []string{"no readiness evidence was recorded"}
	}
	blockers := make([]string, 0)
	for _, result := range results {
		if result.Status == setupcheck.StatusOK {
			continue
		}
		if result.Name == setupcheck.CheckStatusPostingUntested && result.Status == setupcheck.StatusWarning {
			continue
		}
		blockers = append(blockers, result.Name)
	}
	return blockers
}

// controlledSetupPost fetches the current default-branch head and posts the
// harmless thawguard/setup=success status against it. It never posts the
// merge-gating thawguard/freeze context and never records a status result or
// publication row: the setup test is not a freeze-policy decision.
func (s *enforcementService) controlledSetupPost(ctx context.Context, repo domain.Repository) (forge.BranchHead, error) {
	token, found, err := s.tokens.StatusToken(ctx, repo.ID)
	if err != nil {
		return forge.BranchHead{}, fmt.Errorf("load repository status token for status-post verification: %w", err)
	}
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return forge.BranchHead{}, errors.New("repository status token is not configured")
	}
	client, err := s.clientFor(repo, token)
	if err != nil {
		return forge.BranchHead{}, safeOpenPullRequestSyncError(fmt.Errorf("create forgejo enforcement client: %w", err), token)
	}
	if client == nil {
		return forge.BranchHead{}, errors.New("create forgejo enforcement client: nil client")
	}
	head, err := client.GetBranchHead(ctx, repo.Owner, repo.Name, repo.DefaultBranch)
	if err != nil {
		return forge.BranchHead{}, safeOpenPullRequestSyncError(fmt.Errorf("fetch default branch head: %w", err), token)
	}
	if err := client.PostCommitStatus(ctx, repo.Owner, repo.Name, forge.CommitStatus{
		SHA:         head.SHA,
		State:       domain.CommitStatusSuccess,
		Context:     domain.SetupStatusContext,
		Description: statusPostVerificationDescription,
	}); err != nil {
		return forge.BranchHead{}, safeOpenPullRequestSyncError(fmt.Errorf("post controlled setup status: %w", err), token)
	}
	return head, nil
}

// openManagedBranchPullRequests returns the cached open pull requests
// targeting any managed branch plus the managed branch count for audit.
func (s *enforcementService) openManagedBranchPullRequests(ctx context.Context, repo domain.Repository) ([]domain.PullRequest, int, error) {
	branches, err := repository.NewStore(s.db).ListBranches(ctx, repo.ID)
	if err != nil {
		return nil, 0, err
	}
	merged := make([]domain.PullRequest, 0)
	seen := make(map[int]struct{})
	for _, branch := range branches {
		prs, err := s.pullRequests.ListOpenByTargetBranch(ctx, repo.ID, branch.Name)
		if err != nil {
			return nil, 0, err
		}
		for _, pr := range prs {
			if _, ok := seen[pr.Index]; ok {
				continue
			}
			seen[pr.Index] = struct{}{}
			merged = append(merged, pr)
		}
	}
	return merged, len(branches), nil
}

func (s *enforcementService) recordVerificationSuccess(ctx context.Context, repo domain.Repository, head forge.BranchHead, actor domain.Actor) (domain.Repository, error) {
	verifiedAt := s.now().UTC()
	var updated domain.Repository
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		store := repository.NewStoreTx(tx)
		if err := requireCurrentVerificationSnapshot(ctx, store, repo); err != nil {
			return err
		}
		if _, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, &verifiedAt); err != nil {
			return err
		}
		result, err := store.SetEnforcementState(ctx, repo.ID, domain.EnforcementReady)
		if err != nil {
			return err
		}
		updated = result
		event := enforcementEvent(audit.ActionRepositoryStatusPostVerified, updated, actor, map[string]string{
			"default_branch": repo.DefaultBranch,
			"head_sha":       abbreviateSHA(head.SHA),
		}, nil)
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return fmt.Errorf("record repository.status_post_verified audit event: %w", err)
		}
		return nil
	})
	if err != nil {
		return domain.Repository{}, err
	}
	return updated, nil
}

// recordVerificationFailure keeps or restores setup-incomplete and clears the
// verification evidence. Only generic sanitized details are persisted; forge
// response bodies and token material never reach the audit log.
func (s *enforcementService) recordVerificationFailure(ctx context.Context, repo domain.Repository, actor domain.Actor) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		store := repository.NewStoreTx(tx)
		if err := requireCurrentVerificationSnapshot(ctx, store, repo); err != nil {
			return err
		}
		updated, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, nil)
		if err != nil {
			return err
		}
		if repo.EnforcementState != domain.EnforcementSetupIncomplete {
			updated, err = store.SetEnforcementState(ctx, repo.ID, domain.EnforcementSetupIncomplete)
			if err != nil {
				return err
			}
		}
		event := enforcementEvent(audit.ActionRepositoryStatusPostVerifyFailed, updated, actor, map[string]string{
			"default_branch": repo.DefaultBranch,
			"reason":         "controlled setup status post failed",
		}, nil)
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return fmt.Errorf("record repository.status_post_verification_failed audit event: %w", err)
		}
		return nil
	})
}

func requireCurrentVerificationSnapshot(ctx context.Context, store *repository.Store, expected domain.Repository) error {
	current, err := store.Get(ctx, expected.ID)
	if err != nil {
		return err
	}
	if current.Active != expected.Active || current.EnforcementState != expected.EnforcementState || !current.UpdatedAt.Equal(expected.UpdatedAt) {
		return repository.ValidationError{Message: "Repository setup changed while status-post verification was running. Rerun readiness checks and retry verification."}
	}
	return nil
}

type activationCounts struct {
	managedBranches   int
	openPullRequests  int
	statusesAttempted int
	statusesPosted    int
	statusesFailed    int
}

// enforcementFailure describes how a failed enforcement run lands: the
// resulting state, the stable sanitized reason, whether the reason becomes
// the repository's stored failure (only unhealthy results persist it), and
// which audit action records it.
type enforcementFailure struct {
	action                string
	resultState           domain.EnforcementState
	clearVerification     bool
	reason                string
	counts                *activationCounts
	persistFailure        bool
	preserveJobGeneration bool
}

func (s *enforcementService) recordEnforcementFailure(ctx context.Context, repo domain.Repository, actor domain.Actor, failure enforcementFailure) error {
	failedAt := s.now().UTC()
	return s.inTx(ctx, func(tx *sql.Tx) error {
		store := repository.NewStoreTx(tx)
		current, err := store.Get(ctx, repo.ID)
		if err != nil {
			return err
		}
		// A stale reconciliation failure must not overwrite a repository that
		// has since been safely deactivated to ready.
		if failure.resultState == domain.EnforcementUnhealthy && current.EnforcementState != domain.EnforcementActive && current.EnforcementState != domain.EnforcementUnhealthy {
			return nil
		}
		if failure.clearVerification {
			if _, err := store.SetStatusPostVerifiedAt(ctx, repo.ID, nil); err != nil {
				return err
			}
		}
		updated := current
		if current.EnforcementState != failure.resultState {
			if failure.resultState == domain.EnforcementUnhealthy {
				var transitioned bool
				updated, transitioned, err = store.TransitionEnforcementState(ctx, repo.ID, domain.EnforcementActive, domain.EnforcementUnhealthy)
				if err != nil {
					return err
				}
				if !transitioned {
					return nil
				}
			} else {
				updated, err = store.SetEnforcementState(ctx, repo.ID, failure.resultState)
				if err != nil {
					return err
				}
			}
		}
		if failure.persistFailure {
			updated, err = store.SetEnforcementFailure(ctx, repo.ID, failure.reason, failedAt)
			if err != nil {
				return err
			}
		}
		if failure.resultState == domain.EnforcementUnhealthy {
			jobStore := jobs.NewStoreTx(tx)
			if failure.preserveJobGeneration {
				if _, err := jobStore.EnsureReconciliationFailure(ctx, repo.ID, failure.reason); err != nil {
					return err
				}
			} else if _, err := jobStore.EnqueueReconciliationFailure(ctx, repo.ID, failure.reason); err != nil {
				return err
			}
		}
		event := enforcementEvent(failure.action, updated, actor, map[string]string{
			"default_branch": repo.DefaultBranch,
			"reason":         failure.reason,
		}, failure.counts)
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return fmt.Errorf("record %s audit event: %w", failure.action, err)
		}
		return nil
	})
}

func (s *enforcementService) recordRuntimeFailure(ctx context.Context, repositoryID int64, reason string, actor domain.Actor, preserveJobGeneration bool) error {
	if !domain.ValidEnforcementFailureReason(reason) {
		reason = domain.EnforcementFailureRuntime
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return err
	}
	failure := enforcementFailure{
		action:                audit.ActionRepositoryRuntimeConvergenceFail,
		resultState:           domain.EnforcementUnhealthy,
		reason:                reason,
		persistFailure:        true,
		preserveJobGeneration: preserveJobGeneration,
	}
	return s.recordEnforcementFailure(ctx, repo, actor, failure)
}

func (s *enforcementService) markActive(ctx context.Context, repositoryID int64, verifiedAt time.Time, enqueueIntent bool) (jobs.Job, bool, error) {
	claim := jobs.Job{}
	claimed := false
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		store := repository.NewStoreTx(tx)
		if _, err := store.SetStatusPostVerifiedAt(ctx, repositoryID, &verifiedAt); err != nil {
			return err
		}
		if _, err := store.SetEnforcementState(ctx, repositoryID, domain.EnforcementActive); err != nil {
			return err
		}
		if enqueueIntent {
			jobStore := jobs.NewStoreTx(tx)
			if _, err := jobStore.EnqueueReconciliation(ctx, repositoryID); err != nil {
				return err
			}
			var claimErr error
			claim, claimed, claimErr = jobStore.ClaimRepository(ctx, repositoryID)
			if claimErr != nil {
				return claimErr
			}
			if !claimed {
				return jobs.ErrReconciliationInProgress
			}
		}
		return nil
	})
	return claim, claimed, err
}

func (s *enforcementService) failClaimedActivation(ctx context.Context, repo domain.Repository, actor domain.Actor, claim jobs.Job, category string, cause error) error {
	recordErr := s.recordRuntimeFailure(ctx, repo.ID, category, actor, true)
	_, rescheduleErr := s.jobs.RescheduleClaim(ctx, claim, category)
	return errors.Join(cause, recordErr, rescheduleErr)
}

type convergenceStateChangeError struct {
	category string
}

func (e convergenceStateChangeError) Error() string {
	return "repository enforcement changed while convergence was running"
}

func convergenceStateChangeCategory(err error) (string, bool) {
	var stateErr convergenceStateChangeError
	if !errors.As(err, &stateErr) {
		return "", false
	}
	return stateErr.category, true
}

// recordEnforcementSuccess clears the stored failure state and records the
// success audit event after a fully successful activation, recovery, or
// reconciliation run.
func (s *enforcementService) recordEnforcementSuccess(ctx context.Context, repo domain.Repository, actor domain.Actor, action string, extra map[string]string, counts activationCounts, claim jobs.Job) (domain.Repository, error) {
	var updated domain.Repository
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		repositoryStore := repository.NewStoreTx(tx)
		current, err := repositoryStore.Get(ctx, repo.ID)
		if err != nil {
			return err
		}
		if !current.Active || current.EnforcementState != domain.EnforcementActive {
			category := current.EnforcementFailureReason
			if !domain.ValidEnforcementFailureReason(category) {
				category = domain.EnforcementFailureRuntime
			}
			return convergenceStateChangeError{category: category}
		}
		if err := freeze.NewStoreTx(tx).MarkRepositoryRecomputed(ctx, repo.ID); err != nil {
			return err
		}
		result, err := repositoryStore.ClearEnforcementFailure(ctx, repo.ID)
		if err != nil {
			return err
		}
		updated = result
		event := enforcementEvent(action, updated, actor, extra, &counts)
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return fmt.Errorf("record %s audit event: %w", action, err)
		}
		if _, err := jobs.NewStoreTx(tx).CompleteClaim(ctx, claim); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return domain.Repository{}, err
	}
	return updated, nil
}

func (s *enforcementService) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin enforcement transition: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enforcement transition: %w", err)
	}
	committed = true
	return nil
}

func enforcementEvent(action string, repo domain.Repository, actor domain.Actor, extra map[string]string, counts *activationCounts) audit.Event {
	details := map[string]string{
		"actor_kind":        actor.Kind,
		"actor_role":        actor.Role,
		"repository_id":     strconv.FormatInt(repo.ID, 10),
		"full_name":         repo.FullName(),
		"enforcement_state": string(repo.EnforcementState),
	}
	maps.Copy(details, extra)
	if counts != nil {
		details["managed_branch_count"] = strconv.Itoa(counts.managedBranches)
		details["open_pull_request_count"] = strconv.Itoa(counts.openPullRequests)
		details["statuses_attempted"] = strconv.Itoa(counts.statusesAttempted)
		details["statuses_posted"] = strconv.Itoa(counts.statusesPosted)
		details["statuses_failed"] = strconv.Itoa(counts.statusesFailed)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      action,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repo.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func abbreviateSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
