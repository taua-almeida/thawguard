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
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

const statusPostVerificationDescription = "Thawguard status-post verification"

type enforcementReadinessRunner interface {
	Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error)
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
	if err := s.requireVerifiableReadiness(ctx, repo); err != nil {
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
	if err := s.requireVerifiableReadiness(ctx, repo); err != nil {
		return domain.Repository{}, err
	}
	head, postErr := s.controlledSetupPost(ctx, repo)
	if postErr != nil {
		// The token can no longer prove it posts statuses, so ready is no
		// longer truthful: clear the evidence and return to setup.
		failure := activationFailure{resultState: domain.EnforcementSetupIncomplete, clearVerification: true, reason: "setup status post failed"}
		if err := s.recordActivationFailure(ctx, repo, actor, failure); err != nil {
			return domain.Repository{}, err
		}
		return domain.Repository{}, repository.ValidationError{Message: "Activation stopped: the controlled thawguard/setup status could not be posted. The repository returned to setup-incomplete; fix the token or forge setup and verify again."}
	}
	if err := s.syncer.syncRepository(ctx, repo, ""); err != nil {
		failure := activationFailure{resultState: domain.EnforcementReady, reason: "open pull request synchronization failed"}
		if err := s.recordActivationFailure(ctx, repo, actor, failure); err != nil {
			return domain.Repository{}, err
		}
		return domain.Repository{}, repository.ValidationError{Message: "Activation stopped: current open pull requests could not be synchronized from the forge. The repository stays ready and nothing was published."}
	}
	openPRs, managedBranches, err := s.openManagedBranchPullRequests(ctx, repo)
	if err != nil {
		failure := activationFailure{resultState: domain.EnforcementReady, reason: "open pull request lookup failed"}
		if recordErr := s.recordActivationFailure(ctx, repo, actor, failure); recordErr != nil {
			return domain.Repository{}, recordErr
		}
		return domain.Repository{}, repository.ValidationError{Message: "Activation stopped: synchronized open pull requests could not be loaded. The repository stays ready and nothing was published."}
	}
	groups := pullRequestsByHead(openPRs)

	// Publication requires active enforcement, so the state flips first; a
	// publication failure immediately becomes unhealthy instead of silently
	// reporting a successful activation.
	verifiedAt := s.now().UTC()
	if err := s.markActive(ctx, repo.ID, verifiedAt); err != nil {
		return domain.Repository{}, err
	}
	counts := activationCounts{managedBranches: managedBranches, openPullRequests: len(openPRs)}
	for _, group := range groups {
		counts.statusesAttempted++
		result, publishErr := s.statuses.RunForSharedHead(ctx, group, group[0].Index)
		if publishErr == nil {
			_, publishErr = s.publisher.Publish(ctx, result)
		}
		if publishErr != nil {
			counts.statusesFailed++
			failure := activationFailure{resultState: domain.EnforcementUnhealthy, reason: "initial freeze status publication failed", counts: &counts}
			if err := s.recordActivationFailure(ctx, repo, actor, failure); err != nil {
				return domain.Repository{}, err
			}
			return domain.Repository{}, repository.ValidationError{Message: "Activation failed while publishing initial thawguard/freeze statuses. The repository is marked unhealthy; statuses already posted were not rolled back."}
		}
		counts.statusesPosted++
	}
	return s.recordActivationSuccess(ctx, repo, head, actor, counts)
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
func (s *enforcementService) requireVerifiableReadiness(ctx context.Context, repo domain.Repository) error {
	results, err := s.readiness.Run(ctx, repo)
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

type activationCounts struct {
	managedBranches   int
	openPullRequests  int
	statusesAttempted int
	statusesPosted    int
	statusesFailed    int
}

type activationFailure struct {
	resultState       domain.EnforcementState
	clearVerification bool
	reason            string
	counts            *activationCounts
}

func (s *enforcementService) recordActivationFailure(ctx context.Context, repo domain.Repository, actor domain.Actor, failure activationFailure) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		store := repository.NewStoreTx(tx)
		updated := repo
		var err error
		if failure.clearVerification {
			updated, err = store.SetStatusPostVerifiedAt(ctx, repo.ID, nil)
			if err != nil {
				return err
			}
		}
		if failure.resultState != repo.EnforcementState {
			updated, err = store.SetEnforcementState(ctx, repo.ID, failure.resultState)
			if err != nil {
				return err
			}
		}
		event := enforcementEvent(audit.ActionRepositoryEnforcementActivateFail, updated, actor, map[string]string{
			"default_branch": repo.DefaultBranch,
			"reason":         failure.reason,
		}, failure.counts)
		if err := audit.NewStoreTx(tx).Record(ctx, event); err != nil {
			return fmt.Errorf("record repository.enforcement_activation_failed audit event: %w", err)
		}
		return nil
	})
}

func (s *enforcementService) markActive(ctx context.Context, repositoryID int64, verifiedAt time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		store := repository.NewStoreTx(tx)
		if _, err := store.SetStatusPostVerifiedAt(ctx, repositoryID, &verifiedAt); err != nil {
			return err
		}
		if _, err := store.SetEnforcementState(ctx, repositoryID, domain.EnforcementActive); err != nil {
			return err
		}
		return nil
	})
}

func (s *enforcementService) recordActivationSuccess(ctx context.Context, repo domain.Repository, head forge.BranchHead, actor domain.Actor, counts activationCounts) (domain.Repository, error) {
	updated, err := repository.NewStore(s.db).Get(ctx, repo.ID)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("load repository after enforcement activation: %w", err)
	}
	event := enforcementEvent(audit.ActionRepositoryEnforcementActivated, updated, actor, map[string]string{
		"default_branch": repo.DefaultBranch,
		"head_sha":       abbreviateSHA(head.SHA),
	}, &counts)
	if err := audit.NewStore(s.db).Record(ctx, event); err != nil {
		return domain.Repository{}, fmt.Errorf("record repository.enforcement_activated audit event: %w", err)
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
