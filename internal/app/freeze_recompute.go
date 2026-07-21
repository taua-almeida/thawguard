package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

type freezeOperations interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
	CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error)
	End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type freezeLifecycleOperations interface {
	Get(ctx context.Context, id int64) (domain.BranchFreeze, error)
	ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ListScheduledPage(ctx context.Context, status domain.BranchFreezeStatus, offset, limit int) ([]domain.BranchFreeze, int, error)
	CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error)
	EditScheduled(ctx context.Context, params freeze.EditScheduleParams, actor domain.Actor) (domain.BranchFreeze, error)
	CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	StartScheduledNow(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	MarkRecomputed(ctx context.Context, id int64) (domain.BranchFreeze, error)
}

// materializedFreezeEnder ends an operator-thawed materialized freeze with
// thaw-until-next-window suppression of its covering schedules. Implemented
// by the schedule service; optional so freeze handling works without the
// schedule subsystem in tests.
type materializedFreezeEnder interface {
	EndMaterializedFreeze(ctx context.Context, freezeID int64, actor domain.Actor) (domain.BranchFreeze, error)
}

// materializedFreezeReads are the freeze store reads the schedule
// materializer needs; freeze.Service implements them, test fakes may not.
type materializedFreezeReads interface {
	GetActiveForBranch(ctx context.Context, repositoryID int64, branch string) (domain.BranchFreeze, bool, error)
	ListActiveMaterialized(ctx context.Context) ([]domain.BranchFreeze, error)
}

type freezeGetter interface {
	Get(ctx context.Context, id int64) (domain.BranchFreeze, error)
}

type openPullRequestBranchLister interface {
	ListOpenByTargetBranch(ctx context.Context, repositoryID int64, targetBranch string) ([]domain.PullRequest, error)
}

type sharedHeadStatusRunner interface {
	RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error)
}

type statusPublisher interface {
	Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error)
}

type recomputeRepositoryGetter interface {
	Get(ctx context.Context, id int64) (domain.Repository, error)
	BranchManaged(ctx context.Context, repositoryID int64, branch string) (bool, error)
}

// freezeRecomputingStore wraps freeze lifecycle mutations with the one
// enforcement behavior: for an enforcement-active repository every action
// that requires publication first synchronizes current open PRs from the
// forge, then evaluates each affected head SHA across the whole repository
// (including cross-target-branch collisions) and publishes the result.
// Freeze and scheduled-freeze creation are rejected before mutation when the
// repository is not enforcement-active; end/cancel stay possible for cleanup
// but never sync or publish for an inactive repository.
type freezeRecomputingStore struct {
	freezes      freezeOperations
	repositories recomputeRepositoryGetter
	syncer       openPullRequestSyncer
	pullRequests openPullRequestBranchLister
	statuses     sharedHeadStatusRunner
	publisher    statusPublisher
	convergence  enforcementConvergence
	// scheduleEnder, when set, receives operator-driven ends of freezes that
	// a recurring schedule materialized, so the end also suppresses the
	// schedule until its next window instead of being re-frozen on the next
	// materializer tick.
	scheduleEnder materializedFreezeEnder
}

func newFreezeRecomputingStore(freezes freezeOperations, repositories recomputeRepositoryGetter, syncer openPullRequestSyncer, pullRequests openPullRequestBranchLister, statuses sharedHeadStatusRunner, publisher statusPublisher) *freezeRecomputingStore {
	return &freezeRecomputingStore{freezes: freezes, repositories: repositories, syncer: syncer, pullRequests: pullRequests, statuses: statuses, publisher: publisher}
}

func (s *freezeRecomputingStore) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return nil, errors.New("freeze recomputing store has no freeze store")
	}
	return s.freezes.ListActive(ctx)
}

func (s *freezeRecomputingStore) CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, errors.New("freeze recomputing store has no freeze store")
	}
	if err := s.requireEnforcementActive(ctx, params.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.requireManagedBranch(ctx, params.RepositoryID, params.Branch); err != nil {
		return domain.BranchFreeze{}, err
	}
	created, err := s.freezes.CreateActive(ctx, params, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, created); err != nil {
		return created, err
	}
	return created, nil
}

func (s *freezeRecomputingStore) End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, errors.New("freeze recomputing store has no freeze store")
	}
	if ended, handled, err := s.endThroughSchedule(ctx, id, actor); handled {
		if err != nil {
			return domain.BranchFreeze{}, err
		}
		if err := s.convergeFreeze(ctx, ended); err != nil {
			return ended, err
		}
		return ended, nil
	}
	ended, err := s.freezes.End(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, ended); err != nil {
		return ended, err
	}
	return ended, nil
}

// endThroughSchedule routes an operator's "End freeze" on a materialized row
// through the schedule service so the covering schedules are suppressed until
// their next window. handled is false for manual freezes, for missing rows
// (plain End reports the proper error), or when the schedule subsystem is not
// wired.
func (s *freezeRecomputingStore) endThroughSchedule(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, bool, error) {
	if s.scheduleEnder == nil {
		return domain.BranchFreeze{}, false, nil
	}
	getter, ok := s.freezes.(freezeGetter)
	if !ok {
		return domain.BranchFreeze{}, false, nil
	}
	target, err := getter.Get(ctx, id)
	if err != nil || target.ScheduleID == nil {
		return domain.BranchFreeze{}, false, nil
	}
	ended, err := s.scheduleEnder.EndMaterializedFreeze(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, true, err
	}
	return ended, true, nil
}

// EndMaterialized ends a schedule-materialized freeze because its coverage
// lapsed. Unlike End it never routes through manual-end suppression: the
// schedule itself stopped covering, so it must stay eligible to freeze again
// at its next window.
func (s *freezeRecomputingStore) EndMaterialized(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, errors.New("freeze recomputing store has no freeze store")
	}
	ended, err := s.freezes.End(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, ended); err != nil {
		return ended, err
	}
	return ended, nil
}

func (s *freezeRecomputingStore) GetActiveForBranch(ctx context.Context, repositoryID int64, branch string) (domain.BranchFreeze, bool, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, false, errors.New("freeze recomputing store has no freeze store")
	}
	reads, ok := s.freezes.(materializedFreezeReads)
	if !ok {
		return domain.BranchFreeze{}, false, errors.New("freeze store does not support materialized freeze reads")
	}
	return reads.GetActiveForBranch(ctx, repositoryID, branch)
}

func (s *freezeRecomputingStore) ListActiveMaterialized(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return nil, errors.New("freeze recomputing store has no freeze store")
	}
	reads, ok := s.freezes.(materializedFreezeReads)
	if !ok {
		return nil, errors.New("freeze store does not support materialized freeze reads")
	}
	return reads.ListActiveMaterialized(ctx)
}

func (s *freezeRecomputingStore) Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, errors.New("freeze recomputing store has no freeze store")
	}
	cancelled, err := s.freezes.Cancel(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, cancelled); err != nil {
		return cancelled, err
	}
	return cancelled, nil
}

func (s *freezeRecomputingStore) ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return nil, err
	}
	return lifecycle.ListScheduled(ctx, limit)
}

func (s *freezeRecomputingStore) ListScheduledPage(ctx context.Context, status domain.BranchFreezeStatus, offset, limit int) ([]domain.BranchFreeze, int, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return nil, 0, err
	}
	return lifecycle.ListScheduledPage(ctx, status, offset, limit)
}

func (s *freezeRecomputingStore) CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.requireEnforcementActive(ctx, params.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.requireManagedBranch(ctx, params.RepositoryID, params.Branch); err != nil {
		return domain.BranchFreeze{}, err
	}
	return lifecycle.CreateScheduled(ctx, params, actor)
}

func (s *freezeRecomputingStore) CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	return lifecycle.CancelScheduled(ctx, id, actor)
}

func (s *freezeRecomputingStore) EditScheduled(ctx context.Context, params freeze.EditScheduleParams, actor domain.Actor) (domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	return lifecycle.EditScheduled(ctx, params, actor)
}

func (s *freezeRecomputingStore) ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return nil, err
	}
	return lifecycle.ListDueScheduled(ctx, limit)
}

func (s *freezeRecomputingStore) ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	// A due window on a repository whose enforcement is not active must stay
	// scheduled: no activation mutation, audit event, recompute, or publication.
	target, err := lifecycle.Get(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.BranchFreeze{}, freeze.ValidationError{Message: "scheduled freeze is not due"}
		}
		return domain.BranchFreeze{}, fmt.Errorf("load scheduled freeze for enforcement gating: %w", err)
	}
	if err := s.requireEnforcementActive(ctx, target.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	activated, err := lifecycle.ActivateScheduled(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, activated); err != nil {
		return activated, err
	}
	return activated, nil
}

func (s *freezeRecomputingStore) StartScheduledNow(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	target, err := lifecycle.Get(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.BranchFreeze{}, freeze.ValidationError{Message: "scheduled freeze is no longer pending"}
		}
		return domain.BranchFreeze{}, fmt.Errorf("load scheduled freeze for Start Now enforcement gating: %w", err)
	}
	if err := s.requireEnforcementActive(ctx, target.RepositoryID); err != nil {
		return domain.BranchFreeze{}, err
	}
	started, err := lifecycle.StartScheduledNow(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, started); err != nil {
		return started, err
	}
	return started, nil
}

func (s *freezeRecomputingStore) ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return nil, err
	}
	return lifecycle.ListDuePlannedUnfreezes(ctx, limit)
}

func (s *freezeRecomputingStore) ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return nil, err
	}
	return lifecycle.ListNeedsRecompute(ctx, limit)
}

func (s *freezeRecomputingStore) ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	ended, err := lifecycle.ExecutePlannedUnfreeze(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.convergeFreeze(ctx, ended); err != nil {
		return ended, err
	}
	return ended, nil
}

func (s *freezeRecomputingStore) RetryRecompute(ctx context.Context, pending domain.BranchFreeze) error {
	if s.convergence != nil {
		// Repository-scoped reconciliation owns durable retries. A branch-only
		// retry must not consume its job before the full repository converges.
		return nil
	}
	return s.convergeFreeze(ctx, pending)
}

func (s *freezeRecomputingStore) convergeFreeze(ctx context.Context, changed domain.BranchFreeze) error {
	var claim jobs.Job
	if s.convergence != nil {
		var claimed bool
		var err error
		claim, claimed, err = s.convergence.Claim(ctx, changed.RepositoryID)
		if err != nil {
			return err
		}
		if !claimed {
			return nil
		}
	}
	converged, err := s.recomputeBranch(ctx, changed.RepositoryID, changed.Branch, claim)
	if err != nil {
		return failRuntimeConvergence(ctx, s.convergence, claim, err)
	}
	if !converged {
		return nil
	}
	if err := s.markRecomputedIfNeeded(ctx, changed); err != nil {
		return failRuntimeConvergence(ctx, s.convergence, claim, convergenceError(domain.EnforcementFailureRuntime, err))
	}
	if s.convergence != nil {
		if err := s.convergence.Complete(ctx, claim); err != nil {
			return failRuntimeConvergence(ctx, s.convergence, claim, convergenceError(domain.EnforcementFailureRuntime, err))
		}
	}
	return nil
}

func (s *freezeRecomputingStore) markRecomputedIfNeeded(ctx context.Context, freeze domain.BranchFreeze) error {
	if !freeze.NeedsRecompute {
		return nil
	}
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return err
	}
	_, err = lifecycle.MarkRecomputed(ctx, freeze.ID)
	return err
}

func (s *freezeRecomputingStore) freezeLifecycle() (freezeLifecycleOperations, error) {
	if s == nil || s.freezes == nil {
		return nil, errors.New("freeze recomputing store has no freeze store")
	}
	lifecycle, ok := s.freezes.(freezeLifecycleOperations)
	if !ok {
		return nil, errors.New("freeze store does not support lifecycle operations")
	}
	return lifecycle, nil
}

func (s *freezeRecomputingStore) requireEnforcementActive(ctx context.Context, repositoryID int64) error {
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return err
	}
	if !repo.EnforcementActive() {
		return freeze.ValidationError{Message: domain.EnforcementNotActiveMessage}
	}
	return nil
}

// requireManagedBranch is the one managed-branch gate for freeze and
// scheduled-freeze creation: only exact managed branch names are accepted,
// checked before any mutation. End/cancel cleanup is intentionally not gated
// so historical freezes stay closable even if a branch was removed.
func (s *freezeRecomputingStore) requireManagedBranch(ctx context.Context, repositoryID int64, branch string) error {
	if s == nil || s.repositories == nil {
		return errors.New("freeze recomputing store has no repository store")
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		// Let store-level validation report the missing field.
		return nil
	}
	managed, err := s.repositories.BranchManaged(ctx, repositoryID, branch)
	if err != nil {
		return fmt.Errorf("check managed branch for freeze creation: %w", err)
	}
	if !managed {
		return freeze.ValidationError{Message: domain.BranchNotManagedMessage}
	}
	return nil
}

func (s *freezeRecomputingStore) loadRepository(ctx context.Context, repositoryID int64) (domain.Repository, error) {
	if s == nil || s.repositories == nil {
		return domain.Repository{}, errors.New("freeze recomputing store has no repository store")
	}
	repo, err := s.repositories.Get(ctx, repositoryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, freeze.ValidationError{Message: "repository not found"}
		}
		return domain.Repository{}, fmt.Errorf("load repository for freeze enforcement: %w", err)
	}
	return repo, nil
}

func (s *freezeRecomputingStore) recomputeBranch(ctx context.Context, repositoryID int64, branch string, claim jobs.Job) (bool, error) {
	if s == nil || s.syncer == nil || s.pullRequests == nil || s.statuses == nil || s.publisher == nil {
		return false, errors.New("freeze recomputing store is not configured")
	}
	repo, err := s.loadRepository(ctx, repositoryID)
	if err != nil {
		return false, err
	}
	// End/cancel cleanup stays possible for repositories that are not
	// enforcement-active, but nothing is synced or published for them.
	if !repo.EnforcementActive() {
		return false, nil
	}
	// Fail closed: an active repository always refreshes forge state first. If
	// the sync fails (missing token, forge error), no stale cached status is
	// recomputed or published.
	if err := s.syncer.SyncOpenPullRequests(ctx, repositoryID, ""); err != nil {
		return false, convergenceError(domain.EnforcementFailureOpenPRSync, fmt.Errorf("sync open pull requests for freeze recomputation: %w", err))
	}
	branchPRs, err := s.pullRequests.ListOpenByTargetBranch(ctx, repositoryID, branch)
	if err != nil {
		return false, convergenceError(domain.EnforcementFailureRuntime, fmt.Errorf("list cached open pull requests for freeze recomputation: %w", err))
	}
	// One decision per affected head SHA; the status runner expands each group
	// to every cached open PR in the repository sharing the head, including
	// cross-target-branch collisions.
	for _, group := range pullRequestsByHead(branchPRs) {
		current, err := currentRuntimeConvergenceClaim(ctx, s.convergence, claim)
		if err != nil {
			return false, convergenceError(domain.EnforcementFailureRuntime, err)
		}
		if !current {
			return false, nil
		}
		result, err := s.statuses.RunForSharedHead(ctx, group, group[0].Index)
		if err != nil {
			return false, convergenceError(domain.EnforcementFailureEvaluation, fmt.Errorf("recompute freeze status for cached pull requests: %w", err))
		}
		current, err = currentRuntimeConvergenceClaim(ctx, s.convergence, claim)
		if err != nil {
			return false, convergenceError(domain.EnforcementFailureRuntime, err)
		}
		if !current {
			return false, nil
		}
		if _, err := s.publisher.Publish(ctx, result); err != nil {
			return false, convergenceError(domain.EnforcementFailurePublication, fmt.Errorf("publish freeze status for cached pull requests: %w", err))
		}
	}
	return true, nil
}

func pullRequestsByHead(prs []domain.PullRequest) [][]domain.PullRequest {
	groups := make([][]domain.PullRequest, 0)
	indexByHead := make(map[string]int)
	for _, pr := range prs {
		if pr.HeadSHA == "" {
			continue
		}
		index, ok := indexByHead[pr.HeadSHA]
		if !ok {
			indexByHead[pr.HeadSHA] = len(groups)
			groups = append(groups, []domain.PullRequest{pr})
			continue
		}
		groups[index] = append(groups[index], pr)
	}
	return groups
}
