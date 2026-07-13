package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
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
	CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error)
	CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListDueScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ActivateScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListDuePlannedUnfreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ExecutePlannedUnfreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	ListNeedsRecompute(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	MarkRecomputed(ctx context.Context, id int64) (domain.BranchFreeze, error)
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
	if _, err := s.recomputeBranch(ctx, created.RepositoryID, created.Branch); err != nil {
		return created, err
	}
	return created, nil
}

func (s *freezeRecomputingStore) End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, errors.New("freeze recomputing store has no freeze store")
	}
	ended, err := s.freezes.End(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	converged, err := s.recomputeBranch(ctx, ended.RepositoryID, ended.Branch)
	if err != nil {
		return ended, err
	}
	if converged {
		if err := s.markRecomputedIfNeeded(ctx, ended); err != nil {
			return ended, err
		}
	}
	return ended, nil
}

func (s *freezeRecomputingStore) Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.freezes == nil {
		return domain.BranchFreeze{}, errors.New("freeze recomputing store has no freeze store")
	}
	cancelled, err := s.freezes.Cancel(ctx, id, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	converged, err := s.recomputeBranch(ctx, cancelled.RepositoryID, cancelled.Branch)
	if err != nil {
		return cancelled, err
	}
	if converged {
		if err := s.markRecomputedIfNeeded(ctx, cancelled); err != nil {
			return cancelled, err
		}
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
	converged, err := s.recomputeBranch(ctx, activated.RepositoryID, activated.Branch)
	if err != nil {
		return activated, err
	}
	if converged {
		if _, err := lifecycle.MarkRecomputed(ctx, activated.ID); err != nil {
			return activated, err
		}
	}
	return activated, nil
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
	converged, err := s.recomputeBranch(ctx, ended.RepositoryID, ended.Branch)
	if err != nil {
		return ended, err
	}
	if converged {
		if _, err := lifecycle.MarkRecomputed(ctx, ended.ID); err != nil {
			return ended, err
		}
	}
	return ended, nil
}

func (s *freezeRecomputingStore) RetryRecompute(ctx context.Context, pending domain.BranchFreeze) error {
	lifecycle, err := s.freezeLifecycle()
	if err != nil {
		return err
	}
	converged, err := s.recomputeBranch(ctx, pending.RepositoryID, pending.Branch)
	if err != nil {
		return err
	}
	if !converged {
		return nil
	}
	_, err = lifecycle.MarkRecomputed(ctx, pending.ID)
	return err
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

func (s *freezeRecomputingStore) recomputeBranch(ctx context.Context, repositoryID int64, branch string) (bool, error) {
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
		return false, fmt.Errorf("sync open pull requests for freeze recomputation: %w", err)
	}
	branchPRs, err := s.pullRequests.ListOpenByTargetBranch(ctx, repositoryID, branch)
	if err != nil {
		return false, fmt.Errorf("list cached open pull requests for freeze recomputation: %w", err)
	}
	// One decision per affected head SHA; the status runner expands each group
	// to every cached open PR in the repository sharing the head, including
	// cross-target-branch collisions.
	for _, group := range pullRequestsByHead(branchPRs) {
		if len(group) == 0 {
			continue
		}
		result, err := s.statuses.RunForSharedHead(ctx, group, group[0].Index)
		if err != nil {
			return false, fmt.Errorf("recompute freeze status for cached pull requests: %w", err)
		}
		if _, err := s.publisher.Publish(ctx, result); err != nil {
			return false, fmt.Errorf("publish freeze status for cached pull requests: %w", err)
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
