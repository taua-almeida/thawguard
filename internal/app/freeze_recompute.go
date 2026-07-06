package app

import (
	"context"
	"errors"
	"fmt"

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

type openPullRequestBranchLister interface {
	ListOpenByTargetBranch(ctx context.Context, repositoryID int64, targetBranch string) ([]domain.PullRequest, error)
}

type sharedHeadStatusRunner interface {
	RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error)
}

type statusPublisher interface {
	Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error)
}

type freezeRecomputingStore struct {
	freezes      freezeOperations
	pullRequests openPullRequestBranchLister
	syncer       openPullRequestSyncer
	statuses     sharedHeadStatusRunner
	publisher    statusPublisher
}

func newFreezeRecomputingStore(freezes freezeOperations, pullRequests openPullRequestBranchLister, statuses sharedHeadStatusRunner, publisher statusPublisher, syncers ...openPullRequestSyncer) *freezeRecomputingStore {
	var syncer openPullRequestSyncer
	if len(syncers) > 0 {
		syncer = syncers[0]
	}
	return &freezeRecomputingStore{freezes: freezes, pullRequests: pullRequests, syncer: syncer, statuses: statuses, publisher: publisher}
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
	created, err := s.freezes.CreateActive(ctx, params, actor)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := s.syncAndRecomputeBranch(ctx, created.RepositoryID, created.Branch); err != nil {
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
	if err := s.syncAndRecomputeBranch(ctx, ended.RepositoryID, ended.Branch); err != nil {
		return ended, err
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
	if err := s.syncAndRecomputeBranch(ctx, cancelled.RepositoryID, cancelled.Branch); err != nil {
		return cancelled, err
	}
	return cancelled, nil
}

func (s *freezeRecomputingStore) syncAndRecomputeBranch(ctx context.Context, repositoryID int64, branch string) error {
	var syncErr error
	if s.syncer != nil {
		syncErr = s.syncer.SyncOpenPullRequests(ctx, repositoryID, branch)
	}
	if err := s.recomputeBranch(ctx, repositoryID, branch); err != nil {
		return errors.Join(syncErr, err)
	}
	return syncErr
}

func (s *freezeRecomputingStore) recomputeBranch(ctx context.Context, repositoryID int64, branch string) error {
	if s == nil || s.pullRequests == nil || s.statuses == nil || s.publisher == nil {
		return errors.New("freeze recomputing store is not configured")
	}
	prs, err := s.pullRequests.ListOpenByTargetBranch(ctx, repositoryID, branch)
	if err != nil {
		return fmt.Errorf("list cached open pull requests for freeze recomputation: %w", err)
	}
	for _, group := range pullRequestsByHead(prs) {
		if len(group) == 0 {
			continue
		}
		result, err := s.statuses.RunForSharedHead(ctx, group, group[0].Index)
		if err != nil {
			return fmt.Errorf("recompute freeze status for cached pull requests: %w", err)
		}
		if _, err := s.publisher.Publish(ctx, result); err != nil {
			return fmt.Errorf("publish freeze status for cached pull requests: %w", err)
		}
	}
	return nil
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
