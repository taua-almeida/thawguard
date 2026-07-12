package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
)

var ErrOpenPullRequestSyncStatusTokenMissing = errors.New("repository status token is not configured for open pull request sync")
var ErrOpenPullRequestSyncRepositoryNotAllowed = errors.New("repository is not enabled for open pull request sync")

type openPullRequestSyncer interface {
	SyncOpenPullRequests(ctx context.Context, repositoryID int64, targetBranch string) error
}

type openPullRequestRepositoryGetter interface {
	Get(ctx context.Context, id int64) (domain.Repository, error)
}

type openPullRequestStatusTokenGetter interface {
	StatusToken(ctx context.Context, repositoryID int64) (string, bool, error)
}

type openPullRequestUpserter interface {
	Upsert(ctx context.Context, pr domain.PullRequest) (domain.PullRequest, error)
	MarkAbsentOpenClosed(ctx context.Context, repositoryID int64, targetBranch string, openIndexes []int) (int64, error)
}

type openPullRequestForgeClient interface {
	ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error)
}

type openPullRequestForgeClientFactory func(repository domain.Repository, token string) (openPullRequestForgeClient, error)

type openPullRequestAuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
}

type forgeOpenPullRequestSyncer struct {
	repositories openPullRequestRepositoryGetter
	tokens       openPullRequestStatusTokenGetter
	pullRequests openPullRequestUpserter
	auditor      openPullRequestAuditRecorder
	allowedRepos map[string]struct{}
	clientFor    openPullRequestForgeClientFactory
}

func newForgeOpenPullRequestSyncer(repositories openPullRequestRepositoryGetter, tokens openPullRequestStatusTokenGetter, pullRequests openPullRequestUpserter, allowedRepositories []string, clientFor openPullRequestForgeClientFactory, auditors ...openPullRequestAuditRecorder) *forgeOpenPullRequestSyncer {
	var auditor openPullRequestAuditRecorder
	if len(auditors) > 0 {
		auditor = auditors[0]
	}
	return &forgeOpenPullRequestSyncer{repositories: repositories, tokens: tokens, pullRequests: pullRequests, auditor: auditor, allowedRepos: normalizedOpenPullRequestSyncAllowlist(allowedRepositories), clientFor: clientFor}
}

func (s *forgeOpenPullRequestSyncer) SyncOpenPullRequests(ctx context.Context, repositoryID int64, targetBranch string) error {
	if s == nil || s.repositories == nil || s.tokens == nil || s.pullRequests == nil || s.clientFor == nil {
		return errors.New("open pull request syncer is not configured")
	}
	targetBranch = strings.TrimSpace(targetBranch)
	if repositoryID <= 0 {
		return errors.New("missing required open pull request sync fields")
	}
	repo, err := s.repositories.Get(ctx, repositoryID)
	if err != nil {
		return fmt.Errorf("load repository for open pull request sync: %w", err)
	}
	if !s.repositoryAllowed(repo) {
		return ErrOpenPullRequestSyncRepositoryNotAllowed
	}
	token, found, err := s.tokens.StatusToken(ctx, repositoryID)
	if err != nil {
		return fmt.Errorf("load repository status token for open pull request sync: %w", err)
	}
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return ErrOpenPullRequestSyncStatusTokenMissing
	}
	client, err := s.clientFor(repo, token)
	if err != nil {
		return safeOpenPullRequestSyncError(fmt.Errorf("create forgejo pull request client: %w", err), token)
	}
	if client == nil {
		return errors.New("create forgejo pull request client: nil client")
	}
	prs, err := client.ListOpenPullRequests(ctx, repo.Owner, repo.Name, targetBranch)
	if err != nil {
		return safeOpenPullRequestSyncError(fmt.Errorf("list open pull requests from forge: %w", err), token)
	}
	openIndexes := make([]int, 0, len(prs))
	for _, pr := range prs {
		pr.RepositoryID = repositoryID
		if pr.TargetBranch == "" {
			pr.TargetBranch = targetBranch
		}
		if _, err := s.pullRequests.Upsert(ctx, pr); err != nil {
			return safeOpenPullRequestSyncError(fmt.Errorf("cache open pull request %d from forge: %w", pr.Index, err), token)
		}
		openIndexes = append(openIndexes, pr.Index)
	}
	closedAbsent, err := s.pullRequests.MarkAbsentOpenClosed(ctx, repositoryID, targetBranch, openIndexes)
	if err != nil {
		return safeOpenPullRequestSyncError(fmt.Errorf("close cached pull requests absent from forge open list: %w", err), token)
	}
	if s.auditor != nil {
		if err := s.auditor.Record(ctx, openPullRequestsSyncedEvent(repo, targetBranch, len(prs), closedAbsent)); err != nil {
			return fmt.Errorf("record open pull request sync audit event: %w", err)
		}
	}
	return nil
}

func openPullRequestsSyncedEvent(repo domain.Repository, targetBranch string, openCount int, closedAbsentCount int64) audit.Event {
	if targetBranch == "" {
		targetBranch = "all"
	}
	details := map[string]string{
		"repository_id":       strconv.FormatInt(repo.ID, 10),
		"full_name":           repo.FullName(),
		"target_branch":       targetBranch,
		"open_count":          strconv.Itoa(openCount),
		"closed_absent_count": strconv.FormatInt(closedAbsentCount, 10),
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		Action:      audit.ActionRepositoryOpenPullRequestsSynced,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repo.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func (s *forgeOpenPullRequestSyncer) repositoryAllowed(repo domain.Repository) bool {
	if len(s.allowedRepos) == 0 {
		return false
	}
	_, ok := s.allowedRepos[normalizeLiveStatusRepository(repo.FullName())]
	return ok
}

func normalizedOpenPullRequestSyncAllowlist(repositories []string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(repositories))
	for _, repository := range repositories {
		key := normalizeLiveStatusRepository(repository)
		if key != "" {
			allowed[key] = struct{}{}
		}
	}
	return allowed
}

func safeOpenPullRequestSyncError(cause error, sensitiveValues ...string) error {
	message := cause.Error()
	for _, sensitive := range sensitiveValues {
		sensitive = strings.TrimSpace(sensitive)
		if sensitive != "" {
			message = strings.ReplaceAll(message, sensitive, "[redacted]")
		}
	}
	return errors.New(message)
}
