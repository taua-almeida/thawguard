package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/thawexception"
)

type thawApprovalRepositoryGetter interface {
	Get(ctx context.Context, id int64) (domain.Repository, error)
}

type thawApprovalStatusTokenGetter interface {
	StatusToken(ctx context.Context, repositoryID int64) (string, bool, error)
}

type thawApprovalPullRequestCache interface {
	Upsert(ctx context.Context, pr domain.PullRequest) (domain.PullRequest, error)
	ListOpenByHead(ctx context.Context, repositoryID int64, headSHA string) ([]domain.PullRequest, error)
}

type thawApprovalExceptionApprover interface {
	Approve(ctx context.Context, params thawexception.ApproveParams, actor domain.Actor) (domain.ThawException, error)
}

type thawApprovalStatusRunner interface {
	ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error)
	RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error)
}

type thawApprovalForgeClient interface {
	GetPullRequest(ctx context.Context, owner, repo string, index int) (domain.PullRequest, error)
}

type thawApprovalForgeClientFactory func(repository domain.Repository, token string) (thawApprovalForgeClient, error)

type thawApprovalService struct {
	repositories thawApprovalRepositoryGetter
	tokens       thawApprovalStatusTokenGetter
	pullRequests thawApprovalPullRequestCache
	exceptions   thawApprovalExceptionApprover
	statuses     thawApprovalStatusRunner
	publisher    statusPublisher
	syncer       openPullRequestSyncer
	allowedRepos map[string]struct{}
	clientFor    thawApprovalForgeClientFactory
}

func newThawApprovalService(repositories thawApprovalRepositoryGetter, tokens thawApprovalStatusTokenGetter, pullRequests thawApprovalPullRequestCache, exceptions thawApprovalExceptionApprover, statuses thawApprovalStatusRunner, publisher statusPublisher, syncer openPullRequestSyncer, allowedRepositories []string, clientFor thawApprovalForgeClientFactory) *thawApprovalService {
	return &thawApprovalService{repositories: repositories, tokens: tokens, pullRequests: pullRequests, exceptions: exceptions, statuses: statuses, publisher: publisher, syncer: syncer, allowedRepos: normalizedOpenPullRequestSyncAllowlist(allowedRepositories), clientFor: clientFor}
}

func (s *thawApprovalService) ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error) {
	if s == nil || s.statuses == nil {
		return nil, errors.New("thaw approval service has no status runner")
	}
	return s.statuses.ListRecent(ctx, limit)
}

func (s *thawApprovalService) ApproveThaw(ctx context.Context, params statusresult.ThawApprovalParams, actor domain.Actor) (statusresult.Result, error) {
	if s == nil || s.repositories == nil || s.tokens == nil || s.pullRequests == nil || s.exceptions == nil || s.statuses == nil || s.publisher == nil || s.clientFor == nil {
		return statusresult.Result{}, errors.New("thaw approval service is not configured")
	}
	params = normalizeThawApprovalParams(params)
	if err := validateThawApprovalParams(params); err != nil {
		return statusresult.Result{}, err
	}

	repo, err := s.repositories.Get(ctx, params.RepositoryID)
	if err != nil {
		return statusresult.Result{}, fmt.Errorf("load repository for thaw approval: %w", err)
	}
	if !s.repositoryAllowed(repo) {
		return statusresult.Result{}, statusresult.ValidationError{Message: "repository is not enabled for live thaw approvals"}
	}
	token, found, err := s.tokens.StatusToken(ctx, params.RepositoryID)
	if err != nil {
		return statusresult.Result{}, fmt.Errorf("load repository status token for thaw approval: %w", err)
	}
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return statusresult.Result{}, statusresult.ValidationError{Message: "repository status token is not configured"}
	}
	client, err := s.clientFor(repo, token)
	if err != nil {
		return statusresult.Result{}, safeThawApprovalError(fmt.Errorf("create forgejo pull request client: %w", err), token)
	}
	if client == nil {
		return statusresult.Result{}, errors.New("create forgejo pull request client: nil client")
	}

	pr, err := client.GetPullRequest(ctx, repo.Owner, repo.Name, params.PullRequestIndex)
	if err != nil {
		return statusresult.Result{}, safeThawApprovalError(fmt.Errorf("fetch current pull request from forge: %w", err), token)
	}
	pr.RepositoryID = repo.ID
	pr = normalizeThawApprovalPullRequest(pr)
	if err := validateFetchedThawApprovalPullRequest(params, pr); err != nil {
		return statusresult.Result{}, err
	}
	if s.syncer != nil {
		if err := s.syncer.SyncOpenPullRequests(ctx, repo.ID, pr.TargetBranch); err != nil {
			return statusresult.Result{}, safeThawApprovalError(fmt.Errorf("sync open pull requests for thaw approval: %w", err), token)
		}
	}
	cached, err := s.pullRequests.Upsert(ctx, pr)
	if err != nil {
		return statusresult.Result{}, fmt.Errorf("cache thawed pull request: %w", err)
	}
	if _, err := s.exceptions.Approve(ctx, thawexception.ApproveParams{RepositoryID: repo.ID, PullRequestIndex: cached.Index, PullRequestURL: cached.URL, TargetBranch: cached.TargetBranch, HeadSHA: cached.HeadSHA, Reason: params.Reason}, actor); err != nil {
		if thawexception.IsValidationError(err) {
			return statusresult.Result{}, statusresult.ValidationError{Message: err.Error()}
		}
		return statusresult.Result{}, err
	}
	openPRs, err := s.openPullRequestsForHead(ctx, cached)
	if err != nil {
		return statusresult.Result{}, err
	}
	result, err := s.statuses.RunForSharedHead(ctx, openPRs, cached.Index)
	if err != nil {
		return statusresult.Result{}, err
	}
	if _, err := s.publisher.Publish(ctx, result); err != nil {
		return statusresult.Result{}, err
	}
	return result, nil
}

func (s *thawApprovalService) repositoryAllowed(repo domain.Repository) bool {
	if len(s.allowedRepos) == 0 {
		return false
	}
	_, ok := s.allowedRepos[normalizeLiveStatusRepository(repo.FullName())]
	return ok
}

func (s *thawApprovalService) openPullRequestsForHead(ctx context.Context, pr domain.PullRequest) ([]domain.PullRequest, error) {
	openPRs, err := s.pullRequests.ListOpenByHead(ctx, pr.RepositoryID, pr.HeadSHA)
	if err != nil {
		return nil, fmt.Errorf("list open pull requests for approved thaw: %w", err)
	}
	for _, existing := range openPRs {
		if existing.Index == pr.Index {
			return openPRs, nil
		}
	}
	if pr.IsOpen() {
		openPRs = append(openPRs, pr)
	}
	return openPRs, nil
}

func normalizeThawApprovalParams(params statusresult.ThawApprovalParams) statusresult.ThawApprovalParams {
	params.TargetBranch = strings.TrimSpace(params.TargetBranch)
	params.HeadSHA = strings.ToLower(strings.TrimSpace(params.HeadSHA))
	params.Reason = strings.TrimSpace(params.Reason)
	return params
}

func normalizeThawApprovalPullRequest(pr domain.PullRequest) domain.PullRequest {
	pr.State = strings.ToLower(strings.TrimSpace(pr.State))
	pr.TargetBranch = strings.TrimSpace(pr.TargetBranch)
	pr.HeadSHA = strings.ToLower(strings.TrimSpace(pr.HeadSHA))
	pr.Title = strings.TrimSpace(pr.Title)
	pr.URL = strings.TrimSpace(pr.URL)
	if pr.State == "" {
		pr.State = "open"
	}
	return pr
}

func validateThawApprovalParams(params statusresult.ThawApprovalParams) error {
	var missing []string
	if params.RepositoryID <= 0 {
		missing = append(missing, "repository")
	}
	if params.PullRequestIndex <= 0 {
		missing = append(missing, "pull request")
	}
	if params.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if params.Reason == "" {
		missing = append(missing, "reason")
	}
	if len(missing) > 0 {
		return statusresult.ValidationError{Message: fmt.Sprintf("missing required thaw approval fields: %s", strings.Join(missing, ", "))}
	}
	if params.PullRequestIndex > 1_000_000 {
		return statusresult.ValidationError{Message: "pull request number is too large"}
	}
	if len(params.TargetBranch) > 255 || containsControl(params.TargetBranch) {
		return statusresult.ValidationError{Message: "target branch is invalid"}
	}
	if params.HeadSHA != "" && (len(params.HeadSHA) < 6 || len(params.HeadSHA) > 64 || containsControl(params.HeadSHA) || !isHex(params.HeadSHA)) {
		return statusresult.ValidationError{Message: "head SHA is invalid"}
	}
	if len(params.Reason) > 500 || containsControl(params.Reason) {
		return statusresult.ValidationError{Message: "reason is invalid"}
	}
	return nil
}

func validateFetchedThawApprovalPullRequest(params statusresult.ThawApprovalParams, pr domain.PullRequest) error {
	var missing []string
	if pr.Index <= 0 {
		missing = append(missing, "pull request")
	}
	if pr.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if pr.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if len(missing) > 0 {
		return statusresult.ValidationError{Message: fmt.Sprintf("forge pull request is missing required fields: %s", strings.Join(missing, ", "))}
	}
	if pr.Index != params.PullRequestIndex {
		return statusresult.ValidationError{Message: "forge pull request number does not match the requested pull request"}
	}
	if !pr.IsOpen() {
		return statusresult.ValidationError{Message: "pull request is not open"}
	}
	if pr.TargetBranch != params.TargetBranch {
		return statusresult.ValidationError{Message: "pull request target branch no longer matches the requested branch"}
	}
	if params.HeadSHA != "" && pr.HeadSHA != params.HeadSHA {
		return statusresult.ValidationError{Message: "pull request head SHA no longer matches the requested head SHA"}
	}
	return nil
}

func safeThawApprovalError(cause error, sensitiveValues ...string) error {
	message := cause.Error()
	for _, sensitive := range sensitiveValues {
		sensitive = strings.TrimSpace(sensitive)
		if sensitive != "" {
			message = strings.ReplaceAll(message, sensitive, "[redacted]")
		}
	}
	return errors.New(message)
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isHex(value string) bool {
	for _, r := range value {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		return false
	}
	return true
}
