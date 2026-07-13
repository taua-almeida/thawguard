package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
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
	ApproveSharedHead(ctx context.Context, params thawexception.ApproveSharedHeadParams, actor domain.Actor) ([]domain.ThawException, error)
}

type thawApprovalFreezeLister interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
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
	freezes      thawApprovalFreezeLister
	statuses     thawApprovalStatusRunner
	publisher    statusPublisher
	syncer       openPullRequestSyncer
	clientFor    thawApprovalForgeClientFactory
	convergence  enforcementConvergence
}

func newThawApprovalService(repositories thawApprovalRepositoryGetter, tokens thawApprovalStatusTokenGetter, pullRequests thawApprovalPullRequestCache, exceptions thawApprovalExceptionApprover, freezes thawApprovalFreezeLister, statuses thawApprovalStatusRunner, publisher statusPublisher, syncer openPullRequestSyncer, clientFor thawApprovalForgeClientFactory) *thawApprovalService {
	return &thawApprovalService{repositories: repositories, tokens: tokens, pullRequests: pullRequests, exceptions: exceptions, freezes: freezes, statuses: statuses, publisher: publisher, syncer: syncer, clientFor: clientFor}
}

func (s *thawApprovalService) ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error) {
	if s == nil || s.statuses == nil {
		return nil, errors.New("thaw approval service has no status runner")
	}
	return s.statuses.ListRecent(ctx, limit)
}

func (s *thawApprovalService) ApproveThaw(ctx context.Context, params statusresult.ThawApprovalParams, actor domain.Actor) (statusresult.ThawApprovalOutcome, error) {
	if s == nil || s.repositories == nil || s.tokens == nil || s.pullRequests == nil || s.exceptions == nil || s.freezes == nil || s.statuses == nil || s.publisher == nil || s.syncer == nil || s.clientFor == nil {
		return statusresult.ThawApprovalOutcome{}, errors.New("thaw approval service is not configured")
	}
	params = normalizeThawApprovalParams(params)
	if err := validateThawApprovalParams(params); err != nil {
		return statusresult.ThawApprovalOutcome{}, err
	}

	repo, err := s.repositories.Get(ctx, params.RepositoryID)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, fmt.Errorf("load repository for thaw approval: %w", err)
	}
	// Reject before any forge fetch, exception, recompute, or publication.
	if !repo.EnforcementActive() {
		return statusresult.ThawApprovalOutcome{}, statusresult.ValidationError{Message: domain.EnforcementNotActiveMessage}
	}
	token, found, err := s.tokens.StatusToken(ctx, params.RepositoryID)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, fmt.Errorf("load repository status token for thaw approval: %w", err)
	}
	token = strings.TrimSpace(token)
	if !found || token == "" {
		return statusresult.ThawApprovalOutcome{}, statusresult.ValidationError{Message: "repository status token is not configured"}
	}
	client, err := s.clientFor(repo, token)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, safeThawApprovalError(fmt.Errorf("create forgejo pull request client: %w", err), token)
	}
	if client == nil {
		return statusresult.ThawApprovalOutcome{}, errors.New("create forgejo pull request client: nil client")
	}

	pr, err := client.GetPullRequest(ctx, repo.Owner, repo.Name, params.PullRequestIndex)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, safeThawApprovalError(fmt.Errorf("fetch current pull request from forge: %w", err), token)
	}
	pr.RepositoryID = repo.ID
	pr = normalizeThawApprovalPullRequest(pr)
	if err := validateFetchedThawApprovalPullRequest(params, pr); err != nil {
		return statusresult.ThawApprovalOutcome{}, err
	}
	if err := s.syncer.SyncOpenPullRequests(ctx, repo.ID, ""); err != nil {
		return statusresult.ThawApprovalOutcome{}, safeThawApprovalError(fmt.Errorf("sync open pull requests for thaw approval: %w", err), token)
	}
	cached, err := s.pullRequests.Upsert(ctx, pr)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, safeThawApprovalError(fmt.Errorf("cache thawed pull request: %w", err), token)
	}
	openPRs, err := s.openPullRequestsForHead(ctx, cached)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, safeThawApprovalError(err, token)
	}
	// Guard every path on the refreshed state: a thaw exists only to override
	// an active freeze, so if no current affected open PR targets a frozen
	// branch there is nothing to confirm, approve, record, or publish.
	frozenPRs, err := s.frozenPullRequests(ctx, openPRs)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, safeThawApprovalError(err, token)
	}
	if len(frozenPRs) == 0 {
		return statusresult.ThawApprovalOutcome{}, statusresult.ValidationError{Message: "No thaw is needed because none of the affected pull requests currently targets an actively frozen branch."}
	}
	if params.Confirmation != nil && !thawApprovalConfirmationMatches(*params.Confirmation, openPRs) {
		return thawApprovalConfirmationOutcome(openPRs), nil
	}
	if len(openPRs) > 1 && params.Confirmation == nil {
		return thawApprovalConfirmationOutcome(openPRs), nil
	}

	if len(openPRs) == 1 {
		if _, err := s.exceptions.Approve(ctx, thawApprovalExceptionParams(cached, params.Reason), actor); err != nil {
			return statusresult.ThawApprovalOutcome{}, thawApprovalExceptionError(err, token)
		}
	} else {
		exceptions := make([]thawexception.ApproveParams, 0, len(frozenPRs))
		for _, frozenPR := range frozenPRs {
			exceptions = append(exceptions, thawApprovalExceptionParams(frozenPR, params.Reason))
		}
		if _, err := s.exceptions.ApproveSharedHead(ctx, thawexception.ApproveSharedHeadParams{
			RepositoryID:               repo.ID,
			SelectedPullRequestIndex:   cached.Index,
			HeadSHA:                    cached.HeadSHA,
			Reason:                     params.Reason,
			AffectedPullRequestIndexes: pullRequestIndexes(openPRs),
			Exceptions:                 exceptions,
		}, actor); err != nil {
			return statusresult.ThawApprovalOutcome{}, thawApprovalExceptionError(err, token)
		}
	}
	var claim jobs.Job
	if s.convergence != nil {
		var claimed bool
		claim, claimed, err = s.convergence.Claim(ctx, repo.ID)
		if err != nil {
			return statusresult.ThawApprovalOutcome{}, err
		}
		if !claimed {
			return statusresult.ThawApprovalOutcome{}, nil
		}
	}
	current, err := currentRuntimeConvergenceClaim(ctx, s.convergence, claim)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, failRuntimeConvergence(ctx, s.convergence, claim, convergenceError(domain.EnforcementFailureRuntime, err))
	}
	if !current {
		return statusresult.ThawApprovalOutcome{}, nil
	}
	result, err := s.statuses.RunForSharedHead(ctx, openPRs, cached.Index)
	if err != nil {
		convergenceErr := convergenceError(domain.EnforcementFailureEvaluation, safeThawApprovalError(err, token))
		return statusresult.ThawApprovalOutcome{}, failRuntimeConvergence(ctx, s.convergence, claim, convergenceErr)
	}
	current, err = currentRuntimeConvergenceClaim(ctx, s.convergence, claim)
	if err != nil {
		return statusresult.ThawApprovalOutcome{}, failRuntimeConvergence(ctx, s.convergence, claim, convergenceError(domain.EnforcementFailureRuntime, err))
	}
	if !current {
		return statusresult.ThawApprovalOutcome{}, nil
	}
	if _, err := s.publisher.Publish(ctx, result); err != nil {
		convergenceErr := convergenceError(domain.EnforcementFailurePublication, safeThawApprovalError(err, token))
		return statusresult.ThawApprovalOutcome{}, failRuntimeConvergence(ctx, s.convergence, claim, convergenceErr)
	}
	if s.convergence != nil {
		if err := s.convergence.Complete(ctx, claim); err != nil {
			return statusresult.ThawApprovalOutcome{}, failRuntimeConvergence(ctx, s.convergence, claim, convergenceError(domain.EnforcementFailureRuntime, err))
		}
	}
	return statusresult.ThawApprovalOutcome{Result: &result}, nil
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

func (s *thawApprovalService) frozenPullRequests(ctx context.Context, prs []domain.PullRequest) ([]domain.PullRequest, error) {
	freezes, err := s.freezes.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active freezes for shared-head thaw approval: %w", err)
	}
	frozen := make([]domain.PullRequest, 0, len(prs))
	for _, pr := range prs {
		for _, activeFreeze := range freezes {
			if activeFreeze.Active && activeFreeze.RepositoryID == pr.RepositoryID && activeFreeze.Branch == pr.TargetBranch {
				frozen = append(frozen, pr)
				break
			}
		}
	}
	return frozen, nil
}

func thawApprovalExceptionParams(pr domain.PullRequest, reason string) thawexception.ApproveParams {
	return thawexception.ApproveParams{RepositoryID: pr.RepositoryID, PullRequestIndex: pr.Index, PullRequestURL: pr.URL, TargetBranch: pr.TargetBranch, HeadSHA: pr.HeadSHA, Reason: reason}
}

func thawApprovalExceptionError(err error, token string) error {
	if thawexception.IsValidationError(err) {
		return statusresult.ValidationError{Message: safeThawApprovalError(err, token).Error()}
	}
	return safeThawApprovalError(err, token)
}

func thawApprovalConfirmationOutcome(prs []domain.PullRequest) statusresult.ThawApprovalOutcome {
	affected := make([]statusresult.ThawApprovalPullRequest, 0, len(prs))
	for _, pr := range prs {
		affected = append(affected, statusresult.ThawApprovalPullRequest{Index: pr.Index, Title: pr.Title, TargetBranch: pr.TargetBranch, URL: pr.URL, HeadSHA: pr.HeadSHA})
	}
	confirmation := &statusresult.ThawApprovalConfirmation{HeadSHA: prs[0].HeadSHA, AffectedSignature: thawApprovalAffectedSignature(prs)}
	return statusresult.ThawApprovalOutcome{ConfirmationRequired: true, Confirmation: confirmation, AffectedPullRequests: affected}
}

func thawApprovalConfirmationMatches(confirmation statusresult.ThawApprovalConfirmation, prs []domain.PullRequest) bool {
	if len(prs) == 0 || confirmation.HeadSHA != prs[0].HeadSHA || confirmation.AffectedSignature != thawApprovalAffectedSignature(prs) {
		return false
	}
	return true
}

func thawApprovalAffectedSignature(prs []domain.PullRequest) string {
	canonical := append([]domain.PullRequest(nil), prs...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Index < canonical[j].Index })
	digest := sha256.New()
	for _, pr := range canonical {
		_, _ = fmt.Fprintf(digest, "%d\x00%s\n", pr.Index, pr.TargetBranch)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func pullRequestIndexes(prs []domain.PullRequest) []int {
	indexes := make([]int, 0, len(prs))
	for _, pr := range prs {
		indexes = append(indexes, pr.Index)
	}
	sort.Ints(indexes)
	return indexes
}

func normalizeThawApprovalParams(params statusresult.ThawApprovalParams) statusresult.ThawApprovalParams {
	params.TargetBranch = strings.TrimSpace(params.TargetBranch)
	params.HeadSHA = strings.ToLower(strings.TrimSpace(params.HeadSHA))
	params.Reason = strings.TrimSpace(params.Reason)
	if params.Confirmation != nil {
		confirmation := *params.Confirmation
		confirmation.HeadSHA = strings.ToLower(strings.TrimSpace(confirmation.HeadSHA))
		confirmation.AffectedSignature = strings.ToLower(strings.TrimSpace(confirmation.AffectedSignature))
		params.Confirmation = &confirmation
	}
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
	if params.Confirmation != nil {
		if len(params.Confirmation.HeadSHA) < 6 || len(params.Confirmation.HeadSHA) > 64 || containsControl(params.Confirmation.HeadSHA) || !isHex(params.Confirmation.HeadSHA) {
			return statusresult.ValidationError{Message: "confirmed head SHA is invalid"}
		}
		if len(params.Confirmation.AffectedSignature) != sha256.Size*2 || !isHex(params.Confirmation.AffectedSignature) {
			return statusresult.ValidationError{Message: "confirmed affected pull request signature is invalid"}
		}
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
