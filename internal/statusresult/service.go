package statusresult

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/policy"
)

type FreezeLister interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
}

type Service struct {
	store   *Store
	freezes FreezeLister
}

type LocalDecisionParams struct {
	RepositoryID     int64
	PullRequestIndex int
	TargetBranch     string
	HeadSHA          string
}

func NewService(store *Store, freezes FreezeLister) *Service {
	return &Service{store: store, freezes: freezes}
}

func (s *Service) RunLocal(ctx context.Context, params LocalDecisionParams) (Result, error) {
	if s == nil || s.store == nil {
		return Result{}, errors.New("status result service has no store")
	}
	params = normalizeLocalDecisionParams(params)
	if err := validateLocalDecisionParams(params); err != nil {
		return Result{}, err
	}
	return s.RunForPullRequest(ctx, domain.PullRequest{
		ID:           int64(params.PullRequestIndex),
		RepositoryID: params.RepositoryID,
		Index:        params.PullRequestIndex,
		State:        "open",
		TargetBranch: params.TargetBranch,
		HeadSHA:      params.HeadSHA,
	})
}

func (s *Service) RunForPullRequest(ctx context.Context, pr domain.PullRequest) (Result, error) {
	if s == nil || s.store == nil {
		return Result{}, errors.New("status result service has no store")
	}
	pr = normalizePullRequest(pr)
	if err := validatePullRequest(pr); err != nil {
		return Result{}, err
	}
	decision, err := s.evaluate(ctx, pr)
	if err != nil {
		return Result{}, err
	}
	return s.create(ctx, pr, decision)
}

func (s *Service) RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (Result, error) {
	if s == nil || s.store == nil {
		return Result{}, errors.New("status result service has no store")
	}
	normalized, err := normalizeAndValidateSharedHead(prs)
	if err != nil {
		return Result{}, err
	}
	selected := preferredPullRequest(normalized, preferredIndex)
	selectedDecision, err := s.evaluate(ctx, selected)
	if err != nil {
		return Result{}, err
	}
	for _, pr := range normalized {
		decision, err := s.evaluate(ctx, pr)
		if err != nil {
			return Result{}, err
		}
		if decision.State != domain.CommitStatusSuccess {
			selected = pr
			selectedDecision = decision
			break
		}
	}
	return s.create(ctx, selected, selectedDecision)
}

func (s *Service) evaluate(ctx context.Context, pr domain.PullRequest) (policy.Decision, error) {
	activeFreeze, err := s.activeFreeze(ctx, pr.RepositoryID, pr.TargetBranch)
	if err != nil {
		return policy.Decision{}, err
	}
	return policy.Evaluate(policy.Input{PullRequest: pr, ActiveFreeze: activeFreeze}), nil
}

func (s *Service) create(ctx context.Context, pr domain.PullRequest, decision policy.Decision) (Result, error) {
	result, err := s.store.Create(ctx, CreateParams{
		RepositoryID:     pr.RepositoryID,
		PullRequestIndex: pr.Index,
		TargetBranch:     pr.TargetBranch,
		HeadSHA:          pr.HeadSHA,
		Context:          decision.Context,
		State:            decision.State,
		Description:      decision.Description,
	})
	if err != nil {
		return Result{}, err
	}
	return result, nil
}

func (s *Service) ListRecent(ctx context.Context, limit int) ([]Result, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("status result service has no store")
	}
	return s.store.ListRecent(ctx, limit)
}

func (s *Service) activeFreeze(ctx context.Context, repositoryID int64, targetBranch string) (*domain.BranchFreeze, error) {
	if s.freezes == nil {
		return nil, nil
	}
	freezes, err := s.freezes.ListActive(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active freezes for local decision: %w", err)
	}
	for i := range freezes {
		freeze := freezes[i]
		if freeze.RepositoryID == repositoryID && freeze.Branch == targetBranch && freeze.Active {
			return &freeze, nil
		}
	}
	return nil, nil
}

func normalizeLocalDecisionParams(params LocalDecisionParams) LocalDecisionParams {
	params.TargetBranch = strings.TrimSpace(params.TargetBranch)
	params.HeadSHA = strings.TrimSpace(params.HeadSHA)
	params.HeadSHA = strings.ToLower(params.HeadSHA)
	return params
}

func normalizePullRequest(pr domain.PullRequest) domain.PullRequest {
	pr.State = strings.ToLower(strings.TrimSpace(pr.State))
	pr.TargetBranch = strings.TrimSpace(pr.TargetBranch)
	pr.HeadSHA = strings.ToLower(strings.TrimSpace(pr.HeadSHA))
	if pr.State == "" {
		pr.State = "open"
	}
	return pr
}

func normalizeAndValidateSharedHead(prs []domain.PullRequest) ([]domain.PullRequest, error) {
	if len(prs) == 0 {
		return nil, ValidationError{Message: "no open pull requests share this head SHA"}
	}
	normalized := make([]domain.PullRequest, 0, len(prs))
	var repositoryID int64
	var headSHA string
	for _, pr := range prs {
		pr = normalizePullRequest(pr)
		if err := validatePullRequest(pr); err != nil {
			return nil, err
		}
		if !pr.IsOpen() {
			return nil, ValidationError{Message: "shared-head status recomputation requires open pull requests"}
		}
		if repositoryID == 0 {
			repositoryID = pr.RepositoryID
			headSHA = pr.HeadSHA
		}
		if pr.RepositoryID != repositoryID || pr.HeadSHA != headSHA {
			return nil, ValidationError{Message: "shared-head status recomputation requires one repository and head SHA"}
		}
		normalized = append(normalized, pr)
	}
	return normalized, nil
}

func preferredPullRequest(prs []domain.PullRequest, preferredIndex int) domain.PullRequest {
	for _, pr := range prs {
		if pr.Index == preferredIndex {
			return pr
		}
	}
	return prs[0]
}

func validateLocalDecisionParams(params LocalDecisionParams) error {
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
	if params.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required local decision fields: %s", strings.Join(missing, ", "))}
	}
	if params.PullRequestIndex > 1_000_000 {
		return ValidationError{Message: "pull request number is too large"}
	}
	if len(params.TargetBranch) > 255 || containsControl(params.TargetBranch) {
		return ValidationError{Message: "target branch is invalid"}
	}
	if len(params.HeadSHA) < 6 || len(params.HeadSHA) > 64 || containsControl(params.HeadSHA) || !isHex(params.HeadSHA) {
		return ValidationError{Message: "head SHA is invalid"}
	}
	return nil
}

func validatePullRequest(pr domain.PullRequest) error {
	return validateLocalDecisionParams(LocalDecisionParams{
		RepositoryID:     pr.RepositoryID,
		PullRequestIndex: pr.Index,
		TargetBranch:     pr.TargetBranch,
		HeadSHA:          pr.HeadSHA,
	})
}
