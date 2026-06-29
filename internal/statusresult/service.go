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

	activeFreeze, err := s.activeFreeze(ctx, params.RepositoryID, params.TargetBranch)
	if err != nil {
		return Result{}, err
	}
	decision := policy.Evaluate(policy.Input{PullRequest: domain.PullRequest{
		ID:           int64(params.PullRequestIndex),
		RepositoryID: params.RepositoryID,
		Index:        params.PullRequestIndex,
		State:        "open",
		TargetBranch: params.TargetBranch,
		HeadSHA:      params.HeadSHA,
	}, ActiveFreeze: activeFreeze})

	result, err := s.store.Create(ctx, CreateParams{
		RepositoryID:     params.RepositoryID,
		PullRequestIndex: params.PullRequestIndex,
		TargetBranch:     params.TargetBranch,
		HeadSHA:          params.HeadSHA,
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
