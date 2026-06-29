package setupcheck

import (
	"context"
	"errors"
	"fmt"

	"github.com/taua-almeida/thawguard/internal/domain"
)

type Inspector interface {
	Inspect(ctx context.Context, repo domain.Repository) (Report, error)
}

type Service struct {
	store     *Store
	inspector Inspector
}

func NewService(store *Store, inspector Inspector) *Service {
	return &Service{store: store, inspector: inspector}
}

func (s *Service) Run(ctx context.Context, repo domain.Repository) ([]Result, error) {
	if s == nil || s.store == nil {
		return nil, errors.New("setup check service has no store")
	}
	if s.inspector == nil {
		return nil, errors.New("setup check service has no inspector")
	}

	report, err := s.inspector.Inspect(ctx, repo)
	if err != nil {
		return nil, fmt.Errorf("inspect repository setup: %w", err)
	}
	results := Evaluate(report)
	if err := s.store.Record(ctx, repo.ID, repo.DefaultBranch, results); err != nil {
		return nil, err
	}
	return results, nil
}
