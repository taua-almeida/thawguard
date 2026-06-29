package freeze

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) ListActive(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("freeze service has no database")
	}
	return NewStore(s.db).ListActive(ctx)
}

func (s *Service) CreateActive(ctx context.Context, params CreateParams, actor domain.Actor) (domain.BranchFreeze, error) {
	if s == nil || s.db == nil {
		return domain.BranchFreeze{}, errors.New("freeze service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("begin freeze creation: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	params.CreatedByUserID = actor.UserID
	created, err := NewStoreTx(tx).CreateActive(ctx, params)
	if err != nil {
		return domain.BranchFreeze{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, branchFreezeCreatedEvent(created, actor)); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("record branch_freeze.created audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.BranchFreeze{}, fmt.Errorf("commit freeze creation: %w", err)
	}
	committed = true
	return created, nil
}

func branchFreezeCreatedEvent(freeze domain.BranchFreeze, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(freeze.RepositoryID, 10),
		"branch":        freeze.Branch,
		"status":        string(freeze.Status),
		"reason":        freeze.Reason,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionBranchFreezeCreated,
		SubjectType: audit.SubjectTypeBranchFreeze,
		SubjectID:   strconv.FormatInt(freeze.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}
