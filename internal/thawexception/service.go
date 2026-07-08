package thawexception

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

func (s *Service) Approve(ctx context.Context, params ApproveParams, actor domain.Actor) (domain.ThawException, error) {
	if s == nil || s.db == nil {
		return domain.ThawException{}, errors.New("thaw exception service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ThawException{}, fmt.Errorf("begin thaw exception approval: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	approved, err := NewStoreTx(tx).Approve(ctx, params, actor)
	if err != nil {
		return domain.ThawException{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, thawExceptionApprovedEvent(approved, actor)); err != nil {
		return domain.ThawException{}, fmt.Errorf("record thaw_exception.approved audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.ThawException{}, fmt.Errorf("commit thaw exception approval: %w", err)
	}
	committed = true
	return approved, nil
}

func (s *Service) ActiveForPullRequest(ctx context.Context, pr domain.PullRequest) (*domain.ThawException, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("thaw exception service has no database")
	}
	return NewStore(s.db).ActiveForPullRequest(ctx, pr)
}

func thawExceptionApprovedEvent(thaw domain.ThawException, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":         actor.Kind,
		"actor_role":         actor.Role,
		"repository_id":      strconv.FormatInt(thaw.RepositoryID, 10),
		"pull_request_index": strconv.Itoa(thaw.PullRequestIndex),
		"target_branch":      thaw.TargetBranch,
		"head_sha":           thaw.HeadSHA,
		"reason":             thaw.Reason,
		"status":             thaw.Status,
	}
	if thaw.PullRequestURL != "" {
		details["pull_request_url"] = thaw.PullRequestURL
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionThawExceptionApproved,
		SubjectType: audit.SubjectTypeThawException,
		SubjectID:   strconv.FormatInt(thaw.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}
