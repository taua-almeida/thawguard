package repositorysetup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

type Service struct {
	db *sql.DB
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) List(ctx context.Context) ([]domain.Repository, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("repository setup service has no database")
	}
	return repository.NewStore(s.db).List(ctx)
}

func (s *Service) Create(ctx context.Context, params repository.CreateParams, actor domain.Actor) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository setup service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("begin repository setup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	created, err := repository.NewStoreTx(tx).Create(ctx, params)
	if err != nil {
		return domain.Repository{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, repositoryCreatedEvent(created, actor)); err != nil {
		return domain.Repository{}, fmt.Errorf("record repository.created audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Repository{}, fmt.Errorf("commit repository setup: %w", err)
	}
	committed = true
	return created, nil
}

func repositoryCreatedEvent(repo domain.Repository, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":     actor.Kind,
		"actor_role":     actor.Role,
		"forge":          repo.Forge,
		"base_url":       redactURLUserInfo(repo.BaseURL),
		"owner":          repo.Owner,
		"name":           repo.Name,
		"full_name":      repo.FullName(),
		"default_branch": repo.DefaultBranch,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionRepositoryCreated,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repo.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func redactURLUserInfo(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	if parsed.Opaque != "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "[invalid URL]"
	}
	if parsed.User != nil {
		parsed.User = nil
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}
