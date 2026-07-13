package repositorysetup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

type Service struct {
	db      *sql.DB
	secrets secrets.Store
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

// ActiveStatusTokenLockedMessage rejects status-token replacement for
// enforcement-active repositories: an untested token must never sit behind a
// healthy-looking active state, and there is no recovery flow yet.
const ActiveStatusTokenLockedMessage = "Deactivate repository enforcement before replacing the status token."

type ConfigurationError struct {
	Message string
}

func (e ConfigurationError) Error() string { return e.Message }

func IsConfigurationError(err error) bool {
	var configurationErr ConfigurationError
	return errors.As(err, &configurationErr)
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func NewServiceWithSecrets(db *sql.DB, secretStore secrets.Store) *Service {
	return &Service{db: db, secrets: secretStore}
}

func (s *Service) List(ctx context.Context) ([]domain.Repository, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("repository setup service has no database")
	}
	return repository.NewStore(s.db).List(ctx)
}

func (s *Service) FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, false, errors.New("repository setup service has no database")
	}
	return repository.NewStore(s.db).FindActiveByRemote(ctx, params)
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

func (s *Service) SetWebhookSecret(ctx context.Context, repositoryID int64, secret string, actor domain.Actor) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository setup service has no database")
	}
	if s.secrets == nil {
		return domain.Repository{}, ConfigurationError{Message: "webhook secret encryption key is not configured"}
	}
	if err := validateWebhookSecretParams(repositoryID, secret); err != nil {
		return domain.Repository{}, err
	}
	ciphertext, err := s.secrets.Encrypt(ctx, []byte(secret))
	if err != nil {
		return domain.Repository{}, fmt.Errorf("encrypt webhook secret: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("begin webhook secret setup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	repositoryStore := repository.NewStoreTx(tx)
	existing, err := repositoryStore.Get(ctx, repositoryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, ValidationError{Message: "repository not found"}
		}
		return domain.Repository{}, err
	}
	updated, err := repositoryStore.SetWebhookSecretCiphertext(ctx, repositoryID, ciphertext)
	if err != nil {
		return domain.Repository{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, repositoryWebhookSecretConfiguredEvent(updated, actor, existing.HasWebhookSecret)); err != nil {
		return domain.Repository{}, fmt.Errorf("record repository.webhook_secret_configured audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Repository{}, fmt.Errorf("commit webhook secret setup: %w", err)
	}
	committed = true
	return updated, nil
}

func (s *Service) WebhookSecret(ctx context.Context, repositoryID int64) (string, bool, error) {
	if s == nil || s.db == nil {
		return "", false, errors.New("repository setup service has no database")
	}
	if s.secrets == nil {
		return "", false, ConfigurationError{Message: "webhook secret encryption key is not configured"}
	}
	ciphertext, found, err := repository.NewStore(s.db).WebhookSecretCiphertext(ctx, repositoryID)
	if err != nil || !found {
		return "", found, err
	}
	plaintext, err := s.secrets.Decrypt(ctx, ciphertext)
	if err != nil {
		return "", false, fmt.Errorf("decrypt webhook secret: %w", err)
	}
	return string(plaintext), true, nil
}

func (s *Service) SetStatusToken(ctx context.Context, repositoryID int64, token string, actor domain.Actor) (domain.Repository, error) {
	if s == nil || s.db == nil {
		return domain.Repository{}, errors.New("repository setup service has no database")
	}
	if s.secrets == nil {
		return domain.Repository{}, ConfigurationError{Message: "status token encryption key is not configured"}
	}
	if err := validateStatusTokenParams(repositoryID, token); err != nil {
		return domain.Repository{}, err
	}
	ciphertext, err := s.secrets.Encrypt(ctx, []byte(token))
	if err != nil {
		return domain.Repository{}, fmt.Errorf("encrypt status token: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Repository{}, fmt.Errorf("begin status token setup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	repositoryStore := repository.NewStoreTx(tx)
	existing, err := repositoryStore.Get(ctx, repositoryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, ValidationError{Message: "repository not found"}
		}
		return domain.Repository{}, err
	}
	if existing.EnforcementActive() {
		return domain.Repository{}, ValidationError{Message: ActiveStatusTokenLockedMessage}
	}
	updated, err := repositoryStore.SetStatusTokenCiphertext(ctx, repositoryID, ciphertext)
	if err != nil {
		return domain.Repository{}, err
	}
	// A replaced token has never proven it can post statuses: clear the
	// verification evidence and drop a ready repository back to setup.
	updated, err = repositoryStore.SetStatusPostVerifiedAt(ctx, repositoryID, nil)
	if err != nil {
		return domain.Repository{}, err
	}
	if existing.EnforcementState == domain.EnforcementReady {
		updated, err = repositoryStore.SetEnforcementState(ctx, repositoryID, domain.EnforcementSetupIncomplete)
		if err != nil {
			return domain.Repository{}, err
		}
	}
	if err := audit.NewStoreTx(tx).Record(ctx, repositoryStatusTokenConfiguredEvent(updated, actor, existing.HasStatusToken)); err != nil {
		return domain.Repository{}, fmt.Errorf("record repository.status_token_configured audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.Repository{}, fmt.Errorf("commit status token setup: %w", err)
	}
	committed = true
	return updated, nil
}

func (s *Service) StatusToken(ctx context.Context, repositoryID int64) (string, bool, error) {
	if s == nil || s.db == nil {
		return "", false, errors.New("repository setup service has no database")
	}
	if s.secrets == nil {
		return "", false, ConfigurationError{Message: "status token encryption key is not configured"}
	}
	ciphertext, found, err := repository.NewStore(s.db).StatusTokenCiphertext(ctx, repositoryID)
	if err != nil || !found {
		return "", found, err
	}
	plaintext, err := s.secrets.Decrypt(ctx, ciphertext)
	if err != nil {
		return "", false, fmt.Errorf("decrypt status token: %w", err)
	}
	return string(plaintext), true, nil
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

func repositoryWebhookSecretConfiguredEvent(repo domain.Repository, actor domain.Actor, wasConfigured bool) audit.Event {
	details := map[string]string{
		"actor_kind":                    actor.Kind,
		"actor_role":                    actor.Role,
		"repository_id":                 strconv.FormatInt(repo.ID, 10),
		"forge":                         repo.Forge,
		"base_url":                      redactURLUserInfo(repo.BaseURL),
		"owner":                         repo.Owner,
		"name":                          repo.Name,
		"full_name":                     repo.FullName(),
		"webhook_secret_was_configured": strconv.FormatBool(wasConfigured),
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionRepositoryWebhookSecretConfigured,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repo.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func repositoryStatusTokenConfiguredEvent(repo domain.Repository, actor domain.Actor, wasConfigured bool) audit.Event {
	details := map[string]string{
		"actor_kind":                  actor.Kind,
		"actor_role":                  actor.Role,
		"repository_id":               strconv.FormatInt(repo.ID, 10),
		"forge":                       repo.Forge,
		"base_url":                    redactURLUserInfo(repo.BaseURL),
		"owner":                       repo.Owner,
		"name":                        repo.Name,
		"full_name":                   repo.FullName(),
		"status_token_was_configured": strconv.FormatBool(wasConfigured),
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionRepositoryStatusTokenConfigured,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repo.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

func validateWebhookSecretParams(repositoryID int64, secret string) error {
	if repositoryID <= 0 {
		return ValidationError{Message: "repository id is required"}
	}
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return ValidationError{Message: "webhook secret is required"}
	}
	if trimmed != secret {
		return ValidationError{Message: "webhook secret must not include leading or trailing whitespace"}
	}
	if len(secret) < 16 {
		return ValidationError{Message: "webhook secret must be at least 16 characters"}
	}
	if len(secret) > 512 {
		return ValidationError{Message: "webhook secret is too long"}
	}
	for _, r := range secret {
		if r < 0x20 || r == 0x7f {
			return ValidationError{Message: "webhook secret contains invalid characters"}
		}
	}
	return nil
}

func validateStatusTokenParams(repositoryID int64, token string) error {
	if repositoryID <= 0 {
		return ValidationError{Message: "repository id is required"}
	}
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return ValidationError{Message: "status token is required"}
	}
	if trimmed != token {
		return ValidationError{Message: "status token must not include leading or trailing whitespace"}
	}
	if len(token) < 16 {
		return ValidationError{Message: "status token must be at least 16 characters"}
	}
	if len(token) > 1024 {
		return ValidationError{Message: "status token is too long"}
	}
	for _, r := range token {
		if r < 0x20 || r == 0x7f {
			return ValidationError{Message: "status token contains invalid characters"}
		}
	}
	return nil
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
