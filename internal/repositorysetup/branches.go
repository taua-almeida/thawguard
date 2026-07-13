package repositorysetup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

// EnforcementScopeLockedMessage rejects branch-scope changes for
// enforcement-active repositories: an active repository must never gain an
// unverified managed branch without an explicit deactivation step first.
const EnforcementScopeLockedMessage = "Deactivate repository enforcement before changing managed branches."

func (s *Service) ListBranches(ctx context.Context, repositoryID int64) ([]domain.RepositoryBranch, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("repository setup service has no database")
	}
	return repository.NewStore(s.db).ListBranches(ctx, repositoryID)
}

// AddBranch adds one exact managed branch and records the configuration
// change in the same transaction.
func (s *Service) AddBranch(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) (domain.RepositoryBranch, error) {
	if s == nil || s.db == nil {
		return domain.RepositoryBranch{}, errors.New("repository setup service has no database")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.RepositoryBranch{}, fmt.Errorf("begin managed branch add: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	repositoryStore := repository.NewStoreTx(tx)
	repo, err := s.branchScopeRepository(ctx, repositoryStore, repositoryID)
	if err != nil {
		return domain.RepositoryBranch{}, err
	}
	added, err := repositoryStore.AddBranch(ctx, repositoryID, branch)
	if err != nil {
		return domain.RepositoryBranch{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, repositoryBranchEvent(audit.ActionRepositoryBranchAdded, repo, added.Name, actor)); err != nil {
		return domain.RepositoryBranch{}, fmt.Errorf("record repository.branch_added audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.RepositoryBranch{}, fmt.Errorf("commit managed branch add: %w", err)
	}
	committed = true
	return added, nil
}

// RemoveBranch removes one safe non-default managed branch and records the
// configuration change in the same transaction.
func (s *Service) RemoveBranch(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error {
	if s == nil || s.db == nil {
		return errors.New("repository setup service has no database")
	}
	branch = strings.TrimSpace(branch)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin managed branch removal: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	repositoryStore := repository.NewStoreTx(tx)
	repo, err := s.branchScopeRepository(ctx, repositoryStore, repositoryID)
	if err != nil {
		return err
	}
	if branch == repo.DefaultBranch {
		return ValidationError{Message: "the default branch cannot be removed"}
	}
	blocked, err := repositoryStore.BranchHasBlockingFreeze(ctx, repositoryID, branch)
	if err != nil {
		return err
	}
	if blocked {
		return ValidationError{Message: "the branch has an active or scheduled freeze; end or cancel it before removing the branch"}
	}
	if err := repositoryStore.RemoveBranch(ctx, repositoryID, branch); err != nil {
		return err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, repositoryBranchEvent(audit.ActionRepositoryBranchRemoved, repo, branch, actor)); err != nil {
		return fmt.Errorf("record repository.branch_removed audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit managed branch removal: %w", err)
	}
	committed = true
	return nil
}

func (s *Service) branchScopeRepository(ctx context.Context, store *repository.Store, repositoryID int64) (domain.Repository, error) {
	repo, err := store.Get(ctx, repositoryID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Repository{}, ValidationError{Message: "repository not found"}
		}
		return domain.Repository{}, err
	}
	if repo.EnforcementActive() {
		return domain.Repository{}, ValidationError{Message: EnforcementScopeLockedMessage}
	}
	return repo, nil
}

func repositoryBranchEvent(action string, repo domain.Repository, branch string, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":    actor.Kind,
		"actor_role":    actor.Role,
		"repository_id": strconv.FormatInt(repo.ID, 10),
		"branch":        branch,
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      action,
		SubjectType: audit.SubjectTypeRepository,
		SubjectID:   strconv.FormatInt(repo.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}
