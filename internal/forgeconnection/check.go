package forgeconnection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const (
	// checkOverallDeadline bounds the whole observation run outside SQLite.
	checkOverallDeadline = 60 * time.Second
	// maxVisibleRepositories is the inventory work limit; the adapter
	// classifies anything larger as inventory_limit_exceeded.
	maxVisibleRepositories = 1000
)

// checkSnapshot is the reserved-check state carried between the reserve
// transaction, the network observation, and the persist transaction.
type checkSnapshot struct {
	connectionID              int64
	revision                  int64
	generation                int64
	baseURL                   string
	organizationSlug          string
	patCiphertext             []byte
	boundServiceUserRemoteID  string
	boundOrganizationRemoteID string
}

// Check runs one non-mutating connection check: reserve a generation,
// observe the credential-visible inventory outside SQLite, then persist the
// sanitized result only if the reservation is still current. The command is
// pinned to one never-reused connection id, so a stale form can never check
// a recreated connection. A stale generation commits no evidence, preview,
// immutable ID, or audit row; an interrupted run leaves the generation
// ahead of evidence, which the UI reports as "Check incomplete; run again."
func (s *Service) Check(ctx context.Context, actorUserID int64, expectedConnectionID, expectedRevision int64) (SetupCheck, error) {
	if s == nil || s.db == nil {
		return SetupCheck{}, errors.New("forge connection service has no database")
	}
	if s.secrets == nil {
		return SetupCheck{}, ErrConfiguration
	}
	if s.observer == nil {
		return SetupCheck{}, errors.New("forge connection observer is not configured")
	}

	snapshot, err := s.reserveCheck(ctx, actorUserID, expectedConnectionID, expectedRevision)
	if err != nil {
		return SetupCheck{}, err
	}

	observation, err := s.observe(ctx, snapshot)
	if err != nil {
		return SetupCheck{}, err
	}

	return s.persistCheck(ctx, actorUserID, snapshot, observation)
}

func (s *Service) reserveCheck(ctx context.Context, actorUserID int64, expectedConnectionID, expectedRevision int64) (checkSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return checkSnapshot{}, fmt.Errorf("begin forge connection check reservation: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return checkSnapshot{}, err
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return checkSnapshot{}, err
	}
	if !found {
		return checkSnapshot{}, ErrNoConnection
	}
	if record.ID != expectedConnectionID || record.Revision != expectedRevision {
		return checkSnapshot{}, ErrConflict
	}
	if record.CheckGeneration == math.MaxInt64 {
		return checkSnapshot{}, errors.New("forge connection check generation is exhausted")
	}
	newGeneration := record.CheckGeneration + 1
	reserved, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_connections
SET check_generation = ?
WHERE id = ? AND config_revision = ? AND check_generation = ?`,
		newGeneration,
		record.ID,
		record.Revision,
		record.CheckGeneration,
	)
	if err != nil {
		return checkSnapshot{}, fmt.Errorf("reserve forge connection check generation: %w", err)
	}
	if !reserved {
		return checkSnapshot{}, ErrConflict
	}
	snapshot := checkSnapshot{
		connectionID:             record.ID,
		revision:                 record.Revision,
		generation:               newGeneration,
		baseURL:                  record.BaseURL,
		organizationSlug:         record.OrganizationSlug,
		patCiphertext:            record.ServicePATCiphertext,
		boundServiceUserRemoteID: record.ServiceUserRemoteID,
	}
	if record.Organization != nil {
		snapshot.boundOrganizationRemoteID = record.Organization.RemoteID
	}
	// The reservation durably advances the check generation, so it carries
	// its own audit row in the same transaction: even a check that is later
	// interrupted (decrypt failure, malformed observation) leaves an atomic
	// record of the Administrator action with fixed metadata only.
	if err := recordCheckStarted(ctx, tx, actorUserID, snapshot); err != nil {
		return checkSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return checkSnapshot{}, ErrCheckOutcomeUnknown
	}
	return snapshot, nil
}

func recordCheckStarted(ctx context.Context, tx *sql.Tx, actorUserID int64, snapshot checkSnapshot) error {
	details, err := json.Marshal(struct {
		Revision   int64 `json:"revision"`
		Generation int64 `json:"generation"`
	}{Revision: snapshot.revision, Generation: snapshot.generation})
	if err != nil {
		return errors.New("encode forge connection check reservation audit evidence")
	}
	return recordForgeConnectionEvent(ctx, tx, actorUserID, audit.ActionForgeConnectionCheckStarted, snapshot.connectionID, string(details))
}

func (s *Service) observe(ctx context.Context, snapshot checkSnapshot) (Observation, error) {
	envelope, err := s.secrets.Decrypt(ctx, snapshot.patCiphertext)
	if err != nil {
		// Cause-neutral: a wrong key and a corrupt ciphertext read the same.
		return Observation{}, ErrCheckIncomplete
	}
	pat, err := unwrapServicePAT(envelope)
	if err != nil {
		return Observation{}, ErrCheckIncomplete
	}
	defer clearBytes(pat)

	runCtx, cancel := context.WithTimeout(ctx, checkOverallDeadline)
	defer cancel()
	observation := s.observer.Observe(runCtx, ObserveInput{
		BaseURL:                   snapshot.baseURL,
		OrganizationSlug:          snapshot.organizationSlug,
		PAT:                       pat,
		BoundServiceUserRemoteID:  snapshot.boundServiceUserRemoteID,
		BoundOrganizationRemoteID: snapshot.boundOrganizationRemoteID,
	})
	if err := validObservation(snapshot, observation); err != nil {
		return Observation{}, ErrCheckIncomplete
	}
	return observation, nil
}

// validObservation rejects adapter output that violates the observation
// contract before anything reaches SQLite.
func validObservation(snapshot checkSnapshot, observation Observation) error {
	malformed := errors.New("forge connection observation is malformed")
	if !observation.ResultCode.Valid() {
		return malformed
	}
	if observation.ObservedVersion != "" &&
		(len(observation.ObservedVersion) > 64 || !validRemoteName(observation.ObservedVersion)) {
		return malformed
	}
	if !observation.ResultCode.Observed() {
		return nil
	}
	if !validRemoteID(observation.ServiceUserRemoteID) ||
		!validRemoteID(observation.Organization.RemoteID) ||
		!validRemoteName(observation.Organization.Slug) ||
		!validRemoteName(observation.Organization.DisplayName) {
		return malformed
	}
	if snapshot.boundServiceUserRemoteID != "" && observation.ServiceUserRemoteID != snapshot.boundServiceUserRemoteID {
		return malformed
	}
	if snapshot.boundOrganizationRemoteID != "" && observation.Organization.RemoteID != snapshot.boundOrganizationRemoteID {
		return malformed
	}
	if len(observation.Repositories) > maxVisibleRepositories {
		return malformed
	}
	seen := make(map[string]struct{}, len(observation.Repositories))
	privateCount := 0
	for _, repository := range observation.Repositories {
		if !validRemoteID(repository.RemoteID) ||
			!validRemoteName(repository.Owner) ||
			!validRemoteName(repository.Name) ||
			!validRemoteName(repository.DefaultBranch) {
			return malformed
		}
		if _, duplicate := seen[repository.RemoteID]; duplicate {
			return malformed
		}
		seen[repository.RemoteID] = struct{}{}
		if repository.Private {
			privateCount++
		}
	}
	if observation.ResultCode == CheckVisibleInventoryObserved && privateCount == 0 {
		return malformed
	}
	if observation.ResultCode == CheckVisibleInventoryObservedPrivateReadUnproven && privateCount != 0 {
		return malformed
	}
	return nil
}

func (s *Service) persistCheck(
	ctx context.Context,
	actorUserID int64,
	snapshot checkSnapshot,
	observation Observation,
) (SetupCheck, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SetupCheck{}, fmt.Errorf("begin forge connection check persistence: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return SetupCheck{}, err
	}
	current, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return SetupCheck{}, err
	}
	if !found || current.ID != snapshot.connectionID ||
		current.Revision != snapshot.revision ||
		current.CheckGeneration != snapshot.generation ||
		current.BaseURL != snapshot.baseURL ||
		current.OrganizationSlug != snapshot.organizationSlug ||
		current.ServiceUserRemoteID != snapshot.boundServiceUserRemoteID ||
		currentOrganizationRemoteID(current) != snapshot.boundOrganizationRemoteID {
		return SetupCheck{}, ErrCheckStale
	}

	now := s.now().UTC()
	check := SetupCheck{
		ConfigRevision:  snapshot.revision,
		CheckGeneration: snapshot.generation,
		ResultCode:      observation.ResultCode,
		ObservedVersion: observation.ObservedVersion,
		CheckedAt:       now,
	}
	if observation.ResultCode.Observed() {
		visible := int64(len(observation.Repositories))
		privateVisible := int64(0)
		for _, repository := range observation.Repositories {
			if repository.Private {
				privateVisible++
			}
		}
		check.VisibleRepositoryCount = &visible
		check.VisiblePrivateRepositoryCount = &privateVisible

		if err := s.bindAndReplacePreview(ctx, tx, snapshot, current, observation, now); err != nil {
			return SetupCheck{}, err
		}
	}
	if err := replaceSetupCheckRow(ctx, tx, snapshot.connectionID, check); err != nil {
		return SetupCheck{}, err
	}
	if err := recordConnectionChecked(ctx, tx, actorUserID, snapshot.connectionID, check); err != nil {
		return SetupCheck{}, err
	}
	if err := tx.Commit(); err != nil {
		return SetupCheck{}, ErrCheckOutcomeUnknown
	}
	return check, nil
}

func currentOrganizationRemoteID(record connectionRecord) string {
	if record.Organization == nil {
		return ""
	}
	return record.Organization.RemoteID
}

// bindAndReplacePreview establishes the immutable identities on the first
// successful check, refreshes the mutable organization names afterwards, and
// atomically replaces the preview with the repositories visible at this
// check. Rows missing from the observation are removed; their disappearance
// is preview evidence only.
func (s *Service) bindAndReplacePreview(
	ctx context.Context,
	tx *sql.Tx,
	snapshot checkSnapshot,
	current connectionRecord,
	observation Observation,
	now time.Time,
) error {
	observedAt := formatForgeConnectionTime(now)
	if current.Organization == nil {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO forge_organizations(connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (?, ?, ?, ?, ?)`,
			snapshot.connectionID,
			observation.Organization.RemoteID,
			observation.Organization.Slug,
			observation.Organization.DisplayName,
			observedAt,
		); err != nil {
			return fmt.Errorf("bind forge organization: %w", err)
		}
	} else {
		updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_organizations
SET slug = ?, display_name = ?, observed_at = ?
WHERE connection_id = ? AND remote_organization_id = ?`,
			observation.Organization.Slug,
			observation.Organization.DisplayName,
			observedAt,
			snapshot.connectionID,
			observation.Organization.RemoteID,
		)
		if err != nil || !updated {
			return fmt.Errorf("refresh forge organization: %w", err)
		}
	}
	if current.ServiceUserRemoteID == "" {
		updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forgejo_connection_config
SET service_user_remote_id = ?
WHERE connection_id = ? AND service_user_remote_id IS NULL`,
			observation.ServiceUserRemoteID,
			snapshot.connectionID,
		)
		if err != nil || !updated {
			return fmt.Errorf("bind forge service user: %w", err)
		}
	}

	var organizationID int64
	if err := tx.QueryRowContext(ctx, `
SELECT id FROM forge_organizations WHERE connection_id = ?`, snapshot.connectionID).Scan(&organizationID); err != nil {
		return fmt.Errorf("resolve forge organization id: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM forge_visible_repositories WHERE connection_id = ?`, snapshot.connectionID); err != nil {
		return fmt.Errorf("replace forge visible repositories: %w", err)
	}
	for _, repository := range observation.Repositories {
		private := 0
		if repository.Private {
			private = 1
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO forge_visible_repositories(
  connection_id, organization_id, remote_repository_id, owner, name, default_branch,
  private, observed_check_generation, observed_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			snapshot.connectionID,
			organizationID,
			repository.RemoteID,
			repository.Owner,
			repository.Name,
			repository.DefaultBranch,
			private,
			snapshot.generation,
			observedAt,
		); err != nil {
			return fmt.Errorf("insert forge visible repository: %w", err)
		}
	}
	return nil
}

func replaceSetupCheckRow(ctx context.Context, tx *sql.Tx, connectionID int64, check SetupCheck) error {
	var observedVersion any
	if check.ObservedVersion != "" {
		observedVersion = check.ObservedVersion
	}
	var visibleCount, privateCount any
	if check.VisibleRepositoryCount != nil {
		visibleCount = *check.VisibleRepositoryCount
	}
	if check.VisiblePrivateRepositoryCount != nil {
		privateCount = *check.VisiblePrivateRepositoryCount
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO forge_connection_setup_checks(
  connection_id, config_revision, check_generation, result_code, observed_version,
  visible_repository_count, visible_private_repository_count, checked_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(connection_id) DO UPDATE SET
  config_revision = excluded.config_revision,
  check_generation = excluded.check_generation,
  result_code = excluded.result_code,
  observed_version = excluded.observed_version,
  visible_repository_count = excluded.visible_repository_count,
  visible_private_repository_count = excluded.visible_private_repository_count,
  checked_at = excluded.checked_at`,
		connectionID,
		check.ConfigRevision,
		check.CheckGeneration,
		string(check.ResultCode),
		observedVersion,
		visibleCount,
		privateCount,
		formatForgeConnectionTime(check.CheckedAt),
	); err != nil {
		return fmt.Errorf("replace forge connection check evidence: %w", err)
	}
	return nil
}

func recordConnectionChecked(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	connectionID int64,
	check SetupCheck,
) error {
	details, err := json.Marshal(struct {
		Revision     int64           `json:"revision"`
		Generation   int64           `json:"generation"`
		ResultCode   CheckResultCode `json:"result_code"`
		VisibleCount *int64          `json:"visible_count,omitempty"`
		PrivateCount *int64          `json:"private_count,omitempty"`
	}{
		Revision:     check.ConfigRevision,
		Generation:   check.CheckGeneration,
		ResultCode:   check.ResultCode,
		VisibleCount: check.VisibleRepositoryCount,
		PrivateCount: check.VisiblePrivateRepositoryCount,
	})
	if err != nil {
		return errors.New("encode forge connection check audit evidence")
	}
	return recordForgeConnectionEvent(ctx, tx, actorUserID, audit.ActionForgeConnectionChecked, connectionID, string(details))
}
