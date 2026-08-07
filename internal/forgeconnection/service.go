package forgeconnection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

// CheckObserver performs the non-mutating Forgejo observation for one
// reserved check, entirely outside SQLite. Implementations must never call
// a write endpoint and must never retain raw response data in the report.
type CheckObserver interface {
	Observe(ctx context.Context, input ObserveInput) Observation
}

// ObserveInput is the reserved-check snapshot an observer needs. PAT holds
// decrypted secret bytes; the observer must not retain them.
type ObserveInput struct {
	BaseURL          string
	OrganizationSlug string
	PAT              []byte
	// BoundServiceUserRemoteID and BoundOrganizationRemoteID are empty
	// before the first successful check binds the immutable identities.
	BoundServiceUserRemoteID  string
	BoundOrganizationRemoteID string
}

// Observation is the sanitized result of one observation run. Identity and
// repository fields are meaningful only when ResultCode is a success.
type Observation struct {
	ResultCode          CheckResultCode
	ObservedVersion     string
	ServiceUserRemoteID string
	Organization        ObservedOrganization
	Repositories        []ObservedRepository
}

type ObservedOrganization struct {
	RemoteID    string
	Slug        string
	DisplayName string
}

type ObservedRepository struct {
	RemoteID      string
	Owner         string
	Name          string
	DefaultBranch string
	Private       bool
}

type Service struct {
	db       *sql.DB
	secrets  secrets.Store
	observer CheckObserver
	now      func() time.Time
}

func NewService(db *sql.DB, secretStore secrets.Store, observer CheckObserver) *Service {
	return &Service{
		db:       db,
		secrets:  secretStore,
		observer: observer,
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Current(ctx context.Context) (Connection, bool, error) {
	if s == nil || s.db == nil {
		return Connection{}, false, errors.New("forge connection service has no database")
	}
	record, found, err := loadConnectionRecord(ctx, s.db)
	if err != nil || !found {
		return Connection{}, found, err
	}
	connection, err := publicConnection(record)
	if err != nil {
		return Connection{}, false, err
	}
	return connection, true, nil
}

// VisibleRepositories returns the retained preview rows for a connection,
// ordered by owner then name. The check-generation replacement protocol
// keeps every retained row at one observed generation.
func (s *Service) VisibleRepositories(ctx context.Context, connectionID int64) ([]VisibleRepository, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("forge connection service has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT remote_repository_id, owner, name, default_branch, private, observed_check_generation, observed_at
FROM forge_visible_repositories
WHERE connection_id = ?
ORDER BY owner, name, remote_repository_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read forge visible repositories: %w", err)
	}
	defer rows.Close()
	repositories := make([]VisibleRepository, 0)
	for rows.Next() {
		var repository VisibleRepository
		var private int64
		var observedAt string
		if err := rows.Scan(
			&repository.RemoteID,
			&repository.Owner,
			&repository.Name,
			&repository.DefaultBranch,
			&private,
			&repository.ObservedCheckGeneration,
			&observedAt,
		); err != nil {
			return nil, fmt.Errorf("scan forge visible repository: %w", err)
		}
		if private < 0 || private > 1 ||
			!validRemoteID(repository.RemoteID) ||
			!validRemoteName(repository.Owner) ||
			!validRemoteName(repository.Name) ||
			!validRemoteName(repository.DefaultBranch) ||
			repository.ObservedCheckGeneration <= 0 {
			return nil, errors.New("forge visible repository data is malformed")
		}
		repository.Private = private == 1
		repository.ObservedAt, err = parseForgeConnectionTime(observedAt)
		if err != nil {
			return nil, errors.New("forge visible repository data is malformed")
		}
		repositories = append(repositories, repository)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read forge visible repository rows: %w", err)
	}
	return repositories, nil
}

func (s *Service) Create(ctx context.Context, actorUserID int64, input CreateInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge connection service has no database")
	}
	normalized, err := normalizeConnectionInput(input.DisplayName, input.BaseURL, input.OrganizationSlug)
	if err != nil {
		return err
	}
	if err := validateServicePAT(input.ServicePAT); err != nil {
		return err
	}
	if !input.PATAttested {
		return ValidationError{Message: "confirm the read-only service PAT attestation before saving"}
	}
	if s.secrets == nil {
		return ErrConfiguration
	}
	ciphertext, err := encryptServicePAT(ctx, s.secrets, input.ServicePAT)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge connection creation: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	if _, found, err := loadConnectionRecord(ctx, tx); err != nil {
		return err
	} else if found {
		return ErrConflict
	}

	now := s.now().UTC()
	result, err := tx.ExecContext(ctx, `
INSERT INTO forge_connections(provider, display_name, base_url, config_revision, check_generation, created_at, updated_at)
VALUES (?, ?, ?, 1, 0, ?, ?)`,
		ProviderForgejo,
		normalized.displayName,
		normalized.baseURL,
		formatForgeConnectionTime(now),
		formatForgeConnectionTime(now),
	)
	if err != nil {
		return fmt.Errorf("insert forge connection: %w", err)
	}
	connectionID, err := result.LastInsertId()
	if err != nil || connectionID <= 0 {
		return errors.New("determine forge connection id")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO forgejo_connection_config(
  connection_id, organization_slug, service_pat_ciphertext, pat_attested_at, attested_by_user_id
)
VALUES (?, ?, ?, ?, ?)`,
		connectionID,
		normalized.organizationSlug,
		ciphertext,
		formatForgeConnectionTime(now),
		actorUserID,
	); err != nil {
		return fmt.Errorf("insert forgejo connection config: %w", err)
	}
	if err := recordConnectionSaved(ctx, tx, actorUserID, audit.ActionForgeConnectionCreated, connectionID, 1, true); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

func (s *Service) Edit(ctx context.Context, actorUserID int64, input EditInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge connection service has no database")
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedRevision <= 0 {
		return ValidationError{Message: "the expected connection id and revision must identify the connection being edited"}
	}
	normalized, err := normalizeConnectionInput(input.DisplayName, input.BaseURL, input.OrganizationSlug)
	if err != nil {
		return err
	}
	patReplaced := input.ReplacementPAT != ""
	if patReplaced {
		if err := validateServicePAT(input.ReplacementPAT); err != nil {
			return err
		}
		if !input.ReplacementPATAttested {
			return ValidationError{Message: "a replacement service PAT requires a fresh read-only attestation"}
		}
	}
	if s.secrets == nil {
		return ErrConfiguration
	}
	var replacementCiphertext []byte
	if patReplaced {
		replacementCiphertext, err = encryptServicePAT(ctx, s.secrets, input.ReplacementPAT)
		if err != nil {
			return err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge connection edit: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	existing, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || existing.ID != input.ExpectedConnectionID || existing.Revision != input.ExpectedRevision {
		return ErrConflict
	}
	if existing.bound() && (existing.BaseURL != normalized.baseURL || existing.OrganizationSlug != normalized.organizationSlug) {
		return ValidationError{Message: "the connection URL and organization are fixed once identities are bound; only the display name and PAT may change"}
	}
	// The stored write-only PAT was attested for one destination. Changing
	// the installation URL re-routes credential-bearing requests, so it
	// always requires a replacement PAT with a fresh attestation: the old
	// ciphertext is never decrypted for, or sent to, a destination it was
	// not attested for. Display-name and organization edits stay ordinary —
	// they never change where the credential is sent.
	if existing.BaseURL != normalized.baseURL && !patReplaced {
		return ValidationError{Message: "changing the installation URL requires a replacement service PAT attested for the new destination"}
	}
	if !patReplaced &&
		existing.DisplayName == normalized.displayName &&
		existing.BaseURL == normalized.baseURL &&
		existing.OrganizationSlug == normalized.organizationSlug {
		return nil
	}
	if existing.Revision == math.MaxInt64 {
		return errors.New("forge connection revision is exhausted")
	}

	now := s.now().UTC()
	if !now.After(existing.UpdatedAt) {
		now = existing.UpdatedAt.Add(time.Nanosecond)
	}
	newRevision := existing.Revision + 1
	updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_connections
SET display_name = ?, base_url = ?, config_revision = ?, updated_at = ?
WHERE id = ? AND config_revision = ?`,
		normalized.displayName,
		normalized.baseURL,
		newRevision,
		formatForgeConnectionTime(now),
		existing.ID,
		existing.Revision,
	)
	if err != nil {
		return fmt.Errorf("update forge connection: %w", err)
	}
	if !updated {
		return ErrConflict
	}
	if patReplaced {
		replaced, err := execExpectingOneRow(ctx, tx, `
UPDATE forgejo_connection_config
SET organization_slug = ?, service_pat_ciphertext = ?, pat_attested_at = ?, attested_by_user_id = ?
WHERE connection_id = ?`,
			normalized.organizationSlug,
			replacementCiphertext,
			formatForgeConnectionTime(now),
			actorUserID,
			existing.ID,
		)
		if err != nil || !replaced {
			return fmt.Errorf("replace forge connection service PAT: %w", err)
		}
	} else {
		replaced, err := execExpectingOneRow(ctx, tx, `
UPDATE forgejo_connection_config
SET organization_slug = ?
WHERE connection_id = ?`,
			normalized.organizationSlug,
			existing.ID,
		)
		if err != nil || !replaced {
			return fmt.Errorf("update forge connection organization: %w", err)
		}
	}
	if err := recordConnectionSaved(ctx, tx, actorUserID, audit.ActionForgeConnectionUpdated, existing.ID, newRevision, patReplaced); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

func (s *Service) Reset(ctx context.Context, actorUserID int64, input ResetInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge connection service has no database")
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedRevision <= 0 {
		return ValidationError{Message: "the expected connection id and revision must identify the connection being reset"}
	}
	if !input.ConfirmReset {
		return ValidationError{Message: "confirm the reset before deleting the connection"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge connection reset: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	existing, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || existing.ID != input.ExpectedConnectionID || existing.Revision != input.ExpectedRevision {
		return ErrConflict
	}
	deleted, err := execExpectingOneRow(ctx, tx, `DELETE FROM forge_connections WHERE id = ? AND config_revision = ?`, existing.ID, existing.Revision)
	if err != nil {
		return fmt.Errorf("delete forge connection: %w", err)
	}
	if !deleted {
		return ErrConflict
	}
	details, err := json.Marshal(struct {
		Revision int64 `json:"revision"`
	}{Revision: existing.Revision})
	if err != nil {
		return errors.New("encode forge connection reset audit evidence")
	}
	if err := recordForgeConnectionEvent(ctx, tx, actorUserID, audit.ActionForgeConnectionReset, existing.ID, string(details)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

type normalizedConnection struct {
	displayName      string
	baseURL          string
	organizationSlug string
}

func normalizeConnectionInput(displayName, baseURL, organizationSlug string) (normalizedConnection, error) {
	displayName, err := normalizeDisplayName(displayName)
	if err != nil {
		return normalizedConnection{}, err
	}
	baseURL, err = CanonicalBaseURL(baseURL)
	if err != nil {
		return normalizedConnection{}, err
	}
	organizationSlug, err = normalizeOrganizationSlug(organizationSlug)
	if err != nil {
		return normalizedConnection{}, err
	}
	return normalizedConnection{
		displayName:      displayName,
		baseURL:          baseURL,
		organizationSlug: organizationSlug,
	}, nil
}

func encryptServicePAT(ctx context.Context, store secrets.Store, pat string) ([]byte, error) {
	envelope := wrapServicePAT(pat)
	ciphertext, err := store.Encrypt(ctx, envelope)
	clearBytes(envelope)
	if err != nil || len(ciphertext) == 0 {
		return nil, errors.New("encrypt forge connection service PAT")
	}
	return ciphertext, nil
}

// connectionRecord is the internal load model, PAT ciphertext included. It
// never leaves this package.
type connectionRecord struct {
	ID                   int64
	Provider             string
	DisplayName          string
	BaseURL              string
	OrganizationSlug     string
	ServicePATCiphertext []byte
	ServiceUserRemoteID  string
	Revision             int64
	CheckGeneration      int64
	PATAttestedAt        time.Time
	Organization         *Organization
	SetupCheck           *SetupCheck
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

func (r connectionRecord) bound() bool {
	return r.ServiceUserRemoteID != "" && r.Organization != nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadConnectionRecord(ctx context.Context, q queryer) (connectionRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT c.id, c.provider, c.display_name, c.base_url, c.config_revision, c.check_generation,
  c.created_at, c.updated_at,
  fc.organization_slug, fc.service_pat_ciphertext, fc.service_user_remote_id, fc.pat_attested_at,
  o.remote_organization_id, o.slug, o.display_name, o.observed_at,
  sc.config_revision, sc.check_generation, sc.result_code, sc.observed_version,
  sc.visible_repository_count, sc.visible_private_repository_count, sc.checked_at
FROM forge_connections c
JOIN forgejo_connection_config fc ON fc.connection_id = c.id
LEFT JOIN forge_organizations o ON o.connection_id = c.id
LEFT JOIN forge_connection_setup_checks sc ON sc.connection_id = c.id
WHERE c.provider = ?`, ProviderForgejo)

	var record connectionRecord
	var createdAt, updatedAt, patAttestedAt string
	var serviceUserRemoteID sql.NullString
	var orgRemoteID, orgSlug, orgDisplayName, orgObservedAt sql.NullString
	var checkRevision, checkGeneration, visibleCount, privateCount sql.NullInt64
	var resultCode, observedVersion, checkedAt sql.NullString
	err := row.Scan(
		&record.ID,
		&record.Provider,
		&record.DisplayName,
		&record.BaseURL,
		&record.Revision,
		&record.CheckGeneration,
		&createdAt,
		&updatedAt,
		&record.OrganizationSlug,
		&record.ServicePATCiphertext,
		&serviceUserRemoteID,
		&patAttestedAt,
		&orgRemoteID,
		&orgSlug,
		&orgDisplayName,
		&orgObservedAt,
		&checkRevision,
		&checkGeneration,
		&resultCode,
		&observedVersion,
		&visibleCount,
		&privateCount,
		&checkedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return connectionRecord{}, false, nil
	}
	if err != nil {
		return connectionRecord{}, false, fmt.Errorf("read forge connection: %w", err)
	}
	malformed := func() (connectionRecord, bool, error) {
		return connectionRecord{}, false, errors.New("forge connection data is malformed")
	}
	record.CreatedAt, err = parseForgeConnectionTime(createdAt)
	if err != nil {
		return malformed()
	}
	record.UpdatedAt, err = parseForgeConnectionTime(updatedAt)
	if err != nil {
		return malformed()
	}
	record.PATAttestedAt, err = parseForgeConnectionTime(patAttestedAt)
	if err != nil {
		return malformed()
	}
	if serviceUserRemoteID.Valid {
		if !validRemoteID(serviceUserRemoteID.String) {
			return malformed()
		}
		record.ServiceUserRemoteID = serviceUserRemoteID.String
	}
	if orgRemoteID.Valid || orgSlug.Valid || orgDisplayName.Valid || orgObservedAt.Valid {
		if !orgRemoteID.Valid || !orgSlug.Valid || !orgDisplayName.Valid || !orgObservedAt.Valid {
			return malformed()
		}
		observedAt, parseErr := parseForgeConnectionTime(orgObservedAt.String)
		if parseErr != nil || !validRemoteID(orgRemoteID.String) ||
			!validRemoteName(orgSlug.String) || !validRemoteName(orgDisplayName.String) {
			return malformed()
		}
		record.Organization = &Organization{
			RemoteID:    orgRemoteID.String,
			Slug:        orgSlug.String,
			DisplayName: orgDisplayName.String,
			ObservedAt:  observedAt,
		}
	}
	if checkRevision.Valid || checkGeneration.Valid || resultCode.Valid || checkedAt.Valid {
		if !checkRevision.Valid || !checkGeneration.Valid || !resultCode.Valid || !checkedAt.Valid {
			return malformed()
		}
		parsedCheckedAt, parseErr := parseForgeConnectionTime(checkedAt.String)
		if parseErr != nil {
			return malformed()
		}
		check := &SetupCheck{
			ConfigRevision:  checkRevision.Int64,
			CheckGeneration: checkGeneration.Int64,
			ResultCode:      CheckResultCode(resultCode.String),
			CheckedAt:       parsedCheckedAt,
		}
		if observedVersion.Valid {
			check.ObservedVersion = observedVersion.String
		}
		if visibleCount.Valid {
			value := visibleCount.Int64
			check.VisibleRepositoryCount = &value
		}
		if privateCount.Valid {
			value := privateCount.Int64
			check.VisiblePrivateRepositoryCount = &value
		}
		if err := validateSetupCheckShape(*check); err != nil {
			return connectionRecord{}, false, err
		}
		record.SetupCheck = check
	}
	return record, true, nil
}

func validateSetupCheckShape(check SetupCheck) error {
	malformed := errors.New("forge connection check evidence is malformed")
	if check.ConfigRevision <= 0 || check.CheckGeneration <= 0 || !check.ResultCode.Valid() || check.CheckedAt.IsZero() {
		return malformed
	}
	if check.ResultCode.Observed() {
		if check.VisibleRepositoryCount == nil || check.VisiblePrivateRepositoryCount == nil {
			return malformed
		}
		if *check.VisibleRepositoryCount < 0 || *check.VisiblePrivateRepositoryCount < 0 ||
			*check.VisiblePrivateRepositoryCount > *check.VisibleRepositoryCount {
			return malformed
		}
		if check.ResultCode == CheckVisibleInventoryObserved && *check.VisiblePrivateRepositoryCount < 1 {
			return malformed
		}
		if check.ResultCode == CheckVisibleInventoryObservedPrivateReadUnproven && *check.VisiblePrivateRepositoryCount != 0 {
			return malformed
		}
		return nil
	}
	if check.VisibleRepositoryCount != nil || check.VisiblePrivateRepositoryCount != nil {
		return malformed
	}
	return nil
}

func publicConnection(record connectionRecord) (Connection, error) {
	displayName, displayErr := normalizeDisplayName(record.DisplayName)
	baseURL, urlErr := CanonicalBaseURL(record.BaseURL)
	organizationSlug, slugErr := normalizeOrganizationSlug(record.OrganizationSlug)
	if record.ID <= 0 || record.Provider != ProviderForgejo ||
		displayErr != nil || displayName != record.DisplayName ||
		urlErr != nil || baseURL != record.BaseURL ||
		slugErr != nil || organizationSlug != record.OrganizationSlug ||
		len(record.ServicePATCiphertext) == 0 ||
		record.Revision <= 0 || record.CheckGeneration < 0 ||
		record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() ||
		record.UpdatedAt.Before(record.CreatedAt) ||
		(record.ServiceUserRemoteID != "") != (record.Organization != nil) {
		return Connection{}, errors.New("forge connection data is malformed")
	}
	connection := Connection{
		ID:                  record.ID,
		Provider:            record.Provider,
		DisplayName:         record.DisplayName,
		BaseURL:             record.BaseURL,
		OrganizationSlug:    record.OrganizationSlug,
		Revision:            record.Revision,
		CheckGeneration:     record.CheckGeneration,
		PATAttestedAt:       record.PATAttestedAt,
		ServiceUserRemoteID: record.ServiceUserRemoteID,
		CreatedAt:           record.CreatedAt,
		UpdatedAt:           record.UpdatedAt,
	}
	if record.Organization != nil {
		organization := *record.Organization
		connection.Organization = &organization
	}
	if record.SetupCheck != nil {
		check := *record.SetupCheck
		if check.VisibleRepositoryCount != nil {
			value := *check.VisibleRepositoryCount
			check.VisibleRepositoryCount = &value
		}
		if check.VisiblePrivateRepositoryCount != nil {
			value := *check.VisiblePrivateRepositoryCount
			check.VisiblePrivateRepositoryCount = &value
		}
		connection.SetupCheck = &check
	}
	return connection, nil
}

// lockEnabledAdminActor takes the writer on the actor's user row and
// rechecks current enabled Administrator authority inside the transaction.
func lockEnabledAdminActor(ctx context.Context, tx *sql.Tx, actorUserID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, actorUserID); err != nil {
		return fmt.Errorf("lock forge connection actor: %w", err)
	}
	var allowed int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
  WHERE u.id = ? AND u.disabled_at IS NULL
)`, actorUserID).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize forge connection actor: %w", err)
	}
	if allowed != 1 {
		return ErrAuthorization
	}
	return nil
}

func execExpectingOneRow(ctx context.Context, tx *sql.Tx, query string, args ...any) (bool, error) {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected == 1, nil
}

func recordConnectionSaved(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	action string,
	connectionID int64,
	revision int64,
	patReplaced bool,
) error {
	details, err := json.Marshal(struct {
		Revision    int64 `json:"revision"`
		PATReplaced bool  `json:"pat_replaced"`
	}{Revision: revision, PATReplaced: patReplaced})
	if err != nil {
		return errors.New("encode forge connection audit evidence")
	}
	return recordForgeConnectionEvent(ctx, tx, actorUserID, action, connectionID, string(details))
}

func recordForgeConnectionEvent(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	action string,
	connectionID int64,
	detailsJSON string,
) error {
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      action,
		SubjectType: audit.SubjectTypeForgeConnection,
		SubjectID:   strconv.FormatInt(connectionID, 10),
		DetailsJSON: detailsJSON,
	}); err != nil {
		return fmt.Errorf("record forge connection audit event: %w", err)
	}
	return nil
}
