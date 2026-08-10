package forgeconnection

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

type repositoryLocator struct {
	owner string
	name  string
}

type localRepositoryRecord struct {
	id            int64
	forge         string
	baseURL       string
	owner         string
	name          string
	defaultBranch string
	active        bool
	createdAt     time.Time
}

func (r localRepositoryRecord) fullName() string {
	return r.owner + "/" + r.name
}

func (r localRepositoryRecord) canonicalCreatedAt() string {
	return r.createdAt.UTC().Format(time.RFC3339Nano)
}

type remoteRepositoryRecord struct {
	organizationID int64
	remoteID       string
	owner          string
	name           string
	defaultBranch  string
	private        bool
	generation     int64
	observedAt     time.Time
}

func (r remoteRepositoryRecord) locator() repositoryLocator {
	return repositoryLocator{owner: r.owner, name: r.name}
}

type repositoryBindingRecord struct {
	repositoryID   int64
	organizationID int64
	remoteID       string
}

type derivedRepositoryBindingRow struct {
	row      RepositoryBindingRow
	remoteID string
}

type repositoryBindingDerivation struct {
	model                   RepositoryBindingReadModel
	readyRemoteByRepository map[int64]remoteRepositoryRecord
	rows                    []derivedRepositoryBindingRow
}

// RepositoryBindings returns the combined local, retained-preview, and
// immutable-binding read model. All URL and alias matching stays here so web
// callers cannot accidentally derive a weaker identity rule.
func (s *Service) RepositoryBindings(ctx context.Context, connectionID int64) (RepositoryBindingReadModel, error) {
	if s == nil || s.db == nil {
		return RepositoryBindingReadModel{}, errors.New("forge connection service has no database")
	}
	if connectionID <= 0 {
		return RepositoryBindingReadModel{}, ValidationError{Message: "the Forge connection id is required"}
	}
	// One read transaction keeps the connection fences and every loaded row
	// at a single snapshot, so a bind or check committing between the loads
	// cannot render a torn model.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RepositoryBindingReadModel{}, fmt.Errorf("begin forge repository binding read: %w", err)
	}
	defer tx.Rollback()
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return RepositoryBindingReadModel{}, err
	}
	if !found || record.ID != connectionID {
		return RepositoryBindingReadModel{}, ErrNoConnection
	}
	locals, remotes, bindings, err := loadRepositoryBindingRecords(ctx, tx, connectionID)
	if err != nil {
		return RepositoryBindingReadModel{}, err
	}
	return deriveRepositoryBindings(record, locals, remotes, bindings).model, nil
}

func (s *Service) BindRepository(ctx context.Context, actorUserID int64, input BindRepositoryInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge connection service has no database")
	}
	createdAt, err := validateBindRepositoryInput(input)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge repository binding: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || record.ID != input.ExpectedConnectionID ||
		record.Revision != input.ExpectedConfigRevision ||
		record.CheckGeneration != input.ExpectedCheckGeneration ||
		record.BindingRevision != input.ExpectedBindingRevision {
		return ErrConflict
	}
	if record.BindingRevision == math.MaxInt64 {
		return errors.New("forge repository binding revision is exhausted")
	}

	locals, remotes, bindings, err := loadRepositoryBindingRecords(ctx, tx, record.ID)
	if err != nil {
		return err
	}
	derivation := deriveRepositoryBindings(record, locals, remotes, bindings)
	if !derivation.model.Current {
		return ErrBindingUnavailable
	}
	local, found := localRepositoryByID(locals, input.RepositoryID)
	if !found || !local.createdAt.Equal(createdAt) {
		return ErrConflict
	}
	remote, ready := derivation.readyRemoteByRepository[input.RepositoryID]
	if !ready {
		return ErrBindingUnavailable
	}

	var alreadyBound int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM forge_repository_bindings
  WHERE repository_id = ? OR (connection_id = ? AND remote_repository_id = ?)
)`, input.RepositoryID, record.ID, remote.remoteID).Scan(&alreadyBound); err != nil {
		return fmt.Errorf("check forge repository binding identities: %w", err)
	}
	if alreadyBound == 1 {
		return ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO forge_repository_bindings(
  repository_id, connection_id, organization_id, remote_repository_id
)
VALUES (?, ?, ?, ?)`,
		input.RepositoryID,
		record.ID,
		record.OrganizationID,
		remote.remoteID,
	); err != nil {
		return fmt.Errorf("insert forge repository binding: %w", err)
	}
	newBindingRevision := record.BindingRevision + 1
	updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_connections
SET binding_revision = ?
WHERE id = ? AND config_revision = ? AND check_generation = ? AND binding_revision = ?`,
		newBindingRevision,
		record.ID,
		record.Revision,
		record.CheckGeneration,
		record.BindingRevision,
	)
	if err != nil {
		return fmt.Errorf("increment forge repository binding revision: %w", err)
	}
	if !updated {
		return ErrConflict
	}
	if err := recordRepositoryBindingEvent(
		ctx,
		tx,
		actorUserID,
		audit.ActionForgeRepositoryBound,
		record,
		local,
		newBindingRevision,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrBindingOutcomeUnknown
	}
	return nil
}

func (s *Service) UnbindRepository(ctx context.Context, actorUserID int64, input UnbindRepositoryInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge connection service has no database")
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedConfigRevision <= 0 ||
		input.ExpectedBindingRevision < 0 || input.RepositoryID <= 0 {
		return ValidationError{Message: "the expected connection, binding, and repository ids are required"}
	}
	if !input.ConfirmUnbind {
		return ValidationError{Message: "confirm the repository unbind before continuing"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forge repository unbind: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	record, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || record.ID != input.ExpectedConnectionID ||
		record.Revision != input.ExpectedConfigRevision ||
		record.BindingRevision != input.ExpectedBindingRevision {
		return ErrConflict
	}
	if record.BindingRevision == math.MaxInt64 {
		return errors.New("forge repository binding revision is exhausted")
	}

	var createdAtText string
	if err := tx.QueryRowContext(ctx, `
SELECT r.created_at
FROM forge_repository_bindings b
JOIN repositories r ON r.id = b.repository_id
WHERE b.connection_id = ? AND b.repository_id = ?`,
		record.ID,
		input.RepositoryID,
	).Scan(&createdAtText); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		return fmt.Errorf("read forge repository binding: %w", err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdAtText)
	if err != nil {
		return errors.New("bound local repository creation timestamp is malformed")
	}
	local := localRepositoryRecord{id: input.RepositoryID, createdAt: createdAt}

	deleted, err := execExpectingOneRow(ctx, tx, `
DELETE FROM forge_repository_bindings
WHERE connection_id = ? AND repository_id = ?`, record.ID, input.RepositoryID)
	if err != nil {
		return fmt.Errorf("delete forge repository binding: %w", err)
	}
	if !deleted {
		return ErrConflict
	}
	newBindingRevision := record.BindingRevision + 1
	updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forge_connections
SET binding_revision = ?
WHERE id = ? AND config_revision = ? AND binding_revision = ?`,
		newBindingRevision,
		record.ID,
		record.Revision,
		record.BindingRevision,
	)
	if err != nil {
		return fmt.Errorf("increment forge repository binding revision: %w", err)
	}
	if !updated {
		return ErrConflict
	}
	if err := recordRepositoryBindingEvent(
		ctx,
		tx,
		actorUserID,
		audit.ActionForgeRepositoryUnbound,
		record,
		local,
		newBindingRevision,
	); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrBindingOutcomeUnknown
	}
	return nil
}

func validateBindRepositoryInput(input BindRepositoryInput) (time.Time, error) {
	if input.ExpectedConnectionID <= 0 || input.ExpectedConfigRevision <= 0 ||
		input.ExpectedCheckGeneration <= 0 || input.ExpectedBindingRevision < 0 ||
		input.RepositoryID <= 0 {
		return time.Time{}, ValidationError{Message: "the expected connection, check, binding, and repository ids are required"}
	}
	if !input.ConfirmBind {
		return time.Time{}, ValidationError{Message: "confirm the repository binding before continuing"}
	}
	createdAt, err := ParseRepositoryCreatedAt(input.RepositoryCreatedAt)
	if err != nil {
		return time.Time{}, ValidationError{Message: "the repository creation timestamp is malformed"}
	}
	return createdAt, nil
}

func loadRepositoryBindingRecords(
	ctx context.Context,
	q queryer,
	connectionID int64,
) ([]localRepositoryRecord, []remoteRepositoryRecord, []repositoryBindingRecord, error) {
	locals, err := loadLocalRepositoryRecords(ctx, q)
	if err != nil {
		return nil, nil, nil, err
	}
	remotes, err := loadRemoteRepositoryRecords(ctx, q, connectionID)
	if err != nil {
		return nil, nil, nil, err
	}
	bindings, err := loadRepositoryBindingRows(ctx, q, connectionID)
	if err != nil {
		return nil, nil, nil, err
	}
	return locals, remotes, bindings, nil
}

func loadLocalRepositoryRecords(ctx context.Context, q queryer) ([]localRepositoryRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT id, forge, base_url, owner, name, default_branch, active, created_at
FROM repositories
ORDER BY owner, name, id`)
	if err != nil {
		return nil, fmt.Errorf("read local repositories for forge binding: %w", err)
	}
	defer rows.Close()
	locals := make([]localRepositoryRecord, 0)
	for rows.Next() {
		var local localRepositoryRecord
		var active int64
		var createdAt string
		if err := rows.Scan(
			&local.id,
			&local.forge,
			&local.baseURL,
			&local.owner,
			&local.name,
			&local.defaultBranch,
			&active,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("scan local repository for forge binding: %w", err)
		}
		if local.id <= 0 || active < 0 || active > 1 {
			return nil, errors.New("local repository data is malformed")
		}
		local.createdAt, err = time.Parse(time.RFC3339Nano, createdAt)
		if err != nil {
			return nil, errors.New("local repository creation timestamp is malformed")
		}
		local.active = active == 1
		locals = append(locals, local)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read local repository rows for forge binding: %w", err)
	}
	return locals, nil
}

func loadRemoteRepositoryRecords(ctx context.Context, q queryer, connectionID int64) ([]remoteRepositoryRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT organization_id, remote_repository_id, owner, name, default_branch,
  private, observed_check_generation, observed_at
FROM forge_visible_repositories
WHERE connection_id = ?
ORDER BY owner, name, remote_repository_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read remote repositories for forge binding: %w", err)
	}
	defer rows.Close()
	remotes := make([]remoteRepositoryRecord, 0)
	for rows.Next() {
		var remote remoteRepositoryRecord
		var private int64
		var observedAt string
		if err := rows.Scan(
			&remote.organizationID,
			&remote.remoteID,
			&remote.owner,
			&remote.name,
			&remote.defaultBranch,
			&private,
			&remote.generation,
			&observedAt,
		); err != nil {
			return nil, fmt.Errorf("scan remote repository for forge binding: %w", err)
		}
		if remote.organizationID <= 0 || !validRemoteID(remote.remoteID) ||
			!validRemoteName(remote.owner) || !validRemoteName(remote.name) ||
			!validRemoteName(remote.defaultBranch) || private < 0 || private > 1 ||
			remote.generation <= 0 {
			return nil, errors.New("forge visible repository data is malformed")
		}
		remote.observedAt, err = parseForgeConnectionTime(observedAt)
		if err != nil {
			return nil, errors.New("forge visible repository data is malformed")
		}
		remote.private = private == 1
		remotes = append(remotes, remote)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read remote repository rows for forge binding: %w", err)
	}
	return remotes, nil
}

func loadRepositoryBindingRows(ctx context.Context, q queryer, connectionID int64) ([]repositoryBindingRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT repository_id, organization_id, remote_repository_id
FROM forge_repository_bindings
WHERE connection_id = ?
ORDER BY repository_id`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("read forge repository bindings: %w", err)
	}
	defer rows.Close()
	bindings := make([]repositoryBindingRecord, 0)
	for rows.Next() {
		var binding repositoryBindingRecord
		if err := rows.Scan(
			&binding.repositoryID,
			&binding.organizationID,
			&binding.remoteID,
		); err != nil {
			return nil, fmt.Errorf("scan forge repository binding: %w", err)
		}
		if binding.repositoryID <= 0 || binding.organizationID <= 0 || !validRemoteID(binding.remoteID) {
			return nil, errors.New("forge repository binding data is malformed")
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read forge repository binding rows: %w", err)
	}
	return bindings, nil
}

func deriveRepositoryBindings(
	connection connectionRecord,
	locals []localRepositoryRecord,
	remotes []remoteRepositoryRecord,
	bindings []repositoryBindingRecord,
) repositoryBindingDerivation {
	derivation := repositoryBindingDerivation{
		model: RepositoryBindingReadModel{
			Current: currentRepositoryBindingEvidence(connection, remotes),
			Rows:    make([]RepositoryBindingRow, 0, len(bindings)+len(remotes)),
		},
		readyRemoteByRepository: make(map[int64]remoteRepositoryRecord),
		rows:                    make([]derivedRepositoryBindingRow, 0, len(bindings)+len(remotes)),
	}
	localsByID := make(map[int64]localRepositoryRecord, len(locals))
	localsByLocator := make(map[repositoryLocator][]localRepositoryRecord)
	for _, local := range locals {
		localsByID[local.id] = local
		if locator, ok := localRepositoryLocator(connection.BaseURL, local); ok {
			localsByLocator[locator] = append(localsByLocator[locator], local)
		}
	}
	remotesByID := make(map[string]remoteRepositoryRecord, len(remotes))
	remotesByLocator := make(map[repositoryLocator][]remoteRepositoryRecord)
	for _, remote := range remotes {
		remotesByID[remote.remoteID] = remote
		remotesByLocator[remote.locator()] = append(remotesByLocator[remote.locator()], remote)
	}

	boundRepositories := make(map[int64]bool, len(bindings))
	for _, binding := range bindings {
		boundRepositories[binding.repositoryID] = true
	}

	consumed := make(map[string]bool, len(remotes))
	for _, binding := range bindings {
		local, found := localsByID[binding.repositoryID]
		if !found {
			continue
		}
		row := RepositoryBindingRow{}
		applyLocalRepository(&row, local)

		boundRemote, boundVisible := remotesByID[binding.remoteID]
		if !derivation.model.Current {
			row.State = RepositoryBindingLastObservedOnly
			if boundVisible {
				applyRemoteRepositoryGroup(&row, []remoteRepositoryRecord{boundRemote})
				consumed[boundRemote.remoteID] = true
			}
			appendDerivedRepositoryBindingRow(&derivation, row, binding.remoteID)
			continue
		}

		localLocator, localCompatible := localRepositoryLocator(connection.BaseURL, local)
		localMatches := localsByLocator[localLocator]
		localRemoteGroup := remotesByLocator[localLocator]
		var boundRemoteGroup []remoteRepositoryRecord
		if boundVisible {
			boundRemoteGroup = remotesByLocator[boundRemote.locator()]
		}
		identityConflict := binding.organizationID != connection.OrganizationID
		if localCompatible && (len(localMatches) != 1 || localMatches[0].id != local.id) {
			identityConflict = true
		}
		for _, remote := range localRemoteGroup {
			if remote.remoteID != binding.remoteID {
				identityConflict = true
				break
			}
		}
		if len(boundRemoteGroup) > 1 {
			identityConflict = true
		}

		for _, remote := range localRemoteGroup {
			consumed[remote.remoteID] = true
		}
		for _, remote := range boundRemoteGroup {
			consumed[remote.remoteID] = true
		}
		switch {
		case identityConflict:
			row.State = RepositoryBindingIdentityConflict
			// Prefer the identities colliding at the local locator. If the
			// local locator drifted away from every visible identity, the
			// bound identity's current locator is the conflict evidence.
			conflictGroup := localRemoteGroup
			additionalGroup := boundRemoteGroup
			if len(conflictGroup) == 0 {
				conflictGroup = boundRemoteGroup
				additionalGroup = localRemoteGroup
			}
			applyRemoteRepositoryGroup(&row, conflictGroup)
			appendRemoteRepositoryFullNames(&row, additionalGroup)
		case boundVisible && (!localCompatible || boundRemote.locator() != localLocator):
			row.State = RepositoryBindingLocatorDrift
			applyRemoteRepositoryGroup(&row, []remoteRepositoryRecord{boundRemote})
		case boundVisible:
			row.State = RepositoryBindingCurrent
			applyRemoteRepositoryGroup(&row, []remoteRepositoryRecord{boundRemote})
		default:
			row.State = RepositoryBindingNotVisible
		}
		appendDerivedRepositoryBindingRow(&derivation, row, binding.remoteID)
	}

	if !derivation.model.Current {
		for _, remote := range remotes {
			if consumed[remote.remoteID] {
				continue
			}
			row := RepositoryBindingRow{State: RepositoryBindingPreviewNotCurrent}
			applyRemoteRepositoryGroup(&row, []remoteRepositoryRecord{remote})
			localMatches := localsByLocator[remote.locator()]
			if len(localMatches) == 1 && !boundRepositories[localMatches[0].id] {
				applyLocalRepository(&row, localMatches[0])
			}
			appendDerivedRepositoryBindingRow(&derivation, row, remote.remoteID)
		}
		finishRepositoryBindingRows(&derivation)
		return derivation
	}

	locators := make([]repositoryLocator, 0, len(remotesByLocator))
	for locator := range remotesByLocator {
		locators = append(locators, locator)
	}
	sort.Slice(locators, func(i, j int) bool {
		if locators[i].owner != locators[j].owner {
			return locators[i].owner < locators[j].owner
		}
		return locators[i].name < locators[j].name
	})
	for _, locator := range locators {
		group := unconsumedRemoteRepositories(remotesByLocator[locator], consumed)
		if len(group) == 0 {
			continue
		}
		row := RepositoryBindingRow{}
		applyRemoteRepositoryGroup(&row, group)
		localMatches := localsByLocator[locator]
		switch {
		case len(group) > 1:
			row.State = RepositoryBindingDuplicateRemoteLocator
		case len(localMatches) > 1:
			row.State = RepositoryBindingMultipleLocalMatches
		case len(localMatches) == 1:
			row.State = RepositoryBindingReady
			applyLocalRepository(&row, localMatches[0])
			derivation.readyRemoteByRepository[localMatches[0].id] = group[0]
		default:
			row.State = RepositoryBindingUnmatched
		}
		appendDerivedRepositoryBindingRow(&derivation, row, smallestRemoteRepositoryID(group))
	}
	finishRepositoryBindingRows(&derivation)
	return derivation
}

func currentRepositoryBindingEvidence(connection connectionRecord, remotes []remoteRepositoryRecord) bool {
	check := connection.SetupCheck
	if check == nil || connection.Organization == nil || connection.OrganizationID <= 0 ||
		check.ConfigRevision != connection.Revision ||
		check.CheckGeneration != connection.CheckGeneration ||
		!check.ResultCode.Observed() ||
		check.VisibleRepositoryCount == nil || check.VisiblePrivateRepositoryCount == nil ||
		*check.VisibleRepositoryCount != int64(len(remotes)) {
		return false
	}
	privateCount := int64(0)
	for _, remote := range remotes {
		if remote.generation != connection.CheckGeneration || remote.organizationID != connection.OrganizationID {
			return false
		}
		if remote.private {
			privateCount++
		}
	}
	return privateCount == *check.VisiblePrivateRepositoryCount
}

func localRepositoryLocator(connectionBaseURL string, local localRepositoryRecord) (repositoryLocator, bool) {
	switch strings.ToLower(strings.TrimSpace(local.forge)) {
	case "", "forgejo", "codeberg":
	default:
		return repositoryLocator{}, false
	}
	baseURL, err := CanonicalBaseURL(local.baseURL)
	if err != nil || baseURL != connectionBaseURL {
		return repositoryLocator{}, false
	}
	return repositoryLocator{owner: local.owner, name: local.name}, true
}

func applyLocalRepository(row *RepositoryBindingRow, local localRepositoryRecord) {
	row.RepositoryID = local.id
	row.RepositoryCreatedAt = local.canonicalCreatedAt()
	row.LocalFullName = local.fullName()
	row.LocalDefaultBranch = local.defaultBranch
	row.LocalActive = local.active
}

func applyRemoteRepositoryGroup(row *RepositoryBindingRow, group []remoteRepositoryRecord) {
	if len(group) == 0 {
		return
	}
	first := group[0]
	row.RemoteFullName = first.owner + "/" + first.name
	row.RemoteFullNames = []string{row.RemoteFullName}
	row.RemoteDefaultBranch = first.defaultBranch
	private := first.private
	row.RemotePrivate = &private
	row.ObservedAt = first.observedAt
	for _, remote := range group[1:] {
		if fullName := remote.owner + "/" + remote.name; !slices.Contains(row.RemoteFullNames, fullName) {
			row.RemoteFullNames = append(row.RemoteFullNames, fullName)
		}
		if remote.locator() != first.locator() {
			row.RemoteFullName = ""
		}
		if remote.defaultBranch != first.defaultBranch {
			row.RemoteDefaultBranch = ""
		}
		if remote.private != first.private {
			row.RemotePrivate = nil
		}
	}
}

func appendRemoteRepositoryFullNames(row *RepositoryBindingRow, group []remoteRepositoryRecord) {
	for _, remote := range group {
		fullName := remote.owner + "/" + remote.name
		if !slices.Contains(row.RemoteFullNames, fullName) {
			row.RemoteFullNames = append(row.RemoteFullNames, fullName)
		}
	}
}

func unconsumedRemoteRepositories(group []remoteRepositoryRecord, consumed map[string]bool) []remoteRepositoryRecord {
	remaining := make([]remoteRepositoryRecord, 0, len(group))
	for _, remote := range group {
		if !consumed[remote.remoteID] {
			remaining = append(remaining, remote)
		}
	}
	return remaining
}

func localRepositoryByID(locals []localRepositoryRecord, repositoryID int64) (localRepositoryRecord, bool) {
	for _, local := range locals {
		if local.id == repositoryID {
			return local, true
		}
	}
	return localRepositoryRecord{}, false
}

func appendDerivedRepositoryBindingRow(
	derivation *repositoryBindingDerivation,
	row RepositoryBindingRow,
	remoteID string,
) {
	derivation.rows = append(derivation.rows, derivedRepositoryBindingRow{row: row, remoteID: remoteID})
}

func finishRepositoryBindingRows(derivation *repositoryBindingDerivation) {
	sort.SliceStable(derivation.rows, func(i, j int) bool {
		first, second := derivation.rows[i], derivation.rows[j]
		firstName := repositoryBindingPrimaryFullName(first.row)
		secondName := repositoryBindingPrimaryFullName(second.row)
		if firstName != secondName {
			return firstName < secondName
		}
		if first.row.RepositoryID != second.row.RepositoryID {
			return first.row.RepositoryID < second.row.RepositoryID
		}
		return first.remoteID < second.remoteID
	})
	derivation.model.Rows = make([]RepositoryBindingRow, 0, len(derivation.rows))
	for _, derived := range derivation.rows {
		derivation.model.Rows = append(derivation.model.Rows, derived.row)
	}
}

func repositoryBindingPrimaryFullName(row RepositoryBindingRow) string {
	if row.RemoteFullName != "" {
		return row.RemoteFullName
	}
	if row.LocalFullName != "" {
		return row.LocalFullName
	}
	if len(row.RemoteFullNames) > 0 {
		return row.RemoteFullNames[0]
	}
	return ""
}

func smallestRemoteRepositoryID(group []remoteRepositoryRecord) string {
	if len(group) == 0 {
		return ""
	}
	remoteID := group[0].remoteID
	for _, remote := range group[1:] {
		if remote.remoteID < remoteID {
			remoteID = remote.remoteID
		}
	}
	return remoteID
}

func recordRepositoryBindingEvent(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	action string,
	connection connectionRecord,
	local localRepositoryRecord,
	bindingRevision int64,
) error {
	var details []byte
	var err error
	switch action {
	case audit.ActionForgeRepositoryBound:
		details, err = json.Marshal(struct {
			RepositoryID        int64  `json:"repository_id"`
			RepositoryCreatedAt string `json:"repository_created_at"`
			ConfigRevision      int64  `json:"config_revision"`
			CheckGeneration     int64  `json:"check_generation"`
			BindingRevision     int64  `json:"binding_revision"`
		}{
			RepositoryID:        local.id,
			RepositoryCreatedAt: local.canonicalCreatedAt(),
			ConfigRevision:      connection.Revision,
			CheckGeneration:     connection.CheckGeneration,
			BindingRevision:     bindingRevision,
		})
	case audit.ActionForgeRepositoryUnbound:
		details, err = json.Marshal(struct {
			RepositoryID        int64  `json:"repository_id"`
			RepositoryCreatedAt string `json:"repository_created_at"`
			ConfigRevision      int64  `json:"config_revision"`
			BindingRevision     int64  `json:"binding_revision"`
		}{
			RepositoryID:        local.id,
			RepositoryCreatedAt: local.canonicalCreatedAt(),
			ConfigRevision:      connection.Revision,
			BindingRevision:     bindingRevision,
		})
	default:
		return errors.New("unsupported forge repository binding audit action")
	}
	if err != nil {
		return errors.New("encode forge repository binding audit evidence")
	}
	return recordForgeConnectionEvent(ctx, tx, actorUserID, action, connection.ID, string(details))
}
