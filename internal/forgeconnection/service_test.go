package forgeconnection

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

const testServicePAT = "fictional-service-pat-0123456789"

type serviceFixture struct {
	ctx         context.Context
	database    *sql.DB
	service     *Service
	secretStore *secrets.AESGCMStore
	observer    *scriptedObserver
	adminID     int64
}

// scriptedObserver returns queued observations in order and can hold each
// call until released, so tests can interleave concurrent checks.
type scriptedObserver struct {
	observations []Observation
	inputs       []ObserveInput
	gates        []chan struct{}
	started      chan struct{}
}

func (o *scriptedObserver) Observe(ctx context.Context, input ObserveInput) Observation {
	// The service clears the PAT buffer after the observation; keep a copy
	// so tests can assert exactly which secret each destination received.
	input.PAT = append([]byte(nil), input.PAT...)
	o.inputs = append(o.inputs, input)
	call := len(o.inputs) - 1
	if o.started != nil {
		o.started <- struct{}{}
	}
	if call < len(o.gates) && o.gates[call] != nil {
		<-o.gates[call]
	}
	if call < len(o.observations) {
		return o.observations[call]
	}
	return Observation{ResultCode: CheckUnavailable}
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "forge-connection-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := db.LoadMigrations(forgeConnectionTestMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	secretStore, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x21}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &serviceFixture{
		ctx:         ctx,
		database:    database,
		secretStore: secretStore,
		observer:    &scriptedObserver{},
		adminID:     1,
	}
	fixture.service = NewService(database, secretStore, fixture.observer)
	// Fixed-width timestamps: RFC3339Nano trims trailing fractional zeros,
	// which the exactly-nine-digit column constraints reject intermittently.
	now := formatForgeConnectionTime(time.Now())
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (1, 'admin@example.test', 'Administrator', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (1, 'admin', ?);`, now, now, now); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// connectionID returns the current connection's never-reused internal id,
// which every edit, reset, and check command must carry.
func (f *serviceFixture) connectionID(t *testing.T) int64 {
	t.Helper()
	connection, found, err := f.service.Current(f.ctx)
	if err != nil || !found {
		t.Fatalf("current connection: found=%v err=%v", found, err)
	}
	return connection.ID
}

func forgeConnectionTestMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

func validCreateInput() CreateInput {
	return CreateInput{
		DisplayName:      "Fixture Forge",
		BaseURL:          "https://forge.example.test",
		OrganizationSlug: "fixture-org",
		ServicePAT:       testServicePAT,
		PATAttested:      true,
	}
}

func validEditInput(connectionID, revision int64) EditInput {
	return EditInput{
		DisplayName:          "Fixture Forge",
		BaseURL:              "https://forge.example.test",
		OrganizationSlug:     "fixture-org",
		ExpectedConnectionID: connectionID,
		ExpectedRevision:     revision,
	}
}

func successObservation() Observation {
	return Observation{
		ResultCode:          CheckVisibleInventoryObserved,
		ObservedVersion:     "15.0.6",
		ServiceUserRemoteID: "42",
		Organization: ObservedOrganization{
			RemoteID:    "7",
			Slug:        "fixture-org",
			DisplayName: "Fixture Organization",
		},
		Repositories: []ObservedRepository{
			{RemoteID: "100", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main", Private: false},
			{RemoteID: "101", Owner: "fixture-org", Name: "beta", DefaultBranch: "main", Private: true},
		},
	}
}

func TestCreateValidatesInput(t *testing.T) {
	fixture := newServiceFixture(t)
	cases := []struct {
		name   string
		mutate func(*CreateInput)
	}{
		{name: "empty display name", mutate: func(input *CreateInput) { input.DisplayName = " " }},
		{name: "oversized display name", mutate: func(input *CreateInput) { input.DisplayName = strings.Repeat("a", 81) }},
		{name: "control in display name", mutate: func(input *CreateInput) { input.DisplayName = "Fixture\nForge" }},
		{name: "http URL", mutate: func(input *CreateInput) { input.BaseURL = "http://forge.example.test" }},
		{name: "empty organization", mutate: func(input *CreateInput) { input.OrganizationSlug = "" }},
		{name: "organization with slash", mutate: func(input *CreateInput) { input.OrganizationSlug = "a/b" }},
		{name: "dot organization", mutate: func(input *CreateInput) { input.OrganizationSlug = ".." }},
		{name: "empty PAT", mutate: func(input *CreateInput) { input.ServicePAT = "" }},
		{name: "PAT with space", mutate: func(input *CreateInput) { input.ServicePAT = "with space" }},
		{name: "PAT with control", mutate: func(input *CreateInput) { input.ServicePAT = "with\ttab" }},
		{name: "oversized PAT", mutate: func(input *CreateInput) { input.ServicePAT = strings.Repeat("a", 1025) }},
		{name: "attestation unchecked", mutate: func(input *CreateInput) { input.PATAttested = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := validCreateInput()
			tc.mutate(&input)
			if err := fixture.service.Create(fixture.ctx, fixture.adminID, input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
	var connections int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_connections`).Scan(&connections); err != nil {
		t.Fatal(err)
	}
	if connections != 0 {
		t.Fatalf("rejected input persisted %d connections", connections)
	}
}

func TestCreateReadsBackAndAuditsSanitizedEvidence(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("Current: found=%v err=%v", found, err)
	}
	if connection.Provider != ProviderForgejo ||
		connection.DisplayName != "Fixture Forge" ||
		connection.BaseURL != "https://forge.example.test" ||
		connection.OrganizationSlug != "fixture-org" ||
		connection.Revision != 1 ||
		connection.CheckGeneration != 0 ||
		connection.Bound() ||
		connection.SetupCheck != nil {
		t.Fatalf("unexpected connection: %+v", connection)
	}
	if connection.PATAttestedAt.IsZero() {
		t.Fatal("PAT attestation timestamp missing")
	}

	// A second create conflicts with the one-connection contract.
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}

	assertForgeAudit(t, fixture.database, audit.ActionForgeConnectionCreated, connection.ID, map[string]any{
		"revision":     float64(1),
		"pat_replaced": true,
	})
}

func TestCreateRequiresEnabledAdministrator(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, 999, validCreateInput()); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("expected ErrAuthorization for unknown actor, got %v", err)
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM user_roles WHERE user_id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("expected ErrAuthorization for demoted actor, got %v", err)
	}
}

func TestCreateWithoutSecretStoreReportsConfiguration(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.service.secrets = nil
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected ErrConfiguration, got %v", err)
	}
}

func TestEditRevisionFenceNoOpAndRealEdit(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)

	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, validEditInput(connectionID, 4)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for wrong revision, got %v", err)
	}
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, validEditInput(connectionID+7, 1)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for wrong connection id, got %v", err)
	}

	// An exact no-op commits no mutation and no audit.
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, validEditInput(connectionID, 1)); err != nil {
		t.Fatal(err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil || connection.Revision != 1 {
		t.Fatalf("no-op changed revision: %d err=%v", connection.Revision, err)
	}
	assertForgeAuditCount(t, fixture.database, audit.ActionForgeConnectionUpdated, 0)

	// A real edit increments the revision exactly once.
	edit := validEditInput(connectionID, 1)
	edit.DisplayName = "Renamed Forge"
	edit.OrganizationSlug = "corrected-org"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil || connection.Revision != 2 ||
		connection.DisplayName != "Renamed Forge" ||
		connection.OrganizationSlug != "corrected-org" {
		t.Fatalf("edit result: %+v err=%v", connection, err)
	}
	assertForgeAudit(t, fixture.database, audit.ActionForgeConnectionUpdated, connection.ID, map[string]any{
		"revision":     float64(2),
		"pat_replaced": false,
	})
}

func TestEditReplacementPATRequiresFreshAttestation(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	previousCiphertext := storedPATCiphertext(t, fixture.database)

	edit := validEditInput(fixture.connectionID(t), 1)
	edit.ReplacementPAT = "fictional-replacement-pat"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); !IsValidationError(err) {
		t.Fatalf("expected validation error without fresh attestation, got %v", err)
	}

	edit.ReplacementPATAttested = true
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}
	replacedCiphertext := storedPATCiphertext(t, fixture.database)
	if bytes.Equal(previousCiphertext, replacedCiphertext) {
		t.Fatal("replacement PAT did not replace the stored ciphertext")
	}
	envelope, err := fixture.secretStore.Decrypt(fixture.ctx, replacedCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	pat, err := unwrapServicePAT(envelope)
	if err != nil || string(pat) != "fictional-replacement-pat" {
		t.Fatalf("stored envelope did not round-trip: %q err=%v", pat, err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil || connection.Revision != 2 {
		t.Fatalf("replacement did not increment revision once: %d err=%v", connection.Revision, err)
	}
	assertForgeAudit(t, fixture.database, audit.ActionForgeConnectionUpdated, connection.ID, map[string]any{
		"revision":     float64(2),
		"pat_replaced": true,
	})
}

func TestEditAfterBindingFixesURLAndOrganization(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{successObservation()}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1); err != nil {
		t.Fatal(err)
	}

	urlEdit := validEditInput(connectionID, 1)
	urlEdit.BaseURL = "https://other.example.test"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, urlEdit); !IsValidationError(err) {
		t.Fatalf("expected bound URL edit rejection, got %v", err)
	}
	slugEdit := validEditInput(connectionID, 1)
	slugEdit.OrganizationSlug = "other-org"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, slugEdit); !IsValidationError(err) {
		t.Fatalf("expected bound organization edit rejection, got %v", err)
	}

	nameEdit := validEditInput(connectionID, 1)
	nameEdit.DisplayName = "Renamed After Binding"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, nameEdit); err != nil {
		t.Fatal(err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil || connection.Revision != 2 || connection.DisplayName != "Renamed After Binding" {
		t.Fatalf("display-name edit after binding: %+v err=%v", connection, err)
	}
	// The prior check evidence and preview remain, visibly stale by revision.
	if connection.SetupCheck == nil || connection.SetupCheck.ConfigRevision != 1 {
		t.Fatalf("expected retained stale evidence, got %+v", connection.SetupCheck)
	}
	preview, err := fixture.service.VisibleRepositories(fixture.ctx, connection.ID)
	if err != nil || len(preview) != 2 {
		t.Fatalf("expected retained preview rows, got %d err=%v", len(preview), err)
	}
}

// TestEditChangedDestinationRequiresReplacementPAT proves the stored PAT
// is bound to the destination it was attested for: before binding, the
// installation URL can only change together with a freshly attested
// replacement PAT, and the old ciphertext or plaintext is never used for
// the new destination.
func TestEditChangedDestinationRequiresReplacementPAT(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{successObservation()}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	originalCiphertext := storedPATCiphertext(t, fixture.database)

	move := validEditInput(connectionID, 1)
	move.BaseURL = "https://moved.example.test"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, move); !IsValidationError(err) {
		t.Fatalf("destination change without replacement PAT error = %v, want validation error", err)
	}
	move.ReplacementPAT = "fictional-destination-pat"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, move); !IsValidationError(err) {
		t.Fatalf("destination change without fresh attestation error = %v, want validation error", err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil || connection.Revision != 1 || connection.BaseURL != "https://forge.example.test" {
		t.Fatalf("rejected destination change mutated the connection: %+v err=%v", connection, err)
	}
	if !bytes.Equal(originalCiphertext, storedPATCiphertext(t, fixture.database)) {
		t.Fatal("rejected destination change replaced the stored ciphertext")
	}

	move.ReplacementPATAttested = true
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, move); err != nil {
		t.Fatal(err)
	}
	replacedCiphertext := storedPATCiphertext(t, fixture.database)
	if bytes.Equal(originalCiphertext, replacedCiphertext) {
		t.Fatal("destination change retained the old PAT ciphertext")
	}
	envelope, err := fixture.secretStore.Decrypt(fixture.ctx, replacedCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	pat, err := unwrapServicePAT(envelope)
	if err != nil || string(pat) != "fictional-destination-pat" {
		t.Fatalf("stored envelope after destination change: %q err=%v", pat, err)
	}

	// A check against the moved destination observes only the replacement.
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 2); err != nil {
		t.Fatal(err)
	}
	observed := fixture.observer.inputs[0]
	if observed.BaseURL != "https://moved.example.test" {
		t.Fatalf("observation destination = %q", observed.BaseURL)
	}
	if string(observed.PAT) != "fictional-destination-pat" {
		t.Fatal("the old PAT plaintext reached the new destination")
	}
}

func TestResetRequiresConfirmationAndDeletesEverything(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{successObservation()}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connection.ID, 1); err != nil {
		t.Fatal(err)
	}

	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: connection.ID, ExpectedRevision: 1}); !IsValidationError(err) {
		t.Fatalf("expected confirmation requirement, got %v", err)
	}
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: connection.ID, ExpectedRevision: 3, ConfirmReset: true}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected revision fence, got %v", err)
	}
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: connection.ID, ExpectedRevision: 1, ConfirmReset: true}); err != nil {
		t.Fatal(err)
	}

	if _, found, err := fixture.service.Current(fixture.ctx); err != nil || found {
		t.Fatalf("expected no connection after reset: found=%v err=%v", found, err)
	}
	for _, table := range []string{"forgejo_connection_config", "forge_organizations", "forge_visible_repositories", "forge_connection_setup_checks"} {
		var rows int
		if err := fixture.database.QueryRow(`SELECT count(*) FROM ` + table).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 0 {
			t.Fatalf("reset left %d rows in %s", rows, table)
		}
	}
	assertForgeAudit(t, fixture.database, audit.ActionForgeConnectionReset, connection.ID, map[string]any{
		"revision": float64(1),
	})

	// Recreation never reuses the deleted internal id.
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	recreated, _, err := fixture.service.Current(fixture.ctx)
	if err != nil || recreated.ID <= connection.ID {
		t.Fatalf("expected fresh connection id above %d, got %d err=%v", connection.ID, recreated.ID, err)
	}
}

// TestServiceOperationsPreserveUnrelatedState proves the scope sentinel:
// save, check, edit, and reset never change repositories, repository
// grants, users, sessions, or company OIDC state. Only forge tables and
// the audit trail may move.
func TestServiceOperationsPreserveUnrelatedState(t *testing.T) {
	fixture := newServiceFixture(t)
	fixture.observer.observations = []Observation{successObservation()}
	now := formatForgeConnectionTime(time.Now())
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (11, 'forgejo', 'https://local.example.test', 'local-owner', 'local-repo', 'main', 1, ?, ?);
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (11, 1, 'freezer', 1, ?);
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES ('sentinel-session', 1, 'sentinel-csrf', '2026-09-01T10:00:00Z', ?);
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext, revision, created_at, updated_at
)
VALUES (1, 'Sentinel IdP', 'https://id.example.test', 'sentinel-client', x'0102', 4, ?, ?);
INSERT INTO company_oidc_allowed_domains(connection_id, domain)
VALUES (1, 'example.test')`, now, now, now, now, now, now); err != nil {
		t.Fatal(err)
	}

	snapshot := func() map[string]string {
		state := make(map[string]string)
		for name, query := range map[string]string{
			"repositories":       `SELECT count(*), coalesce(group_concat(id || owner || name || base_url || updated_at, '|'), '') FROM repositories ORDER BY id`,
			"repository_grants":  `SELECT count(*), coalesce(group_concat(repository_id || user_id || role, '|'), '') FROM repository_grants`,
			"users":              `SELECT count(*), coalesce(group_concat(id || email || updated_at, '|'), '') FROM users ORDER BY id`,
			"sessions":           `SELECT count(*), coalesce(group_concat(id || user_id, '|'), '') FROM sessions`,
			"oidc_connections":   `SELECT count(*), coalesce(group_concat(id || issuer || revision, '|'), '') FROM company_oidc_connections`,
			"oidc_domains":       `SELECT count(*), coalesce(group_concat(connection_id || domain, '|'), '') FROM company_oidc_allowed_domains`,
			"repository_creds":   `SELECT count(*), coalesce(sum(length(token_ciphertext)), 0) FROM repositories WHERE token_ciphertext IS NOT NULL`,
			"repository_branch":  `SELECT count(*), '' FROM repository_branches`,
			"schedules":          `SELECT count(*), '' FROM schedules`,
			"webhook_deliveries": `SELECT count(*), '' FROM webhook_deliveries`,
		} {
			var count, content string
			if err := fixture.database.QueryRow(query).Scan(&count, &content); err != nil {
				t.Fatalf("snapshot %s: %v", name, err)
			}
			state[name] = count + ":" + content
		}
		return state
	}

	before := snapshot()
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connectionID := fixture.connectionID(t)
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connectionID, 1); err != nil {
		t.Fatal(err)
	}
	nameEdit := validEditInput(connectionID, 1)
	nameEdit.DisplayName = "Sentinel Edit"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, nameEdit); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{ExpectedConnectionID: connectionID, ExpectedRevision: 2, ConfirmReset: true}); err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	for name, want := range before {
		if after[name] != want {
			t.Fatalf("service operations changed %s: before=%q after=%q", name, want, after[name])
		}
	}
}

func storedPATCiphertext(t *testing.T, database *sql.DB) []byte {
	t.Helper()
	var ciphertext []byte
	if err := database.QueryRow(`SELECT service_pat_ciphertext FROM forgejo_connection_config`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func assertForgeAuditCount(t *testing.T, database *sql.DB, action string, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow(`SELECT count(*) FROM audit_events WHERE action = ?`, action).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("audit count for %s = %d, want %d", action, got, want)
	}
}

// assertForgeAudit verifies one sanitized audit event: the exact expected
// details and no connection URL, organization, repository name, or PAT
// material anywhere in the record.
func assertForgeAudit(t *testing.T, database *sql.DB, action string, connectionID int64, wantDetails map[string]any) {
	t.Helper()
	var actorUserID int64
	var subjectType, subjectID, detailsJSON string
	if err := database.QueryRow(`
SELECT actor_user_id, subject_type, subject_id, details_json
FROM audit_events
WHERE action = ?
ORDER BY id DESC
LIMIT 1`, action).Scan(&actorUserID, &subjectType, &subjectID, &detailsJSON); err != nil {
		t.Fatalf("read %s audit event: %v", action, err)
	}
	if actorUserID <= 0 || subjectType != audit.SubjectTypeForgeConnection ||
		subjectID != strconv.FormatInt(connectionID, 10) {
		t.Fatalf("unexpected audit identity: actor=%d subject=%s/%s want id %d", actorUserID, subjectType, subjectID, connectionID)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(detailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if len(details) != len(wantDetails) {
		t.Fatalf("audit details %s, want %v", detailsJSON, wantDetails)
	}
	for key, want := range wantDetails {
		if details[key] != want {
			t.Fatalf("audit detail %s = %v, want %v (%s)", key, details[key], want, detailsJSON)
		}
	}
	lowered := strings.ToLower(detailsJSON)
	for _, forbidden := range []string{
		"forge.example.test",
		"fixture-org",
		"fixture forge",
		"alpha",
		"beta",
		strings.ToLower(testServicePAT),
		"pat_attested_at",
	} {
		if strings.Contains(lowered, forbidden) {
			t.Fatalf("audit details contain forbidden value %q: %s", forbidden, detailsJSON)
		}
	}
}
