package forgeconnection

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

// testClock is a settable clock shared by fixture and service.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// scriptedAccessObserver returns queued observations in order, can hold each
// call until released, and can run a callback inside the observation window
// so tests can interleave concurrent state changes.
type scriptedAccessObserver struct {
	mu           sync.Mutex
	observations []AccessObservation
	inputs       []AccessObserveInput
	gates        []chan struct{}
	started      chan struct{}
	onObserve    func(call int)
}

func (o *scriptedAccessObserver) ObserveAccess(ctx context.Context, input AccessObserveInput) AccessObservation {
	o.mu.Lock()
	input.PAT = append([]byte(nil), input.PAT...)
	o.inputs = append(o.inputs, input)
	call := len(o.inputs) - 1
	started := o.started
	onObserve := o.onObserve
	var gate chan struct{}
	if call < len(o.gates) {
		gate = o.gates[call]
	}
	o.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if onObserve != nil {
		onObserve(call)
	}
	if gate != nil {
		<-gate
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if call < len(o.observations) {
		return o.observations[call]
	}
	return AccessObservation{ResultCode: AccessSyncUnavailable, RequestCount: 1}
}

type accessShadowFixture struct {
	ctx      context.Context
	database *sql.DB
	service  *AccessShadowService
	observer *scriptedAccessObserver
	clock    *testClock
	adminID  int64
}

const accessShadowFixtureTime = "2026-08-01T10:00:00.000000000Z"

func newAccessShadowFixture(t *testing.T) *accessShadowFixture {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "forge-access-shadow-test.db")))
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
	secretStore, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	start, err := parseForgeConnectionTime(accessShadowFixtureTime)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &accessShadowFixture{
		ctx:      ctx,
		database: database,
		observer: &scriptedAccessObserver{},
		clock:    &testClock{now: start},
		adminID:  1,
	}
	fixture.service = NewAccessShadowService(database, secretStore, fixture.observer)
	fixture.service.now = fixture.clock.Now

	ciphertext, err := encryptServicePAT(ctx, secretStore, testServicePAT)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES
  (1, 'admin@example.test', 'Administrator', ?, ?),
  (2, 'dev@example.test', 'Developer', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (1, 'admin', ?);
UPDATE users SET disabled_at = ? WHERE id = 2;
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES
  (11, 'forgejo', 'https://forge.example.test', 'fixture-org', 'alpha', 'main', 1, ?, ?),
  (12, 'forgejo', 'https://forge.example.test', 'fixture-org', 'beta', 'main', 1, ?, ?);
INSERT INTO forge_connections(
  id, provider, display_name, base_url, config_revision, check_generation,
  binding_revision, access_identity_revision, created_at, updated_at
)
VALUES (1, 'forgejo', 'Fixture forge', 'https://forge.example.test', 3, 5, 2, 2, ?, ?);
INSERT INTO forge_organizations(id, connection_id, remote_organization_id, slug, display_name, observed_at)
VALUES (10, 1, '7', 'fixture-org', 'Fixture Organization', ?);
INSERT INTO forge_connection_setup_checks(
  connection_id, config_revision, check_generation, result_code, observed_version,
  visible_repository_count, visible_private_repository_count, checked_at
)
VALUES (1, 3, 5, 'visible_inventory_observed', '15.0.6', 2, 1, ?);
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES (11, 1, 10, '100'), (12, 1, 10, '101');
INSERT INTO forgejo_identities(id, connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES
  (21, 1, 1, '77', 'admin-user', ?),
  (22, 1, 2, '78', 'dev-user', ?)`,
		accessShadowFixtureTime, accessShadowFixtureTime,
		accessShadowFixtureTime, accessShadowFixtureTime,
		accessShadowFixtureTime,
		accessShadowFixtureTime,
		accessShadowFixtureTime, accessShadowFixtureTime,
		accessShadowFixtureTime, accessShadowFixtureTime,
		accessShadowFixtureTime, accessShadowFixtureTime,
		accessShadowFixtureTime,
		accessShadowFixtureTime,
		accessShadowFixtureTime,
		accessShadowFixtureTime,
	); err != nil {
		t.Fatal(err)
	}
	// The ciphertext travels alone: multi-statement Exec re-binds the same
	// leading arguments for every statement, which would misplace a blob.
	if _, err := database.ExecContext(ctx, `
INSERT INTO forgejo_connection_config(
  connection_id, organization_slug, service_pat_ciphertext, service_user_remote_id,
  pat_attested_at, attested_by_user_id
)
VALUES (1, 'fixture-org', ?, '42', ?, 1)`, ciphertext, accessShadowFixtureTime); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *accessShadowFixture) validRunInput() RunAccessShadowInput {
	return RunAccessShadowInput{
		ExpectedConnectionID:           1,
		ExpectedConfigRevision:         3,
		ExpectedCheckGeneration:        5,
		ExpectedBindingRevision:        2,
		ExpectedAccessIdentityRevision: 2,
		ExpectedNewestRunID:            0,
		ConfirmShadowOnly:              true,
	}
}

// completeObservation classifies the fixture's four pairs. Overrides apply
// by pair key.
func completeObservation(requestCount int64, overrides map[[2]int64]AccessObservationReason) AccessObservation {
	pairs := make([]AccessPairObservation, 0, 4)
	for _, identityID := range []int64{21, 22} {
		for _, repositoryID := range []int64{11, 12} {
			reason := AccessReasonNoExplicitAccessNone
			if override, found := overrides[[2]int64{identityID, repositoryID}]; found {
				reason = override
			}
			pairs = append(pairs, AccessPairObservation{
				IdentityID:   identityID,
				RepositoryID: repositoryID,
				Reason:       reason,
			})
		}
	}
	return AccessObservation{ResultCode: AccessSyncComplete, Pairs: pairs, RequestCount: requestCount}
}

func (f *accessShadowFixture) newestRunID(t *testing.T) int64 {
	t.Helper()
	var id int64
	if err := f.database.QueryRowContext(f.ctx, `
SELECT id FROM forge_access_shadow_runs WHERE connection_id = 1 ORDER BY id DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *accessShadowFixture) auditDetails(t *testing.T, action string) []map[string]any {
	t.Helper()
	rows, err := f.database.QueryContext(f.ctx, `
SELECT details_json FROM audit_events WHERE action = ? ORDER BY id`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	details := make([]map[string]any, 0)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			t.Fatal(err)
		}
		details = append(details, decoded)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return details
}

func TestAccessShadowRunValidatesInput(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	cases := []struct {
		name   string
		mutate func(*RunAccessShadowInput)
	}{
		{name: "zero connection id", mutate: func(input *RunAccessShadowInput) { input.ExpectedConnectionID = 0 }},
		{name: "zero config revision", mutate: func(input *RunAccessShadowInput) { input.ExpectedConfigRevision = 0 }},
		{name: "zero check generation", mutate: func(input *RunAccessShadowInput) { input.ExpectedCheckGeneration = 0 }},
		{name: "zero binding revision", mutate: func(input *RunAccessShadowInput) { input.ExpectedBindingRevision = 0 }},
		{name: "zero identity revision", mutate: func(input *RunAccessShadowInput) { input.ExpectedAccessIdentityRevision = 0 }},
		{name: "negative newest run id", mutate: func(input *RunAccessShadowInput) { input.ExpectedNewestRunID = -1 }},
		{name: "missing confirmation", mutate: func(input *RunAccessShadowInput) { input.ConfirmShadowOnly = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := fixture.validRunInput()
			tc.mutate(&input)
			if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
	var runs int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("rejected input reserved %d runs", runs)
	}
}

func TestAccessShadowRunRejectsStaleFencesAndNonAdmins(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	staleCases := []struct {
		name   string
		mutate func(*RunAccessShadowInput)
	}{
		{name: "wrong connection id", mutate: func(input *RunAccessShadowInput) { input.ExpectedConnectionID = 2 }},
		{name: "wrong config revision", mutate: func(input *RunAccessShadowInput) { input.ExpectedConfigRevision = 4 }},
		{name: "wrong check generation", mutate: func(input *RunAccessShadowInput) { input.ExpectedCheckGeneration = 6 }},
		{name: "wrong binding revision", mutate: func(input *RunAccessShadowInput) { input.ExpectedBindingRevision = 3 }},
		{name: "wrong identity revision", mutate: func(input *RunAccessShadowInput) { input.ExpectedAccessIdentityRevision = 3 }},
		{name: "wrong newest run id", mutate: func(input *RunAccessShadowInput) { input.ExpectedNewestRunID = 9 }},
	}
	for _, tc := range staleCases {
		t.Run(tc.name, func(t *testing.T) {
			input := fixture.validRunInput()
			tc.mutate(&input)
			if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrConflict) {
				t.Fatalf("expected conflict, got %v", err)
			}
		})
	}
	if _, err := fixture.service.Run(fixture.ctx, 2, fixture.validRunInput()); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("expected authorization error for non-admin actor, got %v", err)
	}
	var runs int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("rejected reservation persisted %d runs", runs)
	}
}

func TestAccessShadowRunRequiresCurrentSetupEvidence(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	if _, err := fixture.database.Exec(`
UPDATE forge_connection_setup_checks SET result_code = 'unavailable',
  visible_repository_count = NULL, visible_private_repository_count = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict without current successful setup evidence, got %v", err)
	}
}

func TestAccessShadowRunEnforcesSmallAlphaLimits(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	// Push the pair product past 25: 6 identities x 5 bindings.
	for i := int64(3); i <= 8; i++ {
		if _, err := fixture.database.Exec(`
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (?, ?, 'Extra', ?, ?)`,
			i+100, "extra"+string(rune('a'+i))+"@example.test", accessShadowFixtureTime, accessShadowFixtureTime); err != nil {
			t.Fatal(err)
		}
	}
	for i := range int64(4) {
		if _, err := fixture.database.Exec(`
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, ?, ?, 'extra-user', ?)`,
			103+i, "90"+string(rune('0'+i)), accessShadowFixtureTime); err != nil {
			t.Fatal(err)
		}
	}
	for i := range int64(3) {
		if _, err := fixture.database.Exec(`
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (?, 'forgejo', 'https://forge.example.test', 'fixture-org', ?, 'main', 1, ?, ?)`,
			13+i, "extra-repo-"+string(rune('a'+i)), accessShadowFixtureTime, accessShadowFixtureTime); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.Exec(`
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES (?, 1, 10, ?)`, 13+i, "20"+string(rune('0'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); !IsValidationError(err) {
		t.Fatalf("expected small-alpha limit rejection, got %v", err)
	}
	var runs int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("limit rejection persisted %d runs", runs)
	}
}

func TestAccessShadowCompleteRunPublishesObservationsCountsAndAudit(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.observer.observations = []AccessObservation{completeObservation(40, map[[2]int64]AccessObservationReason{
		{21, 11}: AccessReasonDirectCollaborator,
		{21, 12}: AccessReasonTeamAccess,
		{22, 11}: AccessReasonPermissionUnavailable,
	})}
	result, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
	if err != nil || result != AccessSyncComplete {
		t.Fatalf("Run: result=%v err=%v", result, err)
	}

	input := fixture.observer.inputs[0]
	if input.BaseURL != "https://forge.example.test" || input.OrganizationSlug != "fixture-org" ||
		input.BoundServiceUserRemoteID != "42" || input.BoundOrganizationRemoteID != "7" ||
		len(input.Identities) != 2 || len(input.Bindings) != 2 ||
		input.Identities[0].RemoteUserID != "77" || input.Identities[1].UsernameAtLink != "dev-user" ||
		input.Bindings[1].RemoteRepositoryID != "101" ||
		string(input.PAT) != testServicePAT {
		t.Fatalf("observer input is wrong: %+v", input)
	}

	var resultCode string
	var present, unknown int64
	if err := fixture.database.QueryRow(`
SELECT result_code, present_count, unknown_count FROM forge_access_shadow_runs`).Scan(&resultCode, &present, &unknown); err != nil {
		t.Fatal(err)
	}
	if resultCode != "complete" || present != 2 || unknown != 1 {
		t.Fatalf("run row: result=%s present=%d unknown=%d", resultCode, present, unknown)
	}

	var confirmed, unknownRows, total int
	if err := fixture.database.QueryRow(`
SELECT count(*),
  sum(latest_reason IN ('direct_collaborator', 'team_access', 'no_explicit_access_none')),
  sum(last_confirmed_reason IS NULL)
FROM forge_access_shadow_observations`).Scan(&total, &confirmed, &unknownRows); err != nil {
		t.Fatal(err)
	}
	if total != 4 || confirmed != 3 || unknownRows != 1 {
		t.Fatalf("observations: total=%d confirmed=%d without-confirmation=%d", total, confirmed, unknownRows)
	}

	started := fixture.auditDetails(t, audit.ActionForgeAccessSyncStarted)
	finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
	if len(started) != 1 || len(finished) != 1 {
		t.Fatalf("audit events: started=%d finished=%d", len(started), len(finished))
	}
	if started[0]["identity_count"] != float64(2) || started[0]["repository_count"] != float64(2) {
		t.Fatalf("started details: %v", started[0])
	}
	if finished[0]["result_code"] != "complete" || finished[0]["present_count"] != float64(2) ||
		finished[0]["unknown_count"] != float64(1) || finished[0]["request_count"] != float64(40) {
		t.Fatalf("finished details: %v", finished[0])
	}
	for _, details := range append(started, finished...) {
		for key := range details {
			switch key {
			case "run_id", "identity_count", "repository_count", "result_code", "present_count", "unknown_count", "request_count":
			default:
				t.Fatalf("unexpected audit detail key %q", key)
			}
		}
	}
}

func TestAccessShadowSystemicFailurePublishesNothing(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.observer.observations = []AccessObservation{
		completeObservation(30, nil),
		{ResultCode: AccessSyncAuthenticationFailed, RequestCount: 1},
	}
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); err != nil {
		t.Fatal(err)
	}
	firstRunID := fixture.newestRunID(t)

	fixture.clock.Advance(time.Minute)
	input := fixture.validRunInput()
	input.ExpectedNewestRunID = firstRunID
	result, err := fixture.service.Run(fixture.ctx, fixture.adminID, input)
	if err != nil || result != AccessSyncAuthenticationFailed {
		t.Fatalf("Run: result=%v err=%v", result, err)
	}

	// Prior complete observations survive untouched at the first run's id.
	var stale int
	if err := fixture.database.QueryRow(`
SELECT count(*) FROM forge_access_shadow_observations WHERE latest_run_id != ?`, firstRunID).Scan(&stale); err != nil {
		t.Fatal(err)
	}
	if stale != 0 {
		t.Fatalf("systemic failure rewrote %d observations", stale)
	}
	// Retention keeps the newest terminal attempt plus the completed anchor.
	var retained int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 2 {
		t.Fatalf("expected 2 retained runs, got %d", retained)
	}
	finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
	if len(finished) != 2 {
		t.Fatalf("expected 2 finished events, got %d", len(finished))
	}
	if finished[1]["result_code"] != "authentication_failed" {
		t.Fatalf("second finished details: %v", finished[1])
	}
	if _, present := finished[1]["present_count"]; present {
		t.Fatalf("failure finish must not carry pair counts: %v", finished[1])
	}
}

func TestAccessShadowUnknownPreservesConfirmedEvidence(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	pair := [2]int64{21, 11}
	fixture.observer.observations = []AccessObservation{
		completeObservation(30, map[[2]int64]AccessObservationReason{pair: AccessReasonDirectCollaborator}),
		completeObservation(30, map[[2]int64]AccessObservationReason{pair: AccessReasonEvidenceInconsistent}),
		completeObservation(30, map[[2]int64]AccessObservationReason{pair: AccessReasonTeamAccess}),
	}
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); err != nil {
		t.Fatal(err)
	}
	firstRunID := fixture.newestRunID(t)

	fixture.clock.Advance(time.Minute)
	input := fixture.validRunInput()
	input.ExpectedNewestRunID = firstRunID
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); err != nil {
		t.Fatal(err)
	}
	secondRunID := fixture.newestRunID(t)

	var latestReason, confirmedReason string
	var latestRunID, confirmedRunID int64
	row := fixture.database.QueryRow(`
SELECT latest_reason, latest_run_id, last_confirmed_reason, last_confirmed_run_id
FROM forge_access_shadow_observations
WHERE identity_id = 21 AND repository_id = 11`)
	if err := row.Scan(&latestReason, &latestRunID, &confirmedReason, &confirmedRunID); err != nil {
		t.Fatal(err)
	}
	if latestReason != "evidence_inconsistent" || latestRunID != secondRunID ||
		confirmedReason != "direct_collaborator" || confirmedRunID != firstRunID {
		t.Fatalf("unknown did not preserve confirmation: latest=%s/%d confirmed=%s/%d",
			latestReason, latestRunID, confirmedReason, confirmedRunID)
	}

	fixture.clock.Advance(time.Minute)
	input.ExpectedNewestRunID = secondRunID
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); err != nil {
		t.Fatal(err)
	}
	thirdRunID := fixture.newestRunID(t)
	row = fixture.database.QueryRow(`
SELECT latest_reason, latest_run_id, last_confirmed_reason, last_confirmed_run_id
FROM forge_access_shadow_observations
WHERE identity_id = 21 AND repository_id = 11`)
	if err := row.Scan(&latestReason, &latestRunID, &confirmedReason, &confirmedRunID); err != nil {
		t.Fatal(err)
	}
	if latestReason != "team_access" || latestRunID != thirdRunID ||
		confirmedReason != "team_access" || confirmedRunID != thirdRunID {
		t.Fatalf("new confirmation did not replace evidence: latest=%s/%d confirmed=%s/%d",
			latestReason, latestRunID, confirmedReason, confirmedRunID)
	}
}

func TestAccessShadowScopeChangeDuringObservationPublishesNothing(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
	fixture.observer.onObserve = func(int) {
		// A concurrent unbind advances the binding revision mid-observation.
		if _, err := fixture.database.Exec(`
DELETE FROM forge_repository_bindings WHERE repository_id = 12`); err != nil {
			t.Error(err)
		}
		if _, err := fixture.database.Exec(`
UPDATE forge_connections SET binding_revision = 3 WHERE id = 1`); err != nil {
			t.Error(err)
		}
	}
	result, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
	if err != nil || result != AccessSyncScopeChanged {
		t.Fatalf("Run: result=%v err=%v", result, err)
	}
	var observations int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_observations`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if observations != 0 {
		t.Fatalf("scope change published %d observations", observations)
	}
	var resultCode string
	var counts sql.NullInt64
	if err := fixture.database.QueryRow(`
SELECT result_code, present_count FROM forge_access_shadow_runs`).Scan(&resultCode, &counts); err != nil {
		t.Fatal(err)
	}
	if resultCode != "scope_changed" || counts.Valid {
		t.Fatalf("run row: result=%s counts-valid=%v", resultCode, counts.Valid)
	}
}

func TestAccessShadowCredentialUnavailableFinalizesWithoutObservations(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	// Corrupt the stored ciphertext so decryption fails after reservation.
	if _, err := fixture.database.Exec(`
UPDATE forgejo_connection_config SET service_pat_ciphertext = x'01020304'`); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
	if err != nil || result != AccessSyncCredentialUnavailable {
		t.Fatalf("Run: result=%v err=%v", result, err)
	}
	if len(fixture.observer.inputs) != 0 {
		t.Fatal("observer must not run without a decrypted credential")
	}
	var observations int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_observations`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if observations != 0 {
		t.Fatalf("credential failure published %d observations", observations)
	}
	finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
	if len(finished) != 1 || finished[0]["result_code"] != "credential_unavailable" {
		t.Fatalf("finished details: %v", finished)
	}
	if _, present := finished[0]["request_count"]; present {
		t.Fatalf("credential failure must omit the request count: %v", finished[0])
	}
}

func TestAccessShadowConcurrentStartsProduceOneReservation(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	gate := make(chan struct{})
	fixture.observer.gates = []chan struct{}{gate}
	fixture.observer.started = make(chan struct{}, 1)
	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}

	firstDone := make(chan error, 1)
	go func() {
		_, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
		firstDone <- err
	}()
	<-fixture.observer.started

	// The second start sees the young running row and must not reserve.
	secondInput := fixture.validRunInput()
	secondInput.ExpectedNewestRunID = fixture.newestRunID(t)
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, secondInput); !errors.Is(err, ErrAccessSyncRunning) {
		t.Fatalf("expected running rejection, got %v", err)
	}
	// A start submitted from the pre-run page fails the newest-run CAS.
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected newest-run conflict, got %v", err)
	}

	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	var runs int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("expected exactly one run, got %d", runs)
	}
}

func TestAccessShadowOrphanRecoveryTerminalizesAndStartsFresh(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	gate := make(chan struct{})
	fixture.observer.gates = []chan struct{}{gate}
	fixture.observer.started = make(chan struct{}, 1)
	fixture.observer.observations = []AccessObservation{
		completeObservation(30, map[[2]int64]AccessObservationReason{{21, 11}: AccessReasonDirectCollaborator}),
		completeObservation(30, nil),
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
		firstDone <- err
	}()
	<-fixture.observer.started
	orphanRunID := fixture.newestRunID(t)

	// Once the running row is older than the interruption age, the next
	// reservation terminalizes it and starts new work.
	fixture.clock.Advance(2 * time.Minute)
	input := fixture.validRunInput()
	input.ExpectedNewestRunID = orphanRunID
	result, err := fixture.service.Run(fixture.ctx, fixture.adminID, input)
	if err != nil || result != AccessSyncComplete {
		t.Fatalf("recovery run: result=%v err=%v", result, err)
	}
	secondRunID := fixture.newestRunID(t)

	// The late first observer return can no longer publish.
	close(gate)
	if err := <-firstDone; !errors.Is(err, ErrAccessSyncInterrupted) {
		t.Fatalf("expected interrupted late return, got %v", err)
	}
	var fromOrphan int
	if err := fixture.database.QueryRow(`
SELECT count(*) FROM forge_access_shadow_observations WHERE latest_run_id = ?`, orphanRunID).Scan(&fromOrphan); err != nil {
		t.Fatal(err)
	}
	if fromOrphan != 0 {
		t.Fatalf("late observer published %d observations", fromOrphan)
	}
	var current int
	if err := fixture.database.QueryRow(`
SELECT count(*) FROM forge_access_shadow_observations WHERE latest_run_id = ?`, secondRunID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if current != 4 {
		t.Fatalf("recovery run published %d observations", current)
	}
	// The interrupted finish event omits the request count.
	finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
	if len(finished) != 2 || finished[0]["result_code"] != "interrupted" {
		t.Fatalf("finished events: %v", finished)
	}
	if _, present := finished[0]["request_count"]; present {
		t.Fatalf("orphan interruption must omit the request count: %v", finished[0])
	}
}

func TestAccessShadowRetentionKeepsNewestTerminalAndCompletedAnchor(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.observer.observations = []AccessObservation{
		completeObservation(30, nil),
		{ResultCode: AccessSyncUnavailable, RequestCount: 2},
		{ResultCode: AccessSyncUnavailable, RequestCount: 2},
		completeObservation(30, nil),
	}
	input := fixture.validRunInput()
	for i := range 4 {
		fixture.clock.Advance(time.Minute)
		result, err := fixture.service.Run(fixture.ctx, fixture.adminID, input)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		if i == 0 && result != AccessSyncComplete {
			t.Fatalf("first run result %v", result)
		}
		input.ExpectedNewestRunID = fixture.newestRunID(t)
	}
	// After the final complete run, it is both the newest terminal attempt
	// and the newest completed anchor: exactly one row survives.
	rows, err := fixture.database.Query(`SELECT result_code FROM forge_access_shadow_runs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	codes := make([]string, 0, 2)
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			t.Fatal(err)
		}
		codes = append(codes, code)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(codes) != 1 || codes[0] != "complete" {
		t.Fatalf("retained runs: %v", codes)
	}
}

func TestAccessShadowViewDerivesAttemptSnapshotAndPairs(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	view, err := fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !view.HasConnection || view.LatestAttempt != nil || view.LatestSnapshot != nil ||
		view.NewestRunID != 0 || !view.WithinLimits || !view.SetupEvidenceCurrent ||
		view.IdentityCount != 2 || view.BindingCount != 2 || !view.Ready() {
		t.Fatalf("never-run view: %+v", view)
	}
	if len(view.Pairs) != 4 {
		t.Fatalf("expected 4 never-observed pairs, got %d", len(view.Pairs))
	}
	for _, pair := range view.Pairs {
		if pair.Observed {
			t.Fatalf("pair observed before any run: %+v", pair)
		}
	}
	// Sorted by user label then repository label: Administrator before
	// Developer, alpha before beta.
	if view.Pairs[0].UserDisplayName != "Administrator" || view.Pairs[0].RepositoryFullName != "fixture-org/alpha" ||
		view.Pairs[3].UserDisplayName != "Developer" || view.Pairs[3].RepositoryFullName != "fixture-org/beta" {
		t.Fatalf("pair order wrong: %+v", view.Pairs)
	}
	if !view.Pairs[3].UserDisabled || view.Pairs[0].UserDisabled {
		t.Fatal("disabled owner flag wrong")
	}

	fixture.observer.observations = []AccessObservation{
		completeObservation(30, map[[2]int64]AccessObservationReason{
			{21, 11}: AccessReasonDirectCollaborator,
		}),
		completeObservation(30, map[[2]int64]AccessObservationReason{
			{21, 11}: AccessReasonPermissionUnavailable,
		}),
	}
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(time.Minute)
	input := fixture.validRunInput()
	input.ExpectedNewestRunID = fixture.newestRunID(t)
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); err != nil {
		t.Fatal(err)
	}

	view, err = fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.LatestAttempt == nil || view.LatestAttempt.Status != AccessAttemptCompleted ||
		view.LatestSnapshot == nil || !view.LatestSnapshot.ScopeCurrent ||
		view.LatestSnapshot.PresentCount != 0 || view.LatestSnapshot.UnknownCount != 1 ||
		view.LatestSnapshot.AbsentCount != 3 || view.LatestSnapshot.PairCount != 4 {
		t.Fatalf("completed view: attempt=%+v snapshot=%+v", view.LatestAttempt, view.LatestSnapshot)
	}
	var adminAlpha *AccessShadowPairRow
	for i := range view.Pairs {
		if view.Pairs[i].IdentityID == 21 && view.Pairs[i].RepositoryID == 11 {
			adminAlpha = &view.Pairs[i]
		}
	}
	if adminAlpha == nil || !adminAlpha.Observed ||
		adminAlpha.LatestReason != AccessReasonPermissionUnavailable ||
		adminAlpha.PriorConfirmedReason != AccessReasonDirectCollaborator {
		t.Fatalf("pair evidence wrong: %+v", adminAlpha)
	}

	// A binding-revision change flips the attempt to superseded and the
	// snapshot scope to changed.
	if _, err := fixture.database.Exec(`UPDATE forge_connections SET binding_revision = 9`); err != nil {
		t.Fatal(err)
	}
	view, err = fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.LatestAttempt.Status != AccessAttemptSuperseded || view.LatestSnapshot.ScopeCurrent {
		t.Fatalf("stale-scope view: attempt=%+v snapshot=%+v", view.LatestAttempt, view.LatestSnapshot)
	}
}

func TestAccessShadowViewSupersedesTerminalReductionAtSaturatedRevision(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
	if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); err != nil {
		t.Fatal(err)
	}
	// At math.MaxInt64 the access-identity revision cannot advance, and an
	// unlink is a permitted terminal same-revision reduction. Simulate it by
	// removing an identity without touching the revision: the captured and
	// current revisions still match, so only the shrunken identity count can
	// expose that the completed snapshot no longer describes the scope.
	if _, err := fixture.database.Exec(`DELETE FROM forgejo_identities WHERE id = 22`); err != nil {
		t.Fatal(err)
	}
	view, err := fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.LatestAttempt == nil || view.LatestAttempt.Status != AccessAttemptSuperseded {
		t.Fatalf("attempt after terminal reduction = %+v", view.LatestAttempt)
	}
	if view.LatestSnapshot == nil || view.LatestSnapshot.ScopeCurrent {
		t.Fatalf("snapshot after terminal reduction = %+v", view.LatestSnapshot)
	}
}

func TestAccessShadowViewDerivesRunningAndInterrupted(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	gate := make(chan struct{})
	fixture.observer.gates = []chan struct{}{gate}
	fixture.observer.started = make(chan struct{}, 1)
	fixture.observer.observations = []AccessObservation{{ResultCode: AccessSyncUnavailable, RequestCount: 1}}

	done := make(chan error, 1)
	go func() {
		_, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
		done <- err
	}()
	<-fixture.observer.started

	view, err := fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.LatestAttempt == nil || view.LatestAttempt.Status != AccessAttemptRunning || view.Ready() {
		t.Fatalf("running view: %+v", view.LatestAttempt)
	}
	fixture.clock.Advance(2 * time.Minute)
	view, err = fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.LatestAttempt.Status != AccessAttemptInterrupted {
		t.Fatalf("interrupted view: %+v", view.LatestAttempt)
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	view, err = fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.LatestAttempt.Status != AccessAttemptFailed || view.LatestAttempt.ResultCode != AccessSyncUnavailable {
		t.Fatalf("failed view: %+v", view.LatestAttempt)
	}
	if view.LatestSnapshot != nil {
		t.Fatal("failure must not create a snapshot anchor")
	}
}

func TestAccessShadowMalformedObserverOutputRecordsInvalidResponse(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	// A pair set that misses one expected pair violates the contract.
	broken := completeObservation(30, nil)
	broken.Pairs = broken.Pairs[:3]
	fixture.observer.observations = []AccessObservation{broken}
	result, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
	if err != nil || result != AccessSyncInvalidResponse {
		t.Fatalf("Run: result=%v err=%v", result, err)
	}
	var observations int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_observations`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if observations != 0 {
		t.Fatalf("malformed observation published %d rows", observations)
	}
}
