package forgeconnection

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
)

func observedRepositories(repositories ...ObservedRepository) Observation {
	code := CheckVisibleInventoryObservedPrivateReadUnproven
	for _, repository := range repositories {
		if repository.Private {
			code = CheckVisibleInventoryObserved
			break
		}
	}
	return Observation{
		ResultCode:          code,
		ObservedVersion:     "15.0.6",
		ServiceUserRemoteID: "42",
		Organization: ObservedOrganization{
			RemoteID:    "7",
			Slug:        "fixture-org",
			DisplayName: "Fixture Organization",
		},
		Repositories: repositories,
	}
}

func createCheckedConnection(t *testing.T, fixture *serviceFixture, observations ...Observation) Connection {
	t.Helper()
	fixture.observer.observations = observations
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput()); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("Current: found=%v err=%v", found, err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connection.ID, connection.Revision); err != nil {
		t.Fatal(err)
	}
	connection, found, err = fixture.service.Current(fixture.ctx)
	if err != nil || !found {
		t.Fatalf("Current after check: found=%v err=%v", found, err)
	}
	return connection
}

func insertBindingTestRepository(
	t *testing.T,
	fixture *serviceFixture,
	id int64,
	forge string,
	baseURL string,
	owner string,
	name string,
	defaultBranch string,
	active bool,
	createdAt string,
) {
	t.Helper()
	activeValue := 0
	if active {
		activeValue = 1
	}
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO repositories(
  id, forge, base_url, owner, name, default_branch, active, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		forge,
		baseURL,
		owner,
		name,
		defaultBranch,
		activeValue,
		createdAt,
		createdAt,
	); err != nil {
		t.Fatal(err)
	}
}

func bindingTestCreatedAt(id int64) string {
	return fmt.Sprintf("2026-08-02T10:00:00.%09dZ", id)
}

func bindingRowForRepository(t *testing.T, model RepositoryBindingReadModel, repositoryID int64) RepositoryBindingRow {
	t.Helper()
	for _, row := range model.Rows {
		if row.RepositoryID == repositoryID {
			return row
		}
	}
	t.Fatalf("repository %d missing from binding model: %+v", repositoryID, model.Rows)
	return RepositoryBindingRow{}
}

func bindingRowForRemote(t *testing.T, model RepositoryBindingReadModel, fullName string) RepositoryBindingRow {
	t.Helper()
	for _, row := range model.Rows {
		if row.RemoteFullName == fullName {
			return row
		}
	}
	t.Fatalf("remote repository %q missing from binding model: %+v", fullName, model.Rows)
	return RepositoryBindingRow{}
}

func validBindInput(connection Connection, row RepositoryBindingRow) BindRepositoryInput {
	return BindRepositoryInput{
		ExpectedConnectionID:    connection.ID,
		ExpectedConfigRevision:  connection.Revision,
		ExpectedCheckGeneration: connection.CheckGeneration,
		ExpectedBindingRevision: connection.BindingRevision,
		RepositoryID:            row.RepositoryID,
		RepositoryCreatedAt:     row.RepositoryCreatedAt,
		ConfirmBind:             true,
	}
}

func TestRepositoryBindingsUseExactCanonicalMatchingAndFreshnessFirst(t *testing.T) {
	fixture := newServiceFixture(t)
	alpha := ObservedRepository{RemoteID: "100", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main"}
	beta := ObservedRepository{RemoteID: "101", Owner: "fixture-org", Name: "beta", DefaultBranch: "main", Private: true}
	duplicateAlpha := ObservedRepository{RemoteID: "102", Owner: "fixture-org", Name: "alpha", DefaultBranch: "trunk", Private: true}
	connection := createCheckedConnection(
		t,
		fixture,
		observedRepositories(alpha, beta),
		observedRepositories(alpha, duplicateAlpha, beta),
	)
	insertBindingTestRepository(t, fixture, 11, " Forgejo ", "https://FORGE.example.test:443/", "fixture-org", "alpha", "develop", false, bindingTestCreatedAt(11))
	insertBindingTestRepository(t, fixture, 12, "codeberg", "https://forge.example.test", "fixture-org", "beta", "release", true, bindingTestCreatedAt(12))
	insertBindingTestRepository(t, fixture, 13, "gitea", "https://forge.example.test", "fixture-org", "alpha", "main", true, bindingTestCreatedAt(13))
	insertBindingTestRepository(t, fixture, 14, "forgejo", "https://forge.example.test", "Fixture-org", "alpha", "main", true, bindingTestCreatedAt(14))

	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !model.Current || len(model.Rows) != 2 {
		t.Fatalf("current exact model: %+v", model)
	}
	alphaRow := bindingRowForRepository(t, model, 11)
	if alphaRow.State != RepositoryBindingReady || !alphaRow.State.CanBind() || alphaRow.LocalActive ||
		alphaRow.LocalDefaultBranch != "develop" || alphaRow.RemoteDefaultBranch != "main" {
		t.Fatalf("inactive alias match with differing default branch: %+v", alphaRow)
	}
	betaRow := bindingRowForRepository(t, model, 12)
	if betaRow.State != RepositoryBindingReady || !betaRow.State.CanBind() || !betaRow.LocalActive {
		t.Fatalf("codeberg alias match: %+v", betaRow)
	}

	// A legacy-empty alias at the same canonical URL makes the locator
	// ambiguous across local rows, even though the raw repository uniqueness
	// constraint sees different forge and URL strings.
	insertBindingTestRepository(t, fixture, 15, "", "https://forge.example.test/", "fixture-org", "alpha", "main", true, bindingTestCreatedAt(15))
	model, err = fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row := bindingRowForRemote(t, model, "fixture-org/alpha"); row.State != RepositoryBindingMultipleLocalMatches || row.State.CanBind() {
		t.Fatalf("cross-alias duplicate local state: %+v", row)
	}

	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM repositories WHERE id = 15`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connection.ID, connection.Revision); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	model, err = fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bindingRowForRemote(t, model, "fixture-org/alpha")
	if duplicate.State != RepositoryBindingDuplicateRemoteLocator || duplicate.State.CanBind() ||
		duplicate.RemoteDefaultBranch != "" || duplicate.RemotePrivate != nil {
		t.Fatalf("duplicate remote locator state: %+v", duplicate)
	}

	edit := validEditInput(connection.ID, connection.Revision)
	edit.DisplayName = "Edited fixture forge"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	model, err = fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if model.Current {
		t.Fatal("edited connection retained current binding evidence")
	}
	for _, row := range model.Rows {
		if row.State != RepositoryBindingPreviewNotCurrent || row.State.CanBind() {
			t.Fatalf("freshness did not take precedence: %+v", row)
		}
	}
}

func TestRepositoryBindingsSortCombinedRowsAndKeepStaleRemoteIdentities(t *testing.T) {
	fixture := newServiceFixture(t)
	connection := createCheckedConnection(t, fixture, observedRepositories(
		ObservedRepository{RemoteID: "9", Owner: "fixture-org", Name: "alpha", DefaultBranch: "nine", Private: true},
		ObservedRepository{RemoteID: "10", Owner: "fixture-org", Name: "alpha", DefaultBranch: "ten"},
		ObservedRepository{RemoteID: "20", Owner: "fixture-org", Name: "zeta", DefaultBranch: "main"},
	))
	insertBindingTestRepository(
		t,
		fixture,
		61,
		"forgejo",
		"https://forge.example.test",
		"fixture-org",
		"zeta",
		"main",
		true,
		bindingTestCreatedAt(61),
	)
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.BindRepository(
		fixture.ctx,
		fixture.adminID,
		validBindInput(connection, bindingRowForRepository(t, model, 61)),
	); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	edit := validEditInput(connection.ID, connection.Revision)
	edit.DisplayName = "Stale ordering fixture"
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
		t.Fatal(err)
	}

	model, err = fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Rows) != 3 {
		t.Fatalf("stale identities were collapsed: %+v", model.Rows)
	}
	if model.Rows[0].RemoteFullName != "fixture-org/alpha" || model.Rows[0].RemoteDefaultBranch != "ten" ||
		model.Rows[1].RemoteFullName != "fixture-org/alpha" || model.Rows[1].RemoteDefaultBranch != "nine" ||
		model.Rows[2].RepositoryID != 61 || model.Rows[2].RemoteFullName != "fixture-org/zeta" {
		t.Fatalf("combined rows not sorted by display name, local id, and opaque remote id: %+v", model.Rows)
	}
}

func TestBindAndUnbindRepositoryAreInertAuditedAndResetFenced(t *testing.T) {
	fixture := newServiceFixture(t)
	connection := createCheckedConnection(t, fixture, successObservation())
	createdAt := bindingTestCreatedAt(21)
	insertBindingTestRepository(t, fixture, 21, "forgejo", "https://forge.example.test", "fixture-org", "alpha", "release", false, createdAt)
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO repository_branches(repository_id, name, protected, setup_status)
VALUES (21, 'release', 1, 'ok');
INSERT INTO repository_grants(repository_id, user_id, role, granted_by_user_id, granted_at)
VALUES (21, 1, 'freezer', 1, ?);
INSERT INTO repository_webhook_secrets(repository_id, ciphertext, updated_at)
VALUES (21, x'010203', ?);
INSERT INTO repository_status_tokens(repository_id, ciphertext, updated_at)
VALUES (21, x'040506', ?);
INSERT INTO branch_freezes(
  repository_id, branch, status, reason, scheduled, created_at, updated_at
)
VALUES (21, 'release', 'active', 'preserved freeze', 0, ?, ?)`,
		createdAt,
		createdAt,
		createdAt,
		createdAt,
		createdAt,
	); err != nil {
		t.Fatal(err)
	}

	snapshot := repositoryOwnedState(t, fixture.database, 21)
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	ready := bindingRowForRepository(t, model, 21)
	fixture.service.secrets = nil
	fixture.service.observer = nil
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, validBindInput(connection, ready)); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil || connection.BindingRevision != 1 {
		t.Fatalf("binding revision after bind: %d err=%v", connection.BindingRevision, err)
	}
	if got := repositoryOwnedState(t, fixture.database, 21); got != snapshot {
		t.Fatalf("bind changed repository-owned state:\nbefore %s\nafter  %s", snapshot, got)
	}
	assertForgeAudit(t, fixture.database, audit.ActionForgeRepositoryBound, connection.ID, map[string]any{
		"repository_id":         float64(21),
		"repository_created_at": ready.RepositoryCreatedAt,
		"config_revision":       float64(1),
		"check_generation":      float64(1),
		"binding_revision":      float64(1),
	})

	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{
		ExpectedConnectionID:    connection.ID,
		ExpectedRevision:        connection.Revision,
		ExpectedBindingRevision: connection.BindingRevision,
		ConfirmReset:            true,
	}); !errors.Is(err, ErrBindingsExist) {
		t.Fatalf("reset with binding error = %v, want ErrBindingsExist", err)
	}

	// Unbind does not need preview evidence, encryption, PAT decryption, or a
	// provider adapter. Only the immutable binding row is deleted.
	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM forge_visible_repositories; DELETE FROM forge_connection_setup_checks`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.UnbindRepository(fixture.ctx, fixture.adminID, UnbindRepositoryInput{
		ExpectedConnectionID:    connection.ID,
		ExpectedConfigRevision:  connection.Revision,
		ExpectedBindingRevision: connection.BindingRevision,
		RepositoryID:            21,
		ConfirmUnbind:           true,
	}); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil || connection.BindingRevision != 2 {
		t.Fatalf("binding revision after unbind: %d err=%v", connection.BindingRevision, err)
	}
	if got := repositoryOwnedState(t, fixture.database, 21); got != snapshot {
		t.Fatalf("unbind changed repository-owned state:\nbefore %s\nafter  %s", snapshot, got)
	}
	assertForgeAudit(t, fixture.database, audit.ActionForgeRepositoryUnbound, connection.ID, map[string]any{
		"repository_id":         float64(21),
		"repository_created_at": ready.RepositoryCreatedAt,
		"config_revision":       float64(1),
		"binding_revision":      float64(2),
	})
	if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{
		ExpectedConnectionID:    connection.ID,
		ExpectedRevision:        connection.Revision,
		ExpectedBindingRevision: connection.BindingRevision,
		ConfirmReset:            true,
	}); err != nil {
		t.Fatal(err)
	}
	if got := repositoryOwnedState(t, fixture.database, 21); got != snapshot {
		t.Fatalf("reset after unbind changed repository-owned state:\nbefore %s\nafter  %s", snapshot, got)
	}
}

func TestBindRepositoryFencesCanonicalIncarnationAndCurrentEvidence(t *testing.T) {
	fixture := newServiceFixture(t)
	alpha := ObservedRepository{RemoteID: "100", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main"}
	beta := ObservedRepository{RemoteID: "101", Owner: "fixture-org", Name: "beta", DefaultBranch: "main", Private: true}
	connection := createCheckedConnection(t, fixture, observedRepositories(alpha, beta), Observation{ResultCode: CheckUnavailable})
	insertBindingTestRepository(t, fixture, 31, "forgejo", "https://forge.example.test", "fixture-org", "alpha", "main", true, bindingTestCreatedAt(31))
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	ready := bindingRowForRepository(t, model, 31)
	valid := validBindInput(connection, ready)

	for _, tc := range []struct {
		name   string
		mutate func(*BindRepositoryInput)
		want   error
	}{
		{name: "connection", mutate: func(input *BindRepositoryInput) { input.ExpectedConnectionID++ }, want: ErrConflict},
		{name: "config revision", mutate: func(input *BindRepositoryInput) { input.ExpectedConfigRevision++ }, want: ErrConflict},
		{name: "check generation", mutate: func(input *BindRepositoryInput) { input.ExpectedCheckGeneration++ }, want: ErrConflict},
		{name: "binding revision", mutate: func(input *BindRepositoryInput) { input.ExpectedBindingRevision++ }, want: ErrConflict},
		{name: "confirmation", mutate: func(input *BindRepositoryInput) { input.ConfirmBind = false }},
		{name: "noncanonical timestamp", mutate: func(input *BindRepositoryInput) { input.RepositoryCreatedAt = "2026-08-02T10:00:00.000000000Z" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := valid
			tc.mutate(&input)
			err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("error = %v, want %v", err, tc.want)
				}
			} else if !IsValidationError(err) {
				t.Fatalf("error = %v, want validation error", err)
			}
		})
	}

	// Reusing the same integer id for a replacement row cannot satisfy a form
	// issued for the former repository incarnation.
	if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM repositories WHERE id = 31`); err != nil {
		t.Fatal(err)
	}
	insertBindingTestRepository(t, fixture, 31, "forgejo", "https://forge.example.test", "fixture-org", "alpha", "main", true, bindingTestCreatedAt(32))
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, valid); !errors.Is(err, ErrConflict) {
		t.Fatalf("replacement repository error = %v, want ErrConflict", err)
	}

	// A newer failed check is structurally current evidence, but not a current
	// successful preview. Retained rows cannot authorize a bind.
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connection.ID, connection.Revision); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	model, err = fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if model.Current {
		t.Fatal("failed check produced current binding evidence")
	}
	staleInput := valid
	staleInput.ExpectedCheckGeneration = connection.CheckGeneration
	staleInput.RepositoryCreatedAt = bindingTestCreatedAt(32)
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, staleInput); !errors.Is(err, ErrBindingUnavailable) {
		t.Fatalf("bind against failed evidence error = %v, want ErrBindingUnavailable", err)
	}
	assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 0)
}

func TestBoundRepositoryReadModelReportsDriftReplacementAbsenceAndStaleness(t *testing.T) {
	alpha := ObservedRepository{RemoteID: "100", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main"}
	beta := ObservedRepository{RemoteID: "101", Owner: "fixture-org", Name: "beta", DefaultBranch: "main", Private: true}

	t.Run("local rename is locator drift", func(t *testing.T) {
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta))
		if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE repositories SET name = 'renamed-local' WHERE id = 41`); err != nil {
			t.Fatal(err)
		}
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		if row := bindingRowForRepository(t, model, 41); row.State != RepositoryBindingLocatorDrift {
			t.Fatalf("local rename state: %+v", row)
		}
	})

	t.Run("local drift with a duplicate bound remote locator keeps current evidence", func(t *testing.T) {
		renamed := ObservedRepository{
			RemoteID:      "100",
			Owner:         "fixture-org",
			Name:          "renamed-remote",
			DefaultBranch: "release",
			Private:       true,
		}
		duplicate := renamed
		duplicate.RemoteID = "102"
		fixture, connection := boundRepositoryFixture(
			t,
			observedRepositories(alpha, beta),
			observedRepositories(renamed, duplicate, beta),
		)
		if _, err := fixture.database.ExecContext(
			fixture.ctx,
			`UPDATE repositories SET name = 'renamed-local' WHERE id = 41`,
		); err != nil {
			t.Fatal(err)
		}
		observedAt := time.Date(2040, 8, 10, 12, 34, 56, 789, time.UTC)
		fixture.service.now = func() time.Time { return observedAt }
		connection = runNextBindingCheck(t, fixture, connection)

		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if row.State != RepositoryBindingIdentityConflict ||
			row.LocalFullName != "fixture-org/renamed-local" ||
			row.RemoteFullName != "fixture-org/renamed-remote" ||
			!row.ObservedAt.Equal(observedAt) ||
			row.RemoteDefaultBranch != "release" ||
			row.RemotePrivate == nil || !*row.RemotePrivate ||
			!slices.Contains(row.RemoteFullNames, "fixture-org/renamed-remote") {
			t.Fatalf("drifted duplicate bound locator evidence: %+v", row)
		}
		if len(model.Rows) != 2 {
			t.Fatalf("duplicate bound locator rendered outside its conflict row: %+v", model.Rows)
		}
	})

	t.Run("remote rename is locator drift", func(t *testing.T) {
		renamed := ObservedRepository{RemoteID: "100", Owner: "fixture-org", Name: "renamed-remote", DefaultBranch: "main"}
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(renamed, beta))
		connection = runNextBindingCheck(t, fixture, connection)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if row.State != RepositoryBindingLocatorDrift || row.RemoteFullName != "fixture-org/renamed-remote" {
			t.Fatalf("remote rename state: %+v", row)
		}
	})

	t.Run("replacement identity is conflict", func(t *testing.T) {
		replacement := ObservedRepository{RemoteID: "102", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main"}
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(replacement, beta))
		connection = runNextBindingCheck(t, fixture, connection)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if row.State != RepositoryBindingIdentityConflict || row.RemoteFullName != "fixture-org/alpha" {
			t.Fatalf("replacement state: %+v", row)
		}
		if len(model.Rows) != 2 {
			t.Fatalf("replacement locator was rendered outside its binding conflict row: %+v", model.Rows)
		}
	})

	t.Run("replacement visibility comes from the local locator", func(t *testing.T) {
		renamed := ObservedRepository{RemoteID: "100", Owner: "fixture-org", Name: "renamed-remote", DefaultBranch: "main"}
		replacement := ObservedRepository{RemoteID: "102", Owner: "fixture-org", Name: "alpha", DefaultBranch: "release", Private: true}
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(renamed, replacement, beta))
		connection = runNextBindingCheck(t, fixture, connection)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if row.State != RepositoryBindingIdentityConflict || row.RemoteFullName != "fixture-org/alpha" ||
			row.RemoteDefaultBranch != "release" || row.RemotePrivate == nil || !*row.RemotePrivate ||
			!slices.Contains(row.RemoteFullNames, "fixture-org/renamed-remote") {
			t.Fatalf("rename-plus-replacement state: %+v", row)
		}
		if len(model.Rows) != 2 {
			t.Fatalf("related conflict locators were rendered separately: %+v", model.Rows)
		}
	})

	t.Run("duplicate current locator is one conflict row", func(t *testing.T) {
		duplicate := ObservedRepository{RemoteID: "102", Owner: "fixture-org", Name: "alpha", DefaultBranch: "trunk", Private: true}
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(alpha, duplicate, beta))
		connection = runNextBindingCheck(t, fixture, connection)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if row.State != RepositoryBindingIdentityConflict || row.RemoteDefaultBranch != "" || row.RemotePrivate != nil {
			t.Fatalf("duplicate bound locator state: %+v", row)
		}
		for _, candidate := range model.Rows {
			if candidate.State == RepositoryBindingDuplicateRemoteLocator {
				t.Fatalf("consumed duplicate group rendered twice: %+v", model.Rows)
			}
		}
	})

	t.Run("missing from successful preview", func(t *testing.T) {
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(beta))
		connection = runNextBindingCheck(t, fixture, connection)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		if row := bindingRowForRepository(t, model, 41); row.State != RepositoryBindingNotVisible {
			t.Fatalf("missing preview state: %+v", row)
		}
	})

	t.Run("stale evidence is last observed only", func(t *testing.T) {
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta))
		edit := validEditInput(connection.ID, connection.Revision)
		edit.DisplayName = "Edited after binding"
		if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
			t.Fatal(err)
		}
		connection, _, _ = fixture.service.Current(fixture.ctx)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if model.Current || row.State != RepositoryBindingLastObservedOnly || row.State.CanBind() || !row.State.CanUnbind() {
			t.Fatalf("stale bound state: model=%+v row=%+v", model, row)
		}
	})

	t.Run("stale duplicate locator remains a separate identity", func(t *testing.T) {
		duplicate := ObservedRepository{RemoteID: "102", Owner: "fixture-org", Name: "alpha", DefaultBranch: "trunk", Private: true}
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(alpha, duplicate, beta))
		connection = runNextBindingCheck(t, fixture, connection)
		edit := validEditInput(connection.ID, connection.Revision)
		edit.DisplayName = "Edited after binding"
		if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
			t.Fatal(err)
		}
		connection, _, _ = fixture.service.Current(fixture.ctx)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		row := bindingRowForRepository(t, model, 41)
		if row.State != RepositoryBindingLastObservedOnly || row.RemoteFullName != "fixture-org/alpha" ||
			row.RemoteDefaultBranch != "main" || row.RemotePrivate == nil || *row.RemotePrivate {
			t.Fatalf("stale duplicate bound state: %+v", row)
		}
		duplicateRows := 0
		for _, candidate := range model.Rows {
			if candidate.RemoteFullName != "fixture-org/alpha" {
				continue
			}
			duplicateRows++
			if candidate.RepositoryID == 0 && (candidate.State != RepositoryBindingPreviewNotCurrent ||
				candidate.RemoteDefaultBranch != "trunk" || candidate.RemotePrivate == nil || !*candidate.RemotePrivate) {
				t.Fatalf("separate stale duplicate state: %+v", candidate)
			}
		}
		if len(model.Rows) != 3 || duplicateRows != 2 {
			t.Fatalf("stale identities were collapsed: %+v", model.Rows)
		}
	})

	t.Run("stale replacement never names the bound local twice", func(t *testing.T) {
		renamed := ObservedRepository{RemoteID: "100", Owner: "fixture-org", Name: "renamed-remote", DefaultBranch: "main"}
		replacement := ObservedRepository{RemoteID: "102", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main"}
		fixture, connection := boundRepositoryFixture(t, observedRepositories(alpha, beta), observedRepositories(renamed, replacement, beta))
		connection = runNextBindingCheck(t, fixture, connection)
		edit := validEditInput(connection.ID, connection.Revision)
		edit.DisplayName = "Edited after binding"
		if err := fixture.service.Edit(fixture.ctx, fixture.adminID, edit); err != nil {
			t.Fatal(err)
		}
		connection, _, _ = fixture.service.Current(fixture.ctx)
		model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
		if err != nil {
			t.Fatal(err)
		}
		named := 0
		for _, row := range model.Rows {
			if row.RepositoryID == 41 || row.LocalFullName == "fixture-org/alpha" {
				named++
			}
		}
		if named != 1 {
			t.Fatalf("bound local repository named %d times: %+v", named, model.Rows)
		}
	})
}

func TestApplyRemoteRepositoryGroupKeepsAgreedFieldsIndependent(t *testing.T) {
	observedAt := time.Date(2040, 8, 10, 12, 34, 56, 789, time.UTC)
	row := RepositoryBindingRow{}
	applyRemoteRepositoryGroup(&row, []remoteRepositoryRecord{
		{
			remoteID:      "100",
			owner:         "fixture-org",
			name:          "alpha",
			defaultBranch: "main",
			private:       true,
			observedAt:    observedAt,
		},
		{
			remoteID:      "101",
			owner:         "fixture-org",
			name:          "renamed-alpha",
			defaultBranch: "main",
			private:       true,
			observedAt:    observedAt,
		},
	})
	if row.RemoteFullName != "" || row.RemoteDefaultBranch != "main" ||
		row.RemotePrivate == nil || !*row.RemotePrivate ||
		!row.ObservedAt.Equal(observedAt) ||
		!slices.Equal(row.RemoteFullNames, []string{"fixture-org/alpha", "fixture-org/renamed-alpha"}) {
		t.Fatalf("independent remote group agreement: %+v", row)
	}
}

func TestRepositoryBindingAuditFailuresRollbackAndBindIsSerialized(t *testing.T) {
	t.Run("bind audit rollback", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 51)
		if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER fail_forge_repository_bound
BEFORE INSERT ON audit_events
WHEN NEW.action = 'forge.repository_bound'
BEGIN
  SELECT RAISE(ABORT, 'forced binding audit failure');
END`); err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); err == nil {
			t.Fatal("bind succeeded despite audit failure")
		}
		assertBindingStorage(t, fixture.database, connection.ID, 0, 0)
	})

	t.Run("unbind audit rollback", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 52)
		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER fail_forge_repository_unbound
BEFORE INSERT ON audit_events
WHEN NEW.action = 'forge.repository_unbound'
BEGIN
  SELECT RAISE(ABORT, 'forced unbind audit failure');
END`); err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.UnbindRepository(fixture.ctx, fixture.adminID, UnbindRepositoryInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedConfigRevision:  connection.Revision,
			ExpectedBindingRevision: 1,
			RepositoryID:            52,
			ConfirmUnbind:           true,
		}); err == nil {
			t.Fatal("unbind succeeded despite audit failure")
		}
		assertBindingStorage(t, fixture.database, connection.ID, 1, 1)
	})

	t.Run("reset audit rollback", func(t *testing.T) {
		fixture := newServiceFixture(t)
		connection := createCheckedConnection(t, fixture, successObservation())
		if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER fail_forge_connection_reset
BEFORE INSERT ON audit_events
WHEN NEW.action = 'forge.connection_reset'
BEGIN
  SELECT RAISE(ABORT, 'forced reset audit failure');
END`); err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.Reset(fixture.ctx, fixture.adminID, ResetInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedRevision:        connection.Revision,
			ExpectedBindingRevision: connection.BindingRevision,
			ConfirmReset:            true,
		}); err == nil {
			t.Fatal("reset succeeded despite audit failure")
		}
		if _, found, err := fixture.service.Current(fixture.ctx); err != nil || !found {
			t.Fatalf("reset audit failure did not roll back connection: found=%v err=%v", found, err)
		}
		for _, table := range []string{
			"forgejo_connection_config",
			"forge_organizations",
			"forge_visible_repositories",
			"forge_connection_setup_checks",
		} {
			var count int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM ` + table).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				t.Fatalf("reset audit failure deleted %s", table)
			}
		}
	})

	t.Run("concurrent bind", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 53)
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				results <- fixture.service.BindRepository(context.Background(), fixture.adminID, input)
			}()
		}
		close(start)
		errorsSeen := []error{<-results, <-results}
		successes := 0
		conflicts := 0
		for _, err := range errorsSeen {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Fatalf("concurrent bind error = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent bind successes=%d conflicts=%d errors=%v", successes, conflicts, errorsSeen)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 1, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 1)
	})

	t.Run("concurrent unbind", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 54)
		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); err != nil {
			t.Fatal(err)
		}
		unbind := UnbindRepositoryInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedConfigRevision:  connection.Revision,
			ExpectedBindingRevision: 1,
			RepositoryID:            54,
			ConfirmUnbind:           true,
		}
		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				results <- fixture.service.UnbindRepository(context.Background(), fixture.adminID, unbind)
			}()
		}
		close(start)
		errorsSeen := []error{<-results, <-results}
		successes := 0
		conflicts := 0
		for _, err := range errorsSeen {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Fatalf("concurrent unbind error = %v", err)
			}
		}
		if successes != 1 || conflicts != 1 {
			t.Fatalf("concurrent unbind successes=%d conflicts=%d errors=%v", successes, conflicts, errorsSeen)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 0, 2)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryUnbound, 1)
	})
}

func TestRepositoryBindingCommitFailuresReturnUnknownAndRollBack(t *testing.T) {
	t.Run("bind", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 59)
		injectRepositoryBindingCommitFailure(t, fixture.database)

		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrBindingOutcomeUnknown) {
			t.Fatalf("bind commit failure error = %v, want ErrBindingOutcomeUnknown", err)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 0, 0)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 0)
		assertRepositoryBindingCommitFailureRolledBack(t, fixture.database)
	})

	t.Run("unbind", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 60)
		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); err != nil {
			t.Fatal(err)
		}
		injectRepositoryBindingCommitFailure(t, fixture.database)

		err := fixture.service.UnbindRepository(fixture.ctx, fixture.adminID, UnbindRepositoryInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedConfigRevision:  connection.Revision,
			ExpectedBindingRevision: 1,
			RepositoryID:            input.RepositoryID,
			ConfirmUnbind:           true,
		})
		if !errors.Is(err, ErrBindingOutcomeUnknown) {
			t.Fatalf("unbind commit failure error = %v, want ErrBindingOutcomeUnknown", err)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 1, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryUnbound, 0)
		assertRepositoryBindingCommitFailureRolledBack(t, fixture.database)
	})
}

func TestBindFirstThenCheckKeepsBindingCurrent(t *testing.T) {
	fixture, connection, input := readyBindingFixture(t, 61)
	fixture.observer.observations = append(fixture.observer.observations, successObservation())

	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.Check(
		fixture.ctx,
		fixture.adminID,
		connection.ID,
		connection.Revision,
	); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.CheckGeneration != 2 || connection.BindingRevision != 1 {
		t.Fatalf("connection after bind-first check: found=%v connection=%+v err=%v", found, connection, err)
	}
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row := bindingRowForRepository(t, model, input.RepositoryID); !model.Current || row.State != RepositoryBindingCurrent {
		t.Fatalf("binding after bind-first check: model=%+v row=%+v", model, row)
	}
	assertBindingStorage(t, fixture.database, connection.ID, 1, 1)
	assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 1)
}

func TestCheckFirstReservationMakesAnOlderBindStale(t *testing.T) {
	fixture, connection, input := readyBindingFixture(t, 55)
	gate := make(chan struct{})
	fixture.observer.observations = append(fixture.observer.observations, successObservation())
	fixture.observer.gates = []chan struct{}{nil, gate}
	fixture.observer.started = make(chan struct{}, 1)

	checkResult := make(chan error, 1)
	go func() {
		_, err := fixture.service.Check(context.Background(), fixture.adminID, connection.ID, connection.Revision)
		checkResult <- err
	}()
	<-fixture.observer.started

	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrConflict) {
		t.Fatalf("bind after a newer check reservation error = %v, want ErrConflict", err)
	}
	close(gate)
	if err := <-checkResult; err != nil {
		t.Fatalf("persist reserved check: %v", err)
	}
	assertBindingStorage(t, fixture.database, connection.ID, 0, 0)
	assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 0)
}

func TestResetAndBindSerializedOrders(t *testing.T) {
	t.Run("bind first", func(t *testing.T) {
		fixture, connection, bindInput := readyBindingFixture(t, 56)
		resetInput := ResetInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedRevision:        connection.Revision,
			ExpectedBindingRevision: connection.BindingRevision,
			ConfirmReset:            true,
		}

		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, bindInput); err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.Reset(fixture.ctx, fixture.adminID, resetInput); !errors.Is(err, ErrConflict) {
			t.Fatalf("reset after bind error = %v, want ErrConflict", err)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 1, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeConnectionReset, 0)
	})

	t.Run("reset first", func(t *testing.T) {
		fixture, connection, bindInput := readyBindingFixture(t, 56)
		resetInput := ResetInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedRevision:        connection.Revision,
			ExpectedBindingRevision: connection.BindingRevision,
			ConfirmReset:            true,
		}

		if err := fixture.service.Reset(fixture.ctx, fixture.adminID, resetInput); err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, bindInput); !errors.Is(err, ErrConflict) {
			t.Fatalf("bind after reset error = %v, want ErrConflict", err)
		}
		var connections, bindings, repositories int
		if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_connections`).Scan(&connections); err != nil {
			t.Fatal(err)
		}
		if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_repository_bindings`).Scan(&bindings); err != nil {
			t.Fatal(err)
		}
		if err := fixture.database.QueryRow(`SELECT count(*) FROM repositories WHERE id = ?`, bindInput.RepositoryID).Scan(&repositories); err != nil {
			t.Fatal(err)
		}
		if connections != 0 || bindings != 0 || repositories != 1 {
			t.Fatalf(
				"reset-first state connections=%d bindings=%d repositories=%d",
				connections,
				bindings,
				repositories,
			)
		}
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 0)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeConnectionReset, 1)
	})
}

func TestConcurrentBindAndUnbindSerializeOnBindingRevision(t *testing.T) {
	fixture, connection, bindAlpha := readyBindingFixture(t, 62)
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, bindAlpha); err != nil {
		t.Fatal(err)
	}
	insertBindingTestRepository(
		t,
		fixture,
		63,
		"forgejo",
		"https://forge.example.test",
		"fixture-org",
		"beta",
		"main",
		true,
		bindingTestCreatedAt(63),
	)
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.BindingRevision != 1 {
		t.Fatalf("connection before concurrent bind/unbind: found=%v connection=%+v err=%v", found, connection, err)
	}
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	bindBeta := validBindInput(connection, bindingRowForRepository(t, model, 63))
	unbindAlpha := UnbindRepositoryInput{
		ExpectedConnectionID:    connection.ID,
		ExpectedConfigRevision:  connection.Revision,
		ExpectedBindingRevision: connection.BindingRevision,
		RepositoryID:            bindAlpha.RepositoryID,
		ConfirmUnbind:           true,
	}

	type operationResult struct {
		operation string
		err       error
	}
	start := make(chan struct{})
	results := make(chan operationResult, 2)
	go func() {
		<-start
		results <- operationResult{
			operation: "bind",
			err: fixture.service.BindRepository(
				context.Background(),
				fixture.adminID,
				bindBeta,
			),
		}
	}()
	go func() {
		<-start
		results <- operationResult{
			operation: "unbind",
			err: fixture.service.UnbindRepository(
				context.Background(),
				fixture.adminID,
				unbindAlpha,
			),
		}
	}()
	close(start)

	errorsByOperation := make(map[string]error, 2)
	for range 2 {
		result := <-results
		errorsByOperation[result.operation] = result.err
	}
	bindErr := errorsByOperation["bind"]
	unbindErr := errorsByOperation["unbind"]
	switch {
	case bindErr == nil && errors.Is(unbindErr, ErrConflict):
		assertBindingStorage(t, fixture.database, connection.ID, 2, 2)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 2)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryUnbound, 0)
	case unbindErr == nil && errors.Is(bindErr, ErrConflict):
		assertBindingStorage(t, fixture.database, connection.ID, 0, 2)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryUnbound, 1)
	default:
		t.Fatalf("concurrent bind error=%v unbind error=%v", bindErr, unbindErr)
	}
}

func TestBindingRevisionPreventsBindUnbindBindABA(t *testing.T) {
	fixture, connection, originalBind := readyBindingFixture(t, 57)
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, originalBind); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.UnbindRepository(fixture.ctx, fixture.adminID, UnbindRepositoryInput{
		ExpectedConnectionID:    connection.ID,
		ExpectedConfigRevision:  connection.Revision,
		ExpectedBindingRevision: 1,
		RepositoryID:            originalBind.RepositoryID,
		ConfirmUnbind:           true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, originalBind); !errors.Is(err, ErrConflict) {
		t.Fatalf("original bind replay error = %v, want ErrConflict", err)
	}

	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.BindingRevision != 2 {
		t.Fatalf("connection after bind/unbind: found=%v connection=%+v err=%v", found, connection, err)
	}
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	freshBind := validBindInput(connection, bindingRowForRepository(t, model, originalBind.RepositoryID))
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, freshBind); err != nil {
		t.Fatalf("fresh bind after ABA fence: %v", err)
	}
	assertBindingStorage(t, fixture.database, connection.ID, 1, 3)
	assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 2)
	assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryUnbound, 1)
}

func TestBindUnbindAndResetRecheckAdministratorAuthority(t *testing.T) {
	t.Run("bind", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 58)
		err := runForgeWriterAfterAdministratorDemotion(t, fixture, func(ctx context.Context) error {
			return fixture.service.BindRepository(ctx, fixture.adminID, input)
		})
		if !errors.Is(err, ErrAuthorization) {
			t.Fatalf("bind after Administrator demotion error = %v, want ErrAuthorization", err)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 0, 0)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryBound, 0)
	})

	t.Run("unbind", func(t *testing.T) {
		fixture, connection, input := readyBindingFixture(t, 64)
		if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, input); err != nil {
			t.Fatal(err)
		}
		unbind := UnbindRepositoryInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedConfigRevision:  connection.Revision,
			ExpectedBindingRevision: 1,
			RepositoryID:            input.RepositoryID,
			ConfirmUnbind:           true,
		}
		err := runForgeWriterAfterAdministratorDemotion(t, fixture, func(ctx context.Context) error {
			return fixture.service.UnbindRepository(ctx, fixture.adminID, unbind)
		})
		if !errors.Is(err, ErrAuthorization) {
			t.Fatalf("unbind after Administrator demotion error = %v, want ErrAuthorization", err)
		}
		assertBindingStorage(t, fixture.database, connection.ID, 1, 1)
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeRepositoryUnbound, 0)
	})

	t.Run("reset", func(t *testing.T) {
		fixture := newServiceFixture(t)
		connection := createCheckedConnection(t, fixture, successObservation())
		reset := ResetInput{
			ExpectedConnectionID:    connection.ID,
			ExpectedRevision:        connection.Revision,
			ExpectedBindingRevision: connection.BindingRevision,
			ConfirmReset:            true,
		}
		err := runForgeWriterAfterAdministratorDemotion(t, fixture, func(ctx context.Context) error {
			return fixture.service.Reset(ctx, fixture.adminID, reset)
		})
		if !errors.Is(err, ErrAuthorization) {
			t.Fatalf("reset after Administrator demotion error = %v, want ErrAuthorization", err)
		}
		current, found, err := fixture.service.Current(fixture.ctx)
		if err != nil || !found || current.ID != connection.ID {
			t.Fatalf("connection after rejected reset: found=%v connection=%+v err=%v", found, current, err)
		}
		assertForgeAuditCount(t, fixture.database, audit.ActionForgeConnectionReset, 0)
	})
}

func runForgeWriterAfterAdministratorDemotion(
	t *testing.T,
	fixture *serviceFixture,
	operation func(context.Context) error,
) error {
	t.Helper()
	demotion, err := fixture.database.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer demotion.Rollback()
	if _, err := demotion.ExecContext(
		fixture.ctx,
		`DELETE FROM user_roles WHERE user_id = ?`,
		fixture.adminID,
	); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	go func() {
		result <- operation(context.Background())
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for fixture.database.Stats().InUse < 2 {
		select {
		case <-deadline.C:
			t.Fatal("Forge writer did not start while the authority change held SQLite's writer lock")
		default:
			runtime.Gosched()
		}
	}
	if err := demotion.Commit(); err != nil {
		t.Fatal(err)
	}
	return <-result
}

func boundRepositoryFixture(t *testing.T, observations ...Observation) (*serviceFixture, Connection) {
	t.Helper()
	fixture := newServiceFixture(t)
	connection := createCheckedConnection(t, fixture, observations...)
	insertBindingTestRepository(t, fixture, 41, "forgejo", "https://forge.example.test", "fixture-org", "alpha", "main", true, bindingTestCreatedAt(41))
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.BindRepository(fixture.ctx, fixture.adminID, validBindInput(connection, bindingRowForRepository(t, model, 41))); err != nil {
		t.Fatal(err)
	}
	connection, _, err = fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, connection
}

func runNextBindingCheck(t *testing.T, fixture *serviceFixture, connection Connection) Connection {
	t.Helper()
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID, connection.ID, connection.Revision); err != nil {
		t.Fatal(err)
	}
	connection, _, err := fixture.service.Current(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func readyBindingFixture(t *testing.T, repositoryID int64) (*serviceFixture, Connection, BindRepositoryInput) {
	t.Helper()
	fixture := newServiceFixture(t)
	connection := createCheckedConnection(t, fixture, successObservation())
	insertBindingTestRepository(t, fixture, repositoryID, "forgejo", "https://forge.example.test", "fixture-org", "alpha", "main", true, bindingTestCreatedAt(repositoryID))
	model, err := fixture.service.RepositoryBindings(fixture.ctx, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	return fixture, connection, validBindInput(connection, bindingRowForRepository(t, model, repositoryID))
}

func repositoryOwnedState(t *testing.T, database *sql.DB, repositoryID int64) string {
	t.Helper()
	queries := []string{
		`SELECT forge || '|' || base_url || '|' || owner || '|' || name || '|' || default_branch || '|' || active || '|' || enforcement_state || '|' || created_at || '|' || updated_at FROM repositories WHERE id = ?`,
		`SELECT count(*) || ':' || coalesce(group_concat(name || protected || setup_status, '|'), '') FROM repository_branches WHERE repository_id = ?`,
		`SELECT count(*) || ':' || coalesce(group_concat(user_id || role || coalesce(granted_by_user_id, 0), '|'), '') FROM repository_grants WHERE repository_id = ?`,
		`SELECT count(*) || ':' || coalesce(sum(length(ciphertext)), 0) FROM repository_webhook_secrets WHERE repository_id = ?`,
		`SELECT count(*) || ':' || coalesce(sum(length(ciphertext)), 0) FROM repository_status_tokens WHERE repository_id = ?`,
		`SELECT count(*) || ':' || coalesce(group_concat(branch || status || reason, '|'), '') FROM branch_freezes WHERE repository_id = ?`,
	}
	parts := make([]string, 0, len(queries))
	for _, query := range queries {
		var part string
		if err := database.QueryRow(query, repositoryID).Scan(&part); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "\n")
}

func injectRepositoryBindingCommitFailure(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.Exec(`
CREATE TABLE test_repository_binding_commit_failure (
  missing_user_id INTEGER NOT NULL,
  FOREIGN KEY (missing_user_id) REFERENCES users(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER test_repository_binding_commit_failure_trigger
AFTER INSERT ON audit_events
WHEN NEW.action IN ('forge.repository_bound', 'forge.repository_unbound')
BEGIN
  INSERT INTO test_repository_binding_commit_failure(missing_user_id) VALUES (-1);
END;`); err != nil {
		t.Fatal(err)
	}
}

func assertRepositoryBindingCommitFailureRolledBack(t *testing.T, database *sql.DB) {
	t.Helper()
	var rows int
	if err := database.QueryRow(`SELECT count(*) FROM test_repository_binding_commit_failure`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("deferred commit-failure rows = %d, want 0", rows)
	}
}

func assertBindingStorage(t *testing.T, database *sql.DB, connectionID int64, wantBindings, wantRevision int) {
	t.Helper()
	var bindings, revision int
	if err := database.QueryRow(`SELECT count(*) FROM forge_repository_bindings WHERE connection_id = ?`, connectionID).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT binding_revision FROM forge_connections WHERE id = ?`, connectionID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if bindings != wantBindings || revision != wantRevision {
		t.Fatalf("binding storage rows=%d revision=%d, want rows=%d revision=%d", bindings, revision, wantBindings, wantRevision)
	}
}
