package forgeconnection

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

type countingAccessShadowSecretStore struct {
	delegate     secrets.Store
	decryptCalls int
}

func (s *countingAccessShadowSecretStore) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return s.delegate.Encrypt(ctx, plaintext)
}

func (s *countingAccessShadowSecretStore) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	s.decryptCalls++
	return s.delegate.Decrypt(ctx, ciphertext)
}

func (f *accessShadowFixture) validPeriodicEnableInput() EnableAccessShadowPeriodicInput {
	return EnableAccessShadowPeriodicInput{
		ExpectedConnectionID:           1,
		ExpectedConfigRevision:         3,
		ExpectedCheckGeneration:        5,
		ExpectedBindingRevision:        2,
		ExpectedAccessIdentityRevision: 2,
		ExpectedNewestRunID:            0,
		ExpectedPeriodicRevision:       0,
		ConfirmPeriodicEnable:          true,
	}
}

func (f *accessShadowFixture) enablePeriodic(t *testing.T) {
	t.Helper()
	changed, err := f.service.EnablePeriodic(f.ctx, f.adminID, f.validPeriodicEnableInput())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first enable did not report its configuration change")
	}
}

func (f *accessShadowFixture) periodicConfig(t *testing.T) (int64, sql.NullString) {
	t.Helper()
	var revision int64
	var nextDueAt sql.NullString
	if err := f.database.QueryRowContext(f.ctx, `
SELECT revision, next_due_at
FROM forge_access_shadow_periodic_config
WHERE connection_id = 1`).Scan(&revision, &nextDueAt); err != nil {
		t.Fatal(err)
	}
	return revision, nextDueAt
}

func (f *accessShadowFixture) setPeriodicDue(t *testing.T, due time.Time) {
	t.Helper()
	if _, err := f.database.ExecContext(f.ctx, `
UPDATE forge_access_shadow_periodic_config
SET next_due_at = ?
WHERE connection_id = 1`, formatForgeConnectionTime(due)); err != nil {
		t.Fatal(err)
	}
}

func TestAccessShadowPeriodicEnableDisableCASAndAudit(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	secretStore := &countingAccessShadowSecretStore{delegate: fixture.service.secrets}
	fixture.service.secrets = secretStore
	fixture.enablePeriodic(t)
	if secretStore.decryptCalls != 0 || len(fixture.observer.inputs) != 0 {
		t.Fatalf("enable performed PAT decryption/provider calls = %d/%d", secretStore.decryptCalls, len(fixture.observer.inputs))
	}

	revision, due := fixture.periodicConfig(t)
	wantDue := fixture.clock.Now().Add(accessShadowPeriodicCadence)
	if revision != 1 || !due.Valid || due.String != formatForgeConnectionTime(wantDue) {
		t.Fatalf("first enable config = revision %d due %q", revision, due.String)
	}
	enabled := fixture.auditDetails(t, audit.ActionForgeAccessPeriodicEnabled)
	actors := fixture.auditActors(t, audit.ActionForgeAccessPeriodicEnabled)
	if len(enabled) != 1 || enabled[0]["revision"] != float64(1) ||
		len(actors) != 1 || !actors[0].Valid || actors[0].Int64 != fixture.adminID {
		t.Fatalf("enable audit details=%v actors=%v", enabled, actors)
	}

	// Stale expected state wins over the already-enabled no-op.
	staleEnable := fixture.validPeriodicEnableInput()
	if _, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, staleEnable); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale already-enabled call = %v", err)
	}
	exactEnable := fixture.validPeriodicEnableInput()
	exactEnable.ExpectedPeriodicRevision = 1
	changed, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, exactEnable)
	if err != nil {
		t.Fatalf("exact already-enabled call = %v", err)
	}
	if changed {
		t.Fatal("exact already-enabled call reported a configuration change")
	}
	if got := len(fixture.auditDetails(t, audit.ActionForgeAccessPeriodicEnabled)); got != 1 {
		t.Fatalf("enabled no-op wrote %d audit events", got)
	}

	disable := DisableAccessShadowPeriodicInput{
		ExpectedConnectionID:     1,
		ExpectedPeriodicRevision: 1,
		ConfirmPeriodicDisable:   true,
	}
	if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, disable); err != nil {
		t.Fatal(err)
	}
	revision, due = fixture.periodicConfig(t)
	if revision != 2 || due.Valid {
		t.Fatalf("disable config = revision %d due %+v", revision, due)
	}
	disabled := fixture.auditDetails(t, audit.ActionForgeAccessPeriodicDisabled)
	if len(disabled) != 1 || disabled[0]["revision"] != float64(2) {
		t.Fatalf("disable audit = %v", disabled)
	}

	// Stale expected state also wins over the already-disabled no-op.
	if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, disable); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale already-disabled call = %v", err)
	}
	disable.ExpectedPeriodicRevision = 2
	if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, disable); err != nil {
		t.Fatalf("exact already-disabled call = %v", err)
	}
	if got := len(fixture.auditDetails(t, audit.ActionForgeAccessPeriodicDisabled)); got != 1 {
		t.Fatalf("disabled no-op wrote %d audit events", got)
	}

	reenable := fixture.validPeriodicEnableInput()
	reenable.ExpectedPeriodicRevision = 2
	changed, err = fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, reenable)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("re-enable did not report its configuration change")
	}
	revision, due = fixture.periodicConfig(t)
	if revision != 3 || !due.Valid || due.String != formatForgeConnectionTime(wantDue) {
		t.Fatalf("re-enable config = revision %d due %+v", revision, due)
	}
}

func TestAccessShadowPeriodicAbsentConfigurationIsDisabledRevisionZeroNoOp(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, DisableAccessShadowPeriodicInput{
		ExpectedConnectionID:     1,
		ExpectedPeriodicRevision: 0,
		ConfirmPeriodicDisable:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var configs, events int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_periodic_config`).Scan(&configs); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.QueryRow(`SELECT count(*) FROM audit_events WHERE action = ?`, audit.ActionForgeAccessPeriodicDisabled).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if configs != 0 || events != 0 {
		t.Fatalf("absent disable wrote configurations/events = %d/%d", configs, events)
	}
}

func TestAccessShadowPeriodicEnableRejectsEveryStaleScopeFence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*EnableAccessShadowPeriodicInput)
	}{
		{name: "connection", mutate: func(input *EnableAccessShadowPeriodicInput) { input.ExpectedConnectionID++ }},
		{name: "configuration", mutate: func(input *EnableAccessShadowPeriodicInput) { input.ExpectedConfigRevision++ }},
		{name: "check generation", mutate: func(input *EnableAccessShadowPeriodicInput) { input.ExpectedCheckGeneration++ }},
		{name: "binding revision", mutate: func(input *EnableAccessShadowPeriodicInput) { input.ExpectedBindingRevision++ }},
		{name: "identity revision", mutate: func(input *EnableAccessShadowPeriodicInput) { input.ExpectedAccessIdentityRevision++ }},
		{name: "newest run", mutate: func(input *EnableAccessShadowPeriodicInput) { input.ExpectedNewestRunID++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAccessShadowFixture(t)
			input := fixture.validPeriodicEnableInput()
			tc.mutate(&input)
			if _, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrConflict) {
				t.Fatalf("stale enable error = %v", err)
			}
			var configs int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_periodic_config`).Scan(&configs); err != nil {
				t.Fatal(err)
			}
			if configs != 0 {
				t.Fatalf("stale enable wrote %d configurations", configs)
			}
		})
	}
}

func TestAccessShadowPeriodicConfigurationAuthorizationValidationAndExhaustion(t *testing.T) {
	t.Run("authorization and confirmation", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		if _, err := fixture.service.EnablePeriodic(fixture.ctx, 2, fixture.validPeriodicEnableInput()); !errors.Is(err, ErrAuthorization) {
			t.Fatalf("non-admin enable = %v", err)
		}
		enable := fixture.validPeriodicEnableInput()
		enable.ConfirmPeriodicEnable = false
		if _, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, enable); !IsValidationError(err) {
			t.Fatalf("unconfirmed enable = %v", err)
		}
		disable := DisableAccessShadowPeriodicInput{ExpectedConnectionID: 1, ConfirmPeriodicDisable: false}
		if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, disable); !IsValidationError(err) {
			t.Fatalf("unconfirmed disable = %v", err)
		}
	})

	t.Run("enable exhaustion", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forge_access_shadow_periodic_config(connection_id, revision, next_due_at)
VALUES (1, ?, NULL)`, int64(math.MaxInt64)); err != nil {
			t.Fatal(err)
		}
		input := fixture.validPeriodicEnableInput()
		input.ExpectedPeriodicRevision = math.MaxInt64
		if _, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrAccessPeriodicRevisionExhausted) {
			t.Fatalf("saturated enable = %v", err)
		}
	})

	t.Run("disable exhaustion", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forge_access_shadow_periodic_config(connection_id, revision, next_due_at)
VALUES (1, ?, ?)`, int64(math.MaxInt64), accessShadowFixtureTime); err != nil {
			t.Fatal(err)
		}
		input := DisableAccessShadowPeriodicInput{
			ExpectedConnectionID:     1,
			ExpectedPeriodicRevision: math.MaxInt64,
			ConfirmPeriodicDisable:   true,
		}
		if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrAccessPeriodicRevisionExhausted) {
			t.Fatalf("saturated disable = %v", err)
		}
	})
}

func TestAccessShadowPeriodicEnableRequiresEveryLocalPrerequisite(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*accessShadowFixture)
	}{
		{name: "encryption", mutate: func(f *accessShadowFixture) { f.service.secrets = nil }},
		{name: "setup evidence", mutate: func(f *accessShadowFixture) {
			_, _ = f.database.Exec(`UPDATE forge_connection_setup_checks SET result_code = 'unavailable', visible_repository_count = NULL, visible_private_repository_count = NULL`)
		}},
		{name: "identities", mutate: func(f *accessShadowFixture) {
			_, _ = f.database.Exec(`DELETE FROM forgejo_identities`)
		}},
		{name: "bindings", mutate: func(f *accessShadowFixture) {
			_, _ = f.database.Exec(`DELETE FROM forge_repository_bindings`)
		}},
		{name: "scope limit", mutate: func(f *accessShadowFixture) {
			addAccessShadowScopeBeyondLimit(t, f)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAccessShadowFixture(t)
			tc.mutate(fixture)
			_, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, fixture.validPeriodicEnableInput())
			if tc.name == "encryption" {
				if !errors.Is(err, ErrConfiguration) {
					t.Fatalf("enable error = %v", err)
				}
			} else if !IsValidationError(err) {
				t.Fatalf("enable error = %v", err)
			}
			var configs int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_periodic_config`).Scan(&configs); err != nil {
				t.Fatal(err)
			}
			if configs != 0 {
				t.Fatalf("rejected enable wrote %d configs", configs)
			}
		})
	}

	t.Run("reports every simultaneous blocker", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.service.secrets = nil
		if _, err := fixture.database.Exec(`
UPDATE forge_connection_setup_checks
SET result_code = 'unavailable', visible_repository_count = NULL, visible_private_repository_count = NULL;
DELETE FROM forgejo_identities;
DELETE FROM forge_repository_bindings`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.service.EnablePeriodic(
			fixture.ctx,
			fixture.adminID,
			fixture.validPeriodicEnableInput(),
		)
		if !errors.Is(err, ErrConfiguration) {
			t.Fatalf("combined blocker error = %v", err)
		}
		for _, reason := range []string{
			"service PAT encryption is unavailable",
			"setup evidence is not current",
			"no Forgejo identities are linked",
			"no repositories are bound",
		} {
			if !strings.Contains(err.Error(), reason) {
				t.Fatalf("combined blocker error %q is missing %q", err, reason)
			}
		}
	})
}

func TestAccessShadowPeriodicDisableSurvivesBrokenPrerequisites(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.service.secrets = nil
	if _, err := fixture.database.Exec(`
UPDATE forge_connection_setup_checks
SET result_code = 'unavailable', visible_repository_count = NULL, visible_private_repository_count = NULL;
DELETE FROM forgejo_identities;
DELETE FROM forge_repository_bindings`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, DisableAccessShadowPeriodicInput{
		ExpectedConnectionID:     1,
		ExpectedPeriodicRevision: 1,
		ConfirmPeriodicDisable:   true,
	}); err != nil {
		t.Fatal(err)
	}
	_, due := fixture.periodicConfig(t)
	if due.Valid {
		t.Fatalf("broken-prerequisite disable left due time %q", due.String)
	}
}

func TestAccessShadowPeriodicConfigurationAuditAndCommitFailuresRollBack(t *testing.T) {
	t.Run("enable audit", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		if _, err := fixture.database.Exec(`
CREATE TRIGGER fail_access_periodic_enabled
BEFORE INSERT ON audit_events
WHEN NEW.action = 'forge.access_periodic_enabled'
BEGIN
  SELECT RAISE(ABORT, 'forced periodic enable audit failure');
END`); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, fixture.validPeriodicEnableInput()); err == nil {
			t.Fatal("enable succeeded despite audit failure")
		}
		var configs int
		if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_periodic_config`).Scan(&configs); err != nil {
			t.Fatal(err)
		}
		if configs != 0 {
			t.Fatalf("enable audit rollback left %d configurations", configs)
		}
	})

	t.Run("disable audit", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		if _, err := fixture.database.Exec(`
CREATE TRIGGER fail_access_periodic_disabled
BEFORE INSERT ON audit_events
WHEN NEW.action = 'forge.access_periodic_disabled'
BEGIN
  SELECT RAISE(ABORT, 'forced periodic disable audit failure');
END`); err != nil {
			t.Fatal(err)
		}
		err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, DisableAccessShadowPeriodicInput{
			ExpectedConnectionID:     1,
			ExpectedPeriodicRevision: 1,
			ConfirmPeriodicDisable:   true,
		})
		if err == nil {
			t.Fatal("disable succeeded despite audit failure")
		}
		revision, due := fixture.periodicConfig(t)
		if revision != 1 || !due.Valid {
			t.Fatalf("disable audit rollback config = revision %d due %+v", revision, due)
		}
	})

	t.Run("enable commit", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		injectAccessShadowCommitFailure(t, fixture.database, audit.ActionForgeAccessPeriodicEnabled)
		_, err := fixture.service.EnablePeriodic(fixture.ctx, fixture.adminID, fixture.validPeriodicEnableInput())
		if !errors.Is(err, ErrAccessPeriodicOutcomeUnknown) {
			t.Fatalf("enable commit failure = %v", err)
		}
		var configs int
		if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_periodic_config`).Scan(&configs); err != nil {
			t.Fatal(err)
		}
		if configs != 0 {
			t.Fatalf("ambiguous enable persisted %d configurations", configs)
		}
	})

	t.Run("disable commit", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		injectAccessShadowCommitFailure(t, fixture.database, audit.ActionForgeAccessPeriodicDisabled)
		err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, DisableAccessShadowPeriodicInput{
			ExpectedConnectionID:     1,
			ExpectedPeriodicRevision: 1,
			ConfirmPeriodicDisable:   true,
		})
		if !errors.Is(err, ErrAccessPeriodicOutcomeUnknown) {
			t.Fatalf("disable commit failure = %v", err)
		}
		revision, due := fixture.periodicConfig(t)
		if revision != 1 || !due.Valid {
			t.Fatalf("ambiguous disable config = revision %d due %+v", revision, due)
		}
	})
}

func TestAccessShadowManualCompletionPostponesPeriodicWithoutRevisionChange(t *testing.T) {
	t.Run("complete postpones and never shortens", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		fixture.clock.Advance(2 * time.Minute)
		fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
		if result, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); err != nil || result != AccessSyncComplete {
			t.Fatalf("manual completion: result=%v err=%v", result, err)
		}
		revision, due := fixture.periodicConfig(t)
		want := fixture.clock.Now().Add(accessShadowPeriodicCadence)
		if revision != 1 || !due.Valid || due.String != formatForgeConnectionTime(want) {
			t.Fatalf("postponed config = revision %d due %q want %q", revision, due.String, formatForgeConnectionTime(want))
		}

		farDue := fixture.clock.Now().Add(20 * time.Minute)
		fixture.setPeriodicDue(t, farDue)
		fixture.clock.Advance(time.Minute)
		fixture.observer.observations = append(fixture.observer.observations, completeObservation(30, nil))
		input := fixture.validRunInput()
		input.ExpectedNewestRunID = fixture.newestRunID(t)
		if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); err != nil {
			t.Fatal(err)
		}
		_, due = fixture.periodicConfig(t)
		if !due.Valid || due.String != formatForgeConnectionTime(farDue) {
			t.Fatalf("manual completion shortened due time to %q", due.String)
		}
	})

	t.Run("failure and scope change do not move cadence", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		_, originalDue := fixture.periodicConfig(t)
		fixture.observer.observations = []AccessObservation{
			{ResultCode: AccessSyncUnavailable, RequestCount: 1},
			completeObservation(30, nil),
		}
		if result, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); err != nil || result != AccessSyncUnavailable {
			t.Fatalf("manual failure: result=%v err=%v", result, err)
		}
		_, due := fixture.periodicConfig(t)
		if due.String != originalDue.String {
			t.Fatalf("failure moved due from %q to %q", originalDue.String, due.String)
		}

		fixture.clock.Advance(time.Minute)
		input := fixture.validRunInput()
		input.ExpectedNewestRunID = fixture.newestRunID(t)
		fixture.observer.onObserve = func(int) {
			_, _ = fixture.database.Exec(`UPDATE forge_connections SET binding_revision = 3 WHERE id = 1`)
		}
		if result, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); err != nil || result != AccessSyncScopeChanged {
			t.Fatalf("manual scope change: result=%v err=%v", result, err)
		}
		_, due = fixture.periodicConfig(t)
		if due.String != originalDue.String {
			t.Fatalf("scope change moved due from %q to %q", originalDue.String, due.String)
		}
	})

	t.Run("finalization commit ambiguity moves neither completion nor cadence", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		_, originalDue := fixture.periodicConfig(t)
		fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
		injectAccessShadowCommitFailure(t, fixture.database, audit.ActionForgeAccessSyncFinished)
		if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput()); !errors.Is(err, ErrAccessSyncOutcomeUnknown) {
			t.Fatalf("manual finalization commit failure = %v", err)
		}
		_, due := fixture.periodicConfig(t)
		if !due.Valid || due.String != originalDue.String {
			t.Fatalf("ambiguous manual completion moved due from %q to %q", originalDue.String, due.String)
		}
		var running int
		if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs WHERE result_code IS NULL`).Scan(&running); err != nil {
			t.Fatal(err)
		}
		if running != 1 {
			t.Fatalf("ambiguous manual completion left %d running rows", running)
		}
	})
}

func TestAccessShadowRunPeriodicDueNoWorkAndBlockedScans(t *testing.T) {
	t.Run("disabled and not due", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		fixture.enablePeriodic(t)
		if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		if len(fixture.observer.inputs) != 0 {
			t.Fatalf("not-due scan called provider %d times", len(fixture.observer.inputs))
		}
		var runs int
		if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
			t.Fatal(err)
		}
		if runs != 0 {
			t.Fatalf("no-work scans reserved %d runs", runs)
		}
	})

	for _, tc := range []struct {
		name    string
		disable bool
	}{
		{name: "future due"},
		{name: "disabled row", disable: true},
	} {
		t.Run(tc.name+" acquires writer ownership without rewriting config", func(t *testing.T) {
			fixture := newAccessShadowFixture(t)
			fixture.enablePeriodic(t)
			if tc.disable {
				if err := fixture.service.DisablePeriodic(
					fixture.ctx,
					fixture.adminID,
					DisableAccessShadowPeriodicInput{
						ExpectedConnectionID:     1,
						ExpectedPeriodicRevision: 1,
						ConfirmPeriodicDisable:   true,
					},
				); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fixture.database.Exec(`
CREATE TRIGGER reject_periodic_config_rewrite
BEFORE UPDATE ON forge_access_shadow_periodic_config
BEGIN
  SELECT RAISE(ABORT, 'unexpected no-work periodic config rewrite');
END`); err != nil {
				t.Fatal(err)
			}
			if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
				t.Fatalf("no-work scan rewrote periodic config: %v", err)
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*accessShadowFixture)
	}{
		{name: "encryption unavailable", mutate: func(f *accessShadowFixture) { f.service.secrets = nil }},
		{name: "setup evidence stale", mutate: func(f *accessShadowFixture) {
			_, _ = f.database.Exec(`UPDATE forge_connections SET check_generation = 6 WHERE id = 1`)
		}},
		{name: "no identities", mutate: func(f *accessShadowFixture) {
			_, _ = f.database.Exec(`DELETE FROM forgejo_identities`)
		}},
		{name: "no bindings", mutate: func(f *accessShadowFixture) {
			_, _ = f.database.Exec(`DELETE FROM forge_repository_bindings`)
		}},
		{name: "scope exceeds limits", mutate: func(f *accessShadowFixture) {
			addAccessShadowScopeBeyondLimit(t, f)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAccessShadowFixture(t)
			fixture.enablePeriodic(t)
			fixture.clock.Advance(accessShadowPeriodicCadence)
			tc.mutate(fixture)
			if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
				t.Fatal(err)
			}
			if len(fixture.observer.inputs) != 0 {
				t.Fatalf("blocked scan called provider %d times", len(fixture.observer.inputs))
			}
			var runs, activity int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
				t.Fatal(err)
			}
			if err := fixture.database.QueryRow(`
SELECT count(*) FROM audit_events
WHERE action IN ('forge.access_sync_started', 'forge.access_sync_finished')`).Scan(&activity); err != nil {
				t.Fatal(err)
			}
			if runs != 0 || activity != 0 {
				t.Fatalf("blocked scan wrote runs/activity = %d/%d", runs, activity)
			}
			_, due := fixture.periodicConfig(t)
			want := fixture.clock.Now().Add(accessShadowPeriodicCadence)
			if !due.Valid || due.String != formatForgeConnectionTime(want) {
				t.Fatalf("blocked due = %q want %q", due.String, formatForgeConnectionTime(want))
			}
		})
	}
}

func TestAccessShadowRunPeriodicDueReservesExecutesAndAttributesSystem(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	fixture.observer.observations = []AccessObservation{completeObservation(40, nil)}

	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if len(fixture.observer.inputs) != 1 {
		t.Fatalf("provider calls = %d", len(fixture.observer.inputs))
	}
	var requester sql.NullInt64
	var trigger, result string
	if err := fixture.database.QueryRow(`
SELECT requested_by_user_id, run_trigger, result_code
FROM forge_access_shadow_runs`).Scan(&requester, &trigger, &result); err != nil {
		t.Fatal(err)
	}
	if requester.Valid || trigger != "periodic" || result != "complete" {
		t.Fatalf("periodic run requester/trigger/result = %+v/%q/%q", requester, trigger, result)
	}
	_, due := fixture.periodicConfig(t)
	wantDue := fixture.clock.Now().Add(accessShadowPeriodicCadence)
	if !due.Valid || due.String != formatForgeConnectionTime(wantDue) {
		t.Fatalf("next due = %q want %q", due.String, formatForgeConnectionTime(wantDue))
	}
	for _, action := range []string{audit.ActionForgeAccessSyncStarted, audit.ActionForgeAccessSyncFinished} {
		details := fixture.auditDetails(t, action)
		actors := fixture.auditActors(t, action)
		if len(details) != 1 || details[0]["run_trigger"] != "periodic" ||
			details[0]["actor_kind"] != "system" || details[0]["actor_role"] != "shadow_refresh_runner" ||
			len(actors) != 1 || actors[0].Valid {
			t.Fatalf("periodic %s details=%v actors=%v", action, details, actors)
		}
		for key := range details[0] {
			switch key {
			case "run_id", "identity_count", "repository_count", "run_trigger", "result_code",
				"present_count", "unknown_count", "request_count", "actor_kind", "actor_role":
			default:
				t.Fatalf("unexpected periodic audit key %q", key)
			}
		}
	}
	// The persisted future due time prevents an immediate retry/catch-up pass.
	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if len(fixture.observer.inputs) != 1 {
		t.Fatalf("immediate second scan called provider %d times", len(fixture.observer.inputs))
	}
}

func TestAccessShadowRunPeriodicDueSamplesStartedAtAfterReadinessWork(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	scanAt := fixture.clock.Now()
	startedAt := scanAt.Add(7 * time.Second)
	clockCalls := 0
	fixture.service.now = func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return scanAt
		}
		return startedAt
	}
	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}

	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	var persistedStartedAt string
	if err := fixture.database.QueryRow(`
SELECT started_at
FROM forge_access_shadow_runs
ORDER BY id DESC
LIMIT 1`).Scan(&persistedStartedAt); err != nil {
		t.Fatal(err)
	}
	if persistedStartedAt != formatForgeConnectionTime(startedAt) {
		t.Fatalf("periodic started_at = %q, want %q", persistedStartedAt, formatForgeConnectionTime(startedAt))
	}
	_, due := fixture.periodicConfig(t)
	wantDue := formatForgeConnectionTime(startedAt.Add(accessShadowPeriodicCadence))
	if !due.Valid || due.String != wantDue {
		t.Fatalf("periodic next due = %q, want %q", due.String, wantDue)
	}
}

func TestAccessShadowRunPeriodicDueFailureStaysEnabledAndUsesOrdinaryCadence(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	fixture.observer.observations = []AccessObservation{{ResultCode: AccessSyncUnavailable, RequestCount: 1}}

	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	view, err := fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.PeriodicNextDueAt == nil || view.LatestAttempt == nil ||
		view.LatestAttempt.Trigger != AccessShadowRunPeriodic ||
		view.LatestAttempt.ResultCode != AccessSyncUnavailable {
		t.Fatalf("failure view = %+v", view)
	}
	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if len(fixture.observer.inputs) != 1 {
		t.Fatalf("failure retried immediately, calls=%d", len(fixture.observer.inputs))
	}
}

func TestAccessShadowRunPeriodicDueReservationErrorsAdvanceOrdinaryCadence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*accessShadowFixture)
	}{
		{
			name: "runtime configuration",
			mutate: func(f *accessShadowFixture) {
				f.service.observer = nil
			},
		},
		{
			name: "start Activity persistence",
			mutate: func(f *accessShadowFixture) {
				if _, err := f.database.Exec(`
CREATE TRIGGER fail_periodic_access_sync_started
BEFORE INSERT ON audit_events
WHEN NEW.action = 'forge.access_sync_started'
BEGIN
  SELECT RAISE(ABORT, 'forced periodic start Activity failure');
END`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed newest reservation",
			mutate: func(f *accessShadowFixture) {
				connection, err := f.database.Conn(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				if _, err := connection.ExecContext(f.ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
					t.Fatal(err)
				}
				if _, err := connection.ExecContext(f.ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, result_code, finished_at, started_at
)
VALUES (1, NULL, 3, 5, 2, 2, 2, 2, 'scheduled', 'interrupted', ?, ?)`,
					formatForgeConnectionTime(f.clock.Now()),
					formatForgeConnectionTime(f.clock.Now()),
				); err != nil {
					t.Fatal(err)
				}
				if _, err := connection.ExecContext(f.ctx, `PRAGMA ignore_check_constraints = OFF`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed enabled due time",
			mutate: func(f *accessShadowFixture) {
				connection, err := f.database.Conn(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer connection.Close()
				if _, err := connection.ExecContext(f.ctx, `PRAGMA ignore_check_constraints = ON`); err != nil {
					t.Fatal(err)
				}
				if _, err := connection.ExecContext(f.ctx, `
UPDATE forge_access_shadow_periodic_config SET next_due_at = 'malformed' WHERE connection_id = 1`); err != nil {
					t.Fatal(err)
				}
				if _, err := connection.ExecContext(f.ctx, `PRAGMA ignore_check_constraints = OFF`); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newAccessShadowFixture(t)
			fixture.enablePeriodic(t)
			fixture.clock.Advance(accessShadowPeriodicCadence)
			tc.mutate(fixture)
			var runsBefore, activityBefore int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runsBefore); err != nil {
				t.Fatal(err)
			}
			if err := fixture.database.QueryRow(`
SELECT count(*) FROM audit_events WHERE action = 'forge.access_sync_started'`).Scan(&activityBefore); err != nil {
				t.Fatal(err)
			}

			if err := fixture.service.RunPeriodicDue(fixture.ctx); err == nil {
				t.Fatal("reservation error was not returned to the runner boundary")
			}
			_, due := fixture.periodicConfig(t)
			wantDue := formatForgeConnectionTime(fixture.clock.Now().Add(accessShadowPeriodicCadence))
			if !due.Valid || due.String != wantDue {
				t.Fatalf("reservation error due = %q, want %q", due.String, wantDue)
			}
			var runs, activity int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
				t.Fatal(err)
			}
			if err := fixture.database.QueryRow(`
SELECT count(*) FROM audit_events WHERE action = 'forge.access_sync_started'`).Scan(&activity); err != nil {
				t.Fatal(err)
			}
			if runs != runsBefore || activity != activityBefore {
				t.Fatalf(
					"reservation error changed run/Activity counts from %d/%d to %d/%d",
					runsBefore,
					activityBefore,
					runs,
					activity,
				)
			}
			if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
				t.Fatalf("reservation error retried before ordinary due time: %v", err)
			}
		})
	}
}

func TestAccessShadowRunPeriodicDueCancellationStillFinalizesReservation(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	gate := make(chan struct{})
	fixture.observer.gates = []chan struct{}{gate}
	fixture.observer.started = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- fixture.service.RunPeriodicDue(ctx)
	}()
	<-fixture.observer.started
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	var result string
	var running int
	if err := fixture.database.QueryRow(`
SELECT result_code FROM forge_access_shadow_runs ORDER BY id DESC LIMIT 1`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.QueryRow(`
SELECT count(*) FROM forge_access_shadow_runs WHERE result_code IS NULL`).Scan(&running); err != nil {
		t.Fatal(err)
	}
	if result != string(AccessSyncInterrupted) || running != 0 {
		t.Fatalf("cancelled reservation result/running = %q/%d", result, running)
	}
	finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
	if len(finished) != 1 || finished[0]["run_trigger"] != string(AccessShadowRunPeriodic) ||
		finished[0]["result_code"] != string(AccessSyncInterrupted) {
		t.Fatalf("cancelled reservation finish Activity = %v", finished)
	}
	if _, present := finished[0]["request_count"]; present {
		t.Fatalf("cancelled reservation recorded an unknowable request count: %v", finished[0])
	}
}

func TestAccessShadowManualCancellationFinalizesInterruptedWithoutMovingCadence(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	_, originalDue := fixture.periodicConfig(t)
	gate := make(chan struct{})
	fixture.observer.gates = []chan struct{}{gate}
	fixture.observer.started = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	type runResult struct {
		code AccessSyncResultCode
		err  error
	}
	done := make(chan runResult, 1)
	go func() {
		code, err := fixture.service.Run(ctx, fixture.adminID, fixture.validRunInput())
		done <- runResult{code: code, err: err}
	}()
	<-fixture.observer.started
	cancel()
	result := <-done
	if result.err != nil || result.code != AccessSyncInterrupted {
		t.Fatalf("cancelled manual run = %q, %v", result.code, result.err)
	}

	var runCode, runTrigger string
	if err := fixture.database.QueryRow(`
SELECT result_code, run_trigger
FROM forge_access_shadow_runs
ORDER BY id DESC
LIMIT 1`).Scan(&runCode, &runTrigger); err != nil {
		t.Fatal(err)
	}
	if runCode != string(AccessSyncInterrupted) || runTrigger != string(AccessShadowRunManual) {
		t.Fatalf("cancelled manual reservation = %q/%q", runCode, runTrigger)
	}
	_, due := fixture.periodicConfig(t)
	if !due.Valid || due.String != originalDue.String {
		t.Fatalf("cancelled manual run moved due from %q to %q", originalDue.String, due.String)
	}
	finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
	if len(finished) != 1 || finished[0]["run_trigger"] != string(AccessShadowRunManual) ||
		finished[0]["result_code"] != string(AccessSyncInterrupted) {
		t.Fatalf("cancelled manual finish Activity = %v", finished)
	}
	if _, present := finished[0]["request_count"]; present {
		t.Fatalf("cancelled manual run recorded an unknowable request count: %v", finished[0])
	}
}

func TestAccessShadowRunPeriodicDueReservationCommitAmbiguityRollsBackCadence(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	_, originalDue := fixture.periodicConfig(t)
	injectAccessShadowCommitFailure(t, fixture.database, audit.ActionForgeAccessSyncStarted)

	err := fixture.service.RunPeriodicDue(fixture.ctx)
	if !errors.Is(err, ErrAccessPeriodicOutcomeUnknown) {
		t.Fatalf("periodic reservation commit failure = %v", err)
	}
	if len(fixture.observer.inputs) != 0 {
		t.Fatalf("ambiguous reservation called provider %d times", len(fixture.observer.inputs))
	}
	_, due := fixture.periodicConfig(t)
	if !due.Valid || due.String != originalDue.String {
		t.Fatalf("ambiguous reservation moved due from %q to %q", originalDue.String, due.String)
	}
	var runs int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("ambiguous reservation persisted %d runs", runs)
	}
}

func TestAccessShadowRunPeriodicDueScopeChurnPublishesNothingAndKeepsCadence(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
	fixture.observer.onObserve = func(int) {
		if _, err := fixture.database.ExecContext(fixture.ctx, `
UPDATE forge_connections SET config_revision = config_revision + 1 WHERE id = 1`); err != nil {
			t.Error(err)
		}
	}

	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	var result string
	var observations int
	if err := fixture.database.QueryRow(`SELECT result_code FROM forge_access_shadow_runs`).Scan(&result); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_observations`).Scan(&observations); err != nil {
		t.Fatal(err)
	}
	if result != string(AccessSyncScopeChanged) || observations != 0 {
		t.Fatalf("scope churn result/observations = %q/%d", result, observations)
	}
	_, due := fixture.periodicConfig(t)
	if !due.Valid || due.String != formatForgeConnectionTime(fixture.clock.Now().Add(accessShadowPeriodicCadence)) {
		t.Fatalf("scope churn cadence = %q", due.String)
	}
	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if len(fixture.observer.inputs) != 1 {
		t.Fatalf("scope churn retried immediately, calls=%d", len(fixture.observer.inputs))
	}
}

func TestAccessShadowRunPeriodicDueConcurrentScansReserveAtMostOneOperation(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	fixture.enablePeriodic(t)
	fixture.clock.Advance(accessShadowPeriodicCadence)
	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
	gate := make(chan struct{})
	fixture.observer.gates = []chan struct{}{gate}
	fixture.observer.started = make(chan struct{}, 1)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var scans sync.WaitGroup
	for range 2 {
		scans.Go(func() {
			<-start
			errs <- fixture.service.RunPeriodicDue(context.Background())
		})
	}
	close(start)
	<-fixture.observer.started
	close(gate)
	scans.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent scan error = %v", err)
		}
	}
	if len(fixture.observer.inputs) != 1 {
		t.Fatalf("concurrent scans started %d provider operations", len(fixture.observer.inputs))
	}
	var runs int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM forge_access_shadow_runs`).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("concurrent scans reserved %d runs", runs)
	}
}

func TestAccessShadowRunPeriodicDueBusyOrphanAndDisableDuringRun(t *testing.T) {
	t.Run("busy advances normally", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		fixture.clock.Advance(accessShadowPeriodicCadence)
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, started_at
)
VALUES (1, 1, 3, 5, 2, 2, 2, 2, 'manual', ?)`, formatForgeConnectionTime(fixture.clock.Now())); err != nil {
			t.Fatal(err)
		}
		if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		if len(fixture.observer.inputs) != 0 {
			t.Fatal("busy scan called provider")
		}
		_, due := fixture.periodicConfig(t)
		if due.String != formatForgeConnectionTime(fixture.clock.Now().Add(accessShadowPeriodicCadence)) {
			t.Fatalf("busy next due = %q", due.String)
		}
	})

	t.Run("periodic orphan keeps system attribution", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		fixture.clock.Advance(accessShadowPeriodicCadence)
		orphanStart := fixture.clock.Now().Add(-2 * time.Minute)
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forge_access_shadow_runs(
  connection_id, requested_by_user_id, config_revision, check_generation,
  binding_revision, access_identity_revision, identity_count, repository_count,
  run_trigger, started_at
)
VALUES (1, NULL, 3, 5, 2, 2, 2, 2, 'periodic', ?)`, formatForgeConnectionTime(orphanStart)); err != nil {
			t.Fatal(err)
		}
		fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
		if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		finished := fixture.auditDetails(t, audit.ActionForgeAccessSyncFinished)
		actors := fixture.auditActors(t, audit.ActionForgeAccessSyncFinished)
		if len(finished) != 2 || finished[0]["result_code"] != "interrupted" ||
			finished[0]["run_trigger"] != "periodic" || finished[0]["actor_role"] != "shadow_refresh_runner" ||
			len(actors) != 2 || actors[0].Valid || actors[1].Valid {
			t.Fatalf("orphan finished details=%v actors=%v", finished, actors)
		}
	})

	t.Run("disable does not cancel in flight", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		fixture.clock.Advance(accessShadowPeriodicCadence)
		gate := make(chan struct{})
		fixture.observer.gates = []chan struct{}{gate}
		fixture.observer.started = make(chan struct{}, 1)
		fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
		done := make(chan error, 1)
		go func() { done <- fixture.service.RunPeriodicDue(fixture.ctx) }()
		<-fixture.observer.started
		if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, DisableAccessShadowPeriodicInput{
			ExpectedConnectionID:     1,
			ExpectedPeriodicRevision: 1,
			ConfirmPeriodicDisable:   true,
		}); err != nil {
			t.Fatal(err)
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		var result string
		if err := fixture.database.QueryRow(`
SELECT result_code FROM forge_access_shadow_runs ORDER BY id DESC LIMIT 1`).Scan(&result); err != nil {
			t.Fatal(err)
		}
		_, due := fixture.periodicConfig(t)
		if result != "complete" || due.Valid {
			t.Fatalf("disabled in-flight result/due = %q/%+v", result, due)
		}
	})
}

func TestAccessShadowManualAndPeriodicReservationsElectOneFirstWriter(t *testing.T) {
	t.Run("periodic first", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		fixture.clock.Advance(accessShadowPeriodicCadence)
		gate := make(chan struct{})
		fixture.observer.gates = []chan struct{}{gate}
		fixture.observer.started = make(chan struct{}, 1)
		fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
		done := make(chan error, 1)
		go func() { done <- fixture.service.RunPeriodicDue(fixture.ctx) }()
		<-fixture.observer.started
		input := fixture.validRunInput()
		input.ExpectedNewestRunID = fixture.newestRunID(t)
		if _, err := fixture.service.Run(fixture.ctx, fixture.adminID, input); !errors.Is(err, ErrAccessSyncRunning) {
			t.Fatalf("manual after periodic = %v", err)
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("manual first", func(t *testing.T) {
		fixture := newAccessShadowFixture(t)
		fixture.enablePeriodic(t)
		fixture.clock.Advance(accessShadowPeriodicCadence)
		gate := make(chan struct{})
		fixture.observer.gates = []chan struct{}{gate}
		fixture.observer.started = make(chan struct{}, 1)
		fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
		done := make(chan error, 1)
		go func() {
			_, err := fixture.service.Run(fixture.ctx, fixture.adminID, fixture.validRunInput())
			done <- err
		}()
		<-fixture.observer.started
		if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
			t.Fatal(err)
		}
		if len(fixture.observer.inputs) != 1 {
			t.Fatalf("periodic scan started a second provider call: %d", len(fixture.observer.inputs))
		}
		close(gate)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestAccessShadowViewPeriodicAndFreshnessAxes(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	view, err := fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.PeriodicNextDueAt != nil || view.PeriodicRevision != 0 ||
		view.PeriodicDueStatus != AccessPeriodicNotScheduled || len(view.PeriodicBlockers) != 0 {
		t.Fatalf("initial periodic view = %+v", view)
	}
	fixture.enablePeriodic(t)
	view, err = fixture.service.View(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if view.PeriodicNextDueAt == nil || view.PeriodicRevision != 1 ||
		view.PeriodicDueStatus != AccessPeriodicScheduled {
		t.Fatalf("scheduled periodic view = %+v", view)
	}

	fixture.clock.Advance(accessShadowPeriodicCadence)
	view, err = fixture.service.View(fixture.ctx)
	if err != nil || view.PeriodicDueStatus != AccessPeriodicDue {
		t.Fatalf("due view = %+v err=%v", view, err)
	}
	fixture.clock.Advance(30 * time.Second)
	view, err = fixture.service.View(fixture.ctx)
	if err != nil || view.PeriodicDueStatus != AccessPeriodicDue {
		t.Fatalf("exact overdue boundary view = %+v err=%v", view, err)
	}
	fixture.clock.Advance(time.Nanosecond)
	view, err = fixture.service.View(fixture.ctx)
	if err != nil || view.PeriodicDueStatus != AccessPeriodicOverdue {
		t.Fatalf("overdue view = %+v err=%v", view, err)
	}

	fixture.observer.observations = []AccessObservation{completeObservation(30, nil)}
	if err := fixture.service.RunPeriodicDue(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	view, err = fixture.service.View(fixture.ctx)
	if err != nil || view.LatestSnapshot == nil || !view.LatestSnapshot.Fresh {
		t.Fatalf("fresh snapshot view = %+v err=%v", view.LatestSnapshot, err)
	}
	if err := fixture.service.DisablePeriodic(fixture.ctx, fixture.adminID, DisableAccessShadowPeriodicInput{
		ExpectedConnectionID:     1,
		ExpectedPeriodicRevision: 1,
		ConfirmPeriodicDisable:   true,
	}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(accessShadowEvidenceFreshness)
	view, err = fixture.service.View(fixture.ctx)
	if err != nil || view.PeriodicNextDueAt != nil || view.LatestSnapshot == nil || view.LatestSnapshot.Fresh {
		t.Fatalf("exact stale boundary view = %+v err=%v", view.LatestSnapshot, err)
	}
}

func TestAccessShadowViewSamplesClockOnceAndKeepsDueAxisTriggerSpecific(t *testing.T) {
	fixture := newAccessShadowFixture(t)
	calls := 0
	now := fixture.clock.Now()
	fixture.service.now = func() time.Time {
		calls++
		return now
	}
	if _, err := fixture.service.View(fixture.ctx); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("View clock samples = %d, want 1", calls)
	}

	overdue := now.Add(-accessShadowPeriodicOverdueAge - time.Nanosecond)
	manual := &AccessShadowAttempt{
		Status:  AccessAttemptRunning,
		Trigger: AccessShadowRunManual,
	}
	if got := deriveAccessShadowPeriodicDueStatus(now, &overdue, manual); got != AccessPeriodicOverdue {
		t.Fatalf("manual run due status = %q, want overdue", got)
	}
	periodic := &AccessShadowAttempt{
		Status:  AccessAttemptRunning,
		Trigger: AccessShadowRunPeriodic,
	}
	if got := deriveAccessShadowPeriodicDueStatus(now, nil, periodic); got != AccessPeriodicRunning {
		t.Fatalf("disabled in-flight periodic due status = %q, want running", got)
	}
	interruptedPeriodic := &AccessShadowAttempt{
		Status:  AccessAttemptInterrupted,
		Trigger: AccessShadowRunPeriodic,
	}
	if got := deriveAccessShadowPeriodicDueStatus(now, &overdue, interruptedPeriodic); got != AccessPeriodicOverdue {
		t.Fatalf("orphan-aged periodic due status = %q, want overdue", got)
	}
}

func TestAccessShadowViewReadinessRequiresExplicitEncryptionFact(t *testing.T) {
	view := AccessShadowView{
		HasConnection:        true,
		SetupEvidenceCurrent: true,
		IdentityCount:        1,
		BindingCount:         1,
		WithinLimits:         true,
	}
	if view.Ready() {
		t.Fatal("zero-value encryption state reported a manual snapshot ready")
	}
	view.EncryptionAvailable = true
	if !view.Ready() {
		t.Fatal("explicit encryption readiness did not make the otherwise-ready view runnable")
	}
}

func addAccessShadowScopeBeyondLimit(t *testing.T, fixture *accessShadowFixture) {
	t.Helper()
	for i := int64(3); i <= 6; i++ {
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (?, ?, 'Extra', ?, ?)`,
			100+i,
			"extra"+string(rune('a'+i))+"@example.test",
			accessShadowFixtureTime,
			accessShadowFixtureTime,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (1, ?, ?, 'extra-user', ?)`,
			100+i,
			"9"+string(rune('0'+i)),
			accessShadowFixtureTime,
		); err != nil {
			t.Fatal(err)
		}
	}
	for i := int64(0); i < 3; i++ {
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO repositories(id, forge, base_url, owner, name, default_branch, active, created_at, updated_at)
VALUES (?, 'forgejo', 'https://forge.example.test', 'fixture-org', ?, 'main', 1, ?, ?)`,
			20+i,
			"extra-repo-"+string(rune('a'+i)),
			accessShadowFixtureTime,
			accessShadowFixtureTime,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO forge_repository_bindings(repository_id, connection_id, organization_id, remote_repository_id)
VALUES (?, 1, 10, ?)`,
			20+i,
			"20"+string(rune('0'+i)),
		); err != nil {
			t.Fatal(err)
		}
	}
}
