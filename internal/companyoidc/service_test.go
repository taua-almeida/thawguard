package companyoidc

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

const testClientSecret = "  exact client secret\n"

func TestInputValidationAndNormalization(t *testing.T) {
	valid := validCreateInput(testClientSecret)
	valid.ProviderLabel = " \tExample identity provider\n"
	valid.Issuer = " \thttps://ID.Example.test:443/tenant/%7Eexact/\r\n"
	valid.ClientID = " \tclient id with interior spaces\r\n"
	valid.Domains = []string{" ZETA.EXAMPLE ", "xn--bcher-kva.example", "alpha.example", "zeta.example", ""}
	normalized, err := normalizeCreateInput(valid)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.ProviderLabel != "Example identity provider" {
		t.Fatalf("provider label was not trimmed once: %q", normalized.ProviderLabel)
	}
	if normalized.Issuer != "https://ID.Example.test:443/tenant/%7Eexact/" {
		t.Fatalf("issuer was canonicalized instead of preserved: %q", normalized.Issuer)
	}
	if normalized.ClientID != "client id with interior spaces" {
		t.Fatalf("Client ID normalization changed the interior: %q", normalized.ClientID)
	}
	wantDomains := []string{"alpha.example", "xn--bcher-kva.example", "zeta.example"}
	if !slices.Equal(normalized.Domains, wantDomains) {
		t.Fatalf("domains = %v, want %v", normalized.Domains, wantDomains)
	}
	if normalized.ClientSecret != testClientSecret {
		t.Fatal("client secret was trimmed or normalized")
	}

	providerCases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: " \t"},
		{name: "too many runes", value: strings.Repeat("é", 81)},
		{name: "invalid UTF-8", value: string([]byte{0xff})},
		{name: "control", value: "Example\nProvider"},
		{name: "line separator", value: "Example\u2028Provider"},
	}
	for _, tc := range providerCases {
		t.Run("provider "+tc.name, func(t *testing.T) {
			input := validCreateInput(testClientSecret)
			input.ProviderLabel = tc.value
			if _, err := normalizeCreateInput(input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
	providerMax := validCreateInput(testClientSecret)
	providerMax.ProviderLabel = strings.Repeat("é", 80)
	if _, err := normalizeCreateInput(providerMax); err != nil {
		t.Fatalf("expected 80-rune provider label to pass: %v", err)
	}

	issuerCases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "too long", value: "https://id.example/" + strings.Repeat("a", 2049)},
		{name: "non-ASCII", value: "https://idé.example"},
		{name: "HTTP", value: "http://id.example"},
		{name: "relative", value: "/tenant"},
		{name: "opaque", value: "https:tenant"},
		{name: "missing host", value: "https:///tenant"},
		{name: "userinfo", value: "https://user@id.example"},
		{name: "query", value: "https://id.example?tenant=1"},
		{name: "empty query", value: "https://id.example?"},
		{name: "fragment", value: "https://id.example#tenant"},
		{name: "empty fragment", value: "https://id.example#"},
		{name: "raw path space", value: "https://id.example/tenant name"},
		{name: "raw path quote", value: `https://id.example/tenant"name`},
		{name: "raw path bracket", value: "https://id.example/tenant[name"},
		{name: "control", value: "https://id.example/ten\nant"},
	}
	for _, tc := range issuerCases {
		t.Run("issuer "+tc.name, func(t *testing.T) {
			input := validCreateInput(testClientSecret)
			input.Issuer = tc.value
			if _, err := normalizeCreateInput(input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}

	clientIDCases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: "\t"},
		{name: "too long", value: strings.Repeat("a", 513)},
		{name: "invalid UTF-8", value: string([]byte{0xff})},
		{name: "control", value: "client\tid"},
		{name: "paragraph separator", value: "client\u2029id"},
	}
	for _, tc := range clientIDCases {
		t.Run("client ID "+tc.name, func(t *testing.T) {
			input := validCreateInput(testClientSecret)
			input.ClientID = tc.value
			if _, err := normalizeCreateInput(input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
	clientIDMax := validCreateInput(testClientSecret)
	clientIDMax.ClientID = strings.Repeat("é", 256)
	if _, err := normalizeCreateInput(clientIDMax); err != nil {
		t.Fatalf("expected 512-byte Client ID to pass: %v", err)
	}

	secretCases := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "too long", value: strings.Repeat("s", 4097)},
		{name: "invalid UTF-8", value: string([]byte{0xff})},
		{name: "NUL", value: "before\x00after"},
	}
	for _, tc := range secretCases {
		t.Run("secret "+tc.name, func(t *testing.T) {
			input := validCreateInput(tc.value)
			if _, err := normalizeCreateInput(input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
	secretMax := validCreateInput(strings.Repeat("s", 4096))
	if _, err := normalizeCreateInput(secretMax); err != nil {
		t.Fatalf("expected 4096-byte secret to pass: %v", err)
	}

	domainCases := []struct {
		name   string
		values []string
	}{
		{name: "none", values: nil},
		{name: "too many", values: numberedDomains(21)},
		{name: "Unicode", values: []string{"bücher.example"}},
		{name: "wildcard", values: []string{"*.example.test"}},
		{name: "scheme", values: []string{"https://example.test"}},
		{name: "port", values: []string{"example.test:443"}},
		{name: "userinfo", values: []string{"user@example.test"}},
		{name: "IPv4", values: []string{"192.0.2.1"}},
		{name: "IPv6", values: []string{"2001:db8::1"}},
		{name: "empty label", values: []string{"example..test"}},
		{name: "trailing dot", values: []string{"example.test."}},
		{name: "leading hyphen", values: []string{"-example.test"}},
		{name: "trailing hyphen", values: []string{"example-.test"}},
		{name: "long label", values: []string{strings.Repeat("a", 64) + ".test"}},
		{name: "long name", values: []string{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62) + ".x"}},
	}
	for _, tc := range domainCases {
		t.Run("domain "+tc.name, func(t *testing.T) {
			input := validCreateInput(testClientSecret)
			input.Domains = tc.values
			if _, err := normalizeCreateInput(input); !IsValidationError(err) {
				t.Fatalf("expected validation error, got %v", err)
			}
		})
	}
	for _, values := range [][]string{numberedDomains(20), {"xn--bcher-kva.example"}, {strings.Repeat("a", 63) + ".example"}} {
		input := validCreateInput(testClientSecret)
		input.Domains = values
		if _, err := normalizeCreateInput(input); err != nil {
			t.Fatalf("expected valid domains %v: %v", values, err)
		}
	}
}

func TestCreateEncryptsSecretAndExposesOnlyPublicData(t *testing.T) {
	fixture := newServiceFixture(t)
	createdAt := time.Date(2026, 7, 28, 10, 0, 0, 123, time.UTC)
	fixture.service.now = func() time.Time { return createdAt }
	input := validCreateInput(testClientSecret)
	input.Domains = []string{"Zeta.Example", "alpha.example", "zeta.example"}

	if err := fixture.service.Create(fixture.ctx, fixture.adminID, input); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.Revision != 1 {
		t.Fatalf("read created Draft: found=%v connection=%+v err=%v", found, connection, err)
	}
	createdAtText, updatedAtText := storedConnectionTimes(t, fixture.database)
	if want := "2026-07-28T10:00:00.000000123Z"; createdAtText != want || updatedAtText != want {
		t.Fatalf("stored timestamps = %q/%q, want %q", createdAtText, updatedAtText, want)
	}
	if !slices.Equal(connection.Domains, []string{"alpha.example", "zeta.example"}) {
		t.Fatalf("unexpected domains: %v", connection.Domains)
	}
	if strings.Contains(fmt.Sprintf("%+v", connection), testClientSecret) {
		t.Fatal("returned model contains the plaintext secret")
	}

	var ciphertext []byte
	if err := fixture.database.QueryRowContext(fixture.ctx, `SELECT client_secret_ciphertext FROM company_oidc_connections WHERE id = 1`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(testClientSecret)) {
		t.Fatal("database ciphertext contains the plaintext secret")
	}
	plaintext, err := fixture.secretStore.Decrypt(fixture.ctx, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != testClientSecret {
		t.Fatal("encrypted secret did not preserve the exact submitted bytes")
	}

	assertDraftSavedAudit(t, fixture.database, 1, false, 2)

	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput("losing secret")); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected stale create conflict, got %v", err)
	}
	assertAuditCount(t, fixture.database, 1)
	if bytes.Contains(ciphertext, []byte("losing secret")) {
		t.Fatal("stale create replaced the stored ciphertext")
	}
}

func TestEditPreservesBlankSecretSupportsNoOpAndFencesStaleRevision(t *testing.T) {
	fixture := newServiceFixture(t)
	createdAt := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	fixture.service.now = func() time.Time { return createdAt }
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	createdAtText, updatedAtText := storedConnectionTimes(t, fixture.database)
	if want := "2026-07-28T10:00:00.000000000Z"; createdAtText != want || updatedAtText != want {
		t.Fatalf("exact-second timestamps = %q/%q, want %q", createdAtText, updatedAtText, want)
	}
	originalCiphertext := storedCiphertext(t, fixture.database)

	fixture.service.now = func() time.Time { return createdAt.Add(time.Hour) }
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, EditInput{
		ProviderLabel:    " Example IdP ",
		Issuer:           " https://id.example.test/tenant ",
		ClientID:         " client-id ",
		Domains:          []string{"EXAMPLE.TEST", "example.test"},
		ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	connection, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.Revision != 1 {
		t.Fatalf("normalized no-op changed the Draft: found=%v connection=%+v err=%v", found, connection, err)
	}
	noOpCreatedAtText, noOpUpdatedAtText := storedConnectionTimes(t, fixture.database)
	if noOpCreatedAtText != createdAtText || noOpUpdatedAtText != updatedAtText {
		t.Fatalf("normalized no-op changed timestamps: before=%q/%q after=%q/%q", createdAtText, updatedAtText, noOpCreatedAtText, noOpUpdatedAtText)
	}
	if !bytes.Equal(storedCiphertext(t, fixture.database), originalCiphertext) {
		t.Fatal("blank no-op changed the stored ciphertext")
	}
	assertAuditCount(t, fixture.database, 1)

	updatedAt := createdAt.Add(2 * time.Hour)
	fixture.service.now = func() time.Time { return updatedAt }
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, EditInput{
		ProviderLabel:    "Renamed IdP",
		Issuer:           "https://id.example.test/tenant",
		ClientID:         "client-id",
		Domains:          []string{"example.test", "subsidiary.example"},
		ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	connection, found, err = fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.Revision != 2 {
		t.Fatalf("unexpected non-secret edit: found=%v connection=%+v err=%v", found, connection, err)
	}
	_, updatedAtText = storedConnectionTimes(t, fixture.database)
	if want := "2026-07-28T12:00:00.000000000Z"; updatedAtText != want {
		t.Fatalf("updated timestamp = %q, want %q", updatedAtText, want)
	}
	if !bytes.Equal(storedCiphertext(t, fixture.database), originalCiphertext) {
		t.Fatal("blank replacement changed the stored ciphertext")
	}
	assertDraftSavedAudit(t, fixture.database, 2, false, 2)

	replacement := "replacement secret\n"
	fixture.service.now = func() time.Time { return updatedAt.Add(time.Hour) }
	if err := fixture.service.Edit(fixture.ctx, fixture.adminID, EditInput{
		ProviderLabel:           "Renamed IdP",
		Issuer:                  "https://id.example.test/tenant",
		ClientID:                "client-id",
		ReplacementClientSecret: replacement,
		Domains:                 []string{"example.test", "subsidiary.example"},
		ExpectedRevision:        2,
	}); err != nil {
		t.Fatal(err)
	}
	connection, found, err = fixture.service.Current(fixture.ctx)
	if err != nil || !found || connection.Revision != 3 {
		t.Fatalf("replacement revision: found=%v connection=%+v err=%v", found, connection, err)
	}
	replacementCiphertext := storedCiphertext(t, fixture.database)
	if bytes.Equal(replacementCiphertext, originalCiphertext) || bytes.Contains(replacementCiphertext, []byte(replacement)) {
		t.Fatal("replacement did not produce fresh ciphertext")
	}
	plaintext, err := fixture.secretStore.Decrypt(fixture.ctx, replacementCiphertext)
	if err != nil || string(plaintext) != replacement {
		t.Fatalf("replacement secret was not stored exactly: plaintext=%q err=%v", plaintext, err)
	}
	assertDraftSavedAudit(t, fixture.database, 3, true, 2)

	err = fixture.service.Edit(fixture.ctx, fixture.adminID, EditInput{
		ProviderLabel:           "Stale overwrite",
		Issuer:                  "https://stale.example.test",
		ClientID:                "stale-client",
		ReplacementClientSecret: "stale secret",
		Domains:                 []string{"stale.example"},
		ExpectedRevision:        2,
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected stale edit conflict, got %v", err)
	}
	current, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || current.Revision != 3 || current.ProviderLabel != "Renamed IdP" {
		t.Fatalf("stale edit changed current Draft: found=%v connection=%+v err=%v", found, current, err)
	}
	if !bytes.Equal(storedCiphertext(t, fixture.database), replacementCiphertext) {
		t.Fatal("stale edit consumed its submitted secret")
	}
	assertAuditCount(t, fixture.database, 3)
}

func TestEncryptionUnavailableStillAllowsReadsAndRejectsMutations(t *testing.T) {
	fixture := newServiceFixture(t)
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	withoutEncryption := NewService(fixture.database, nil, nil)
	if connection, found, err := withoutEncryption.Current(fixture.ctx); err != nil || !found {
		t.Fatalf("read without encryption: found=%v connection=%+v err=%v", found, connection, err)
	}
	if err := withoutEncryption.Edit(fixture.ctx, fixture.adminID, validEditInput(1)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected edit configuration error, got %v", err)
	}

	emptyFixture := newServiceFixture(t)
	withoutEncryption = NewService(emptyFixture.database, nil, nil)
	if err := withoutEncryption.Create(emptyFixture.ctx, emptyFixture.adminID, validCreateInput(testClientSecret)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("expected create configuration error, got %v", err)
	}
	var rows int
	if err := emptyFixture.database.QueryRow(`SELECT count(*) FROM company_oidc_connections`).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("unconfigured create wrote %d rows: %v", rows, err)
	}
}

func TestEncryptionErrorsDoNotExposeSubmittedSecret(t *testing.T) {
	fixture := newServiceFixture(t)
	secret := "secret canary from encryption error"
	service := NewService(fixture.database, leakingErrorStore{secret: secret}, nil)
	err := service.Create(fixture.ctx, fixture.adminID, validCreateInput(secret))
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("encryption error leaked the secret: %v", err)
	}
}

func TestMutationsRequireCurrentEnabledAdministratorAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate string
	}{
		{name: "missing actor", mutate: "missing"},
		{name: "disabled actor", mutate: "disabled"},
		{name: "demoted actor", mutate: "demoted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			actorID := fixture.adminID
			switch tc.mutate {
			case "missing":
				actorID = 999
			case "disabled":
				if _, err := fixture.database.ExecContext(fixture.ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339Nano), actorID); err != nil {
					t.Fatal(err)
				}
			case "demoted":
				if _, err := fixture.database.ExecContext(fixture.ctx, `DELETE FROM user_roles WHERE user_id = ? AND role = 'admin'`, actorID); err != nil {
					t.Fatal(err)
				}
			}
			if err := fixture.service.Create(fixture.ctx, actorID, validCreateInput(testClientSecret)); !errors.Is(err, ErrAuthorization) {
				t.Fatalf("expected authorization error, got %v", err)
			}
			var rows int
			if err := fixture.database.QueryRow(`SELECT count(*) FROM company_oidc_connections`).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("rejected actor wrote %d rows: %v", rows, err)
			}
			assertAuditCount(t, fixture.database, 0)
		})
	}
}

func TestWriterFirstAuthorityCheckObservesConcurrentDemotion(t *testing.T) {
	fixture := newServiceFixture(t)
	blocker, err := fixture.database.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(fixture.ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, fixture.adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.ExecContext(fixture.ctx, `DELETE FROM user_roles WHERE user_id = ? AND role = 'admin'`, fixture.adminID); err != nil {
		t.Fatal(err)
	}

	result := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		result <- fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret))
	}()
	<-started
	time.Sleep(20 * time.Millisecond)
	if err := blocker.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrAuthorization) {
		t.Fatalf("expected post-lock demotion to reject save, got %v", err)
	}
	assertAuditCount(t, fixture.database, 0)
}

func TestDraftAndAuditRollBackTogether(t *testing.T) {
	fixture := newServiceFixture(t)
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TRIGGER reject_oidc_draft_audit
BEFORE INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.draft_saved'
BEGIN
  SELECT RAISE(ABORT, 'test audit rejection');
END;`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err == nil {
		t.Fatal("expected audit failure")
	}
	var connections, domains int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM company_oidc_connections`).Scan(&connections); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.QueryRow(`SELECT count(*) FROM company_oidc_allowed_domains`).Scan(&domains); err != nil {
		t.Fatal(err)
	}
	if connections != 0 || domains != 0 {
		t.Fatalf("audit failure left connection=%d domains=%d", connections, domains)
	}
	assertAuditCount(t, fixture.database, 0)
}

func TestCommitFailureIsReportedAsUnknownOutcome(t *testing.T) {
	fixture := newServiceFixture(t)
	if _, err := fixture.database.ExecContext(fixture.ctx, `
CREATE TABLE oidc_commit_parent (id INTEGER PRIMARY KEY);
CREATE TABLE oidc_commit_child (
  id INTEGER PRIMARY KEY,
  parent_id INTEGER NOT NULL REFERENCES oidc_commit_parent(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TRIGGER fail_oidc_commit
AFTER INSERT ON audit_events
WHEN NEW.action = 'oidc_connection.draft_saved'
BEGIN
  INSERT INTO oidc_commit_child(parent_id) VALUES (999);
END;`); err != nil {
		t.Fatal(err)
	}
	err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret))
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("expected unknown commit outcome, got %v", err)
	}
	if strings.Contains(err.Error(), testClientSecret) {
		t.Fatal("unknown-outcome error exposed the secret")
	}
}

func TestConcurrentCreatesEnforceExpectedAbsence(t *testing.T) {
	fixture := newServiceFixture(t)
	secondAdminID := fixture.insertAdmin(t, "second-admin@example.test")
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, actorID := range []int64{fixture.adminID, secondAdminID} {
		go func(i int, actorID int64) {
			<-start
			input := validCreateInput(fmt.Sprintf("concurrent secret %d", i))
			input.ProviderLabel = fmt.Sprintf("Concurrent IdP %d", i)
			results <- fixture.service.Create(fixture.ctx, actorID, input)
		}(i, actorID)
	}
	close(start)
	var succeeded, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent create error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent creates: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	assertAuditCount(t, fixture.database, 1)
}

func TestConcurrentEditorsFenceOneStaleRevision(t *testing.T) {
	fixture := newServiceFixture(t)
	secondAdminID := fixture.insertAdmin(t, "second-editor@example.test")
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, actorID := range []int64{fixture.adminID, secondAdminID} {
		go func(i int, actorID int64) {
			<-start
			input := validEditInput(1)
			input.ProviderLabel = fmt.Sprintf("Editor %d", i)
			input.ReplacementClientSecret = fmt.Sprintf("editor secret %d", i)
			results <- fixture.service.Edit(fixture.ctx, actorID, input)
		}(i, actorID)
	}
	close(start)
	var succeeded, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent edit error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent edits: succeeded=%d conflicted=%d", succeeded, conflicted)
	}
	current, found, err := fixture.service.Current(fixture.ctx)
	if err != nil || !found || current.Revision != 2 {
		t.Fatalf("current after concurrent edit: found=%v connection=%+v err=%v", found, current, err)
	}
	assertAuditCount(t, fixture.database, 2)
}

func TestCurrentReadsOneCompleteRevisionDuringConcurrentEdits(t *testing.T) {
	fixture := newServiceFixture(t)
	create := validCreateInput(testClientSecret)
	create.ProviderLabel = "Revision A"
	create.Issuer = "https://a.example.test"
	create.ClientID = "client-a"
	create.Domains = []string{"a.example"}
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, create); err != nil {
		t.Fatal(err)
	}

	const editCount = 80
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-start
		for expected := int64(1); expected <= editCount; expected++ {
			input := validEditInput(expected)
			if (expected+1)%2 == 0 {
				input.ProviderLabel = "Revision B"
				input.Issuer = "https://b.example.test"
				input.ClientID = "client-b"
				input.Domains = numberedDomains(20)
			} else {
				input.ProviderLabel = "Revision A"
				input.Issuer = "https://a.example.test"
				input.ClientID = "client-a"
				input.Domains = []string{"a.example"}
			}
			if err := fixture.service.Edit(fixture.ctx, fixture.adminID, input); err != nil {
				done <- err
				return
			}
			time.Sleep(time.Millisecond)
		}
		done <- nil
	}()
	close(start)

	reads := 0
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if reads == 0 {
				t.Fatal("expected at least one read during concurrent edits")
			}
			return
		default:
		}
		connection, found, err := fixture.service.Current(fixture.ctx)
		if err != nil || !found {
			t.Fatalf("concurrent Current: found=%v err=%v", found, err)
		}
		reads++
		if connection.Revision%2 == 1 {
			if connection.ProviderLabel != "Revision A" ||
				connection.Issuer != "https://a.example.test" ||
				connection.ClientID != "client-a" ||
				!slices.Equal(connection.Domains, []string{"a.example"}) {
				t.Fatalf("revision %d mixed configuration A: %+v", connection.Revision, connection)
			}
			continue
		}
		if connection.ProviderLabel != "Revision B" ||
			connection.Issuer != "https://b.example.test" ||
			connection.ClientID != "client-b" ||
			!slices.Equal(connection.Domains, numberedDomains(20)) {
			t.Fatalf("revision %d mixed configuration B: %+v", connection.Revision, connection)
		}
	}
}

type serviceFixture struct {
	ctx         context.Context
	database    *sql.DB
	service     *Service
	secretStore *secrets.AESGCMStore
	adminID     int64
	nextUserID  int64
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "company-oidc-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	migrations, err := db.LoadMigrations(companyOIDCTestMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	secretStore, err := secrets.NewAESGCMStore(bytes.Repeat([]byte{0x37}, 32))
	if err != nil {
		t.Fatal(err)
	}
	fixture := &serviceFixture{
		ctx:         ctx,
		database:    database,
		secretStore: secretStore,
		adminID:     1,
		nextUserID:  2,
	}
	fixture.service = NewService(database, secretStore, nil)
	fixture.insertAdminWithID(t, fixture.adminID, "admin@example.test")
	return fixture
}

func (f *serviceFixture) insertAdmin(t *testing.T, email string) int64 {
	t.Helper()
	id := f.nextUserID
	f.nextUserID++
	f.insertAdminWithID(t, id, email)
	return id
}

func (f *serviceFixture) insertAdminWithID(t *testing.T, id int64, email string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := f.database.ExecContext(f.ctx, `
INSERT INTO users(id, email, display_name, created_at, updated_at)
VALUES (?, ?, 'Administrator', ?, ?);
INSERT INTO user_roles(user_id, role, created_at)
VALUES (?, 'admin', ?);`, id, email, now, now, id, now); err != nil {
		t.Fatal(err)
	}
}

func validCreateInput(secret string) CreateInput {
	return CreateInput{
		ProviderLabel: "Example IdP",
		Issuer:        "https://id.example.test/tenant",
		ClientID:      "client-id",
		ClientSecret:  secret,
		Domains:       []string{"example.test"},
	}
}

func validEditInput(revision int64) EditInput {
	return EditInput{
		ProviderLabel:    "Example IdP",
		Issuer:           "https://id.example.test/tenant",
		ClientID:         "client-id",
		Domains:          []string{"example.test"},
		ExpectedRevision: revision,
	}
}

func numberedDomains(count int) []string {
	domains := make([]string, 0, count)
	for i := range count {
		domains = append(domains, fmt.Sprintf("domain-%02d.example", i))
	}
	return domains
}

func storedCiphertext(t *testing.T, database *sql.DB) []byte {
	t.Helper()
	var ciphertext []byte
	if err := database.QueryRow(`SELECT client_secret_ciphertext FROM company_oidc_connections WHERE id = 1`).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func storedConnectionTimes(t *testing.T, database *sql.DB) (string, string) {
	t.Helper()
	var createdAt, updatedAt string
	if err := database.QueryRow(`SELECT created_at, updated_at FROM company_oidc_connections WHERE id = 1`).Scan(&createdAt, &updatedAt); err != nil {
		t.Fatal(err)
	}
	return createdAt, updatedAt
}

func assertAuditCount(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow(`SELECT count(*) FROM audit_events WHERE action = ?`, audit.ActionOIDCConnectionDraftSaved).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("OIDC Draft audit count = %d, want %d", got, want)
	}
}

func assertDraftSavedAudit(t *testing.T, database *sql.DB, revision int64, secretReplaced bool, domainCount int) {
	t.Helper()
	var action, subjectType, subjectID, detailsJSON string
	var actorUserID int64
	if err := database.QueryRow(`
SELECT actor_user_id, action, subject_type, subject_id, details_json
FROM audit_events
WHERE action = ? AND json_extract(details_json, '$.revision') = ?`, audit.ActionOIDCConnectionDraftSaved, revision).Scan(
		&actorUserID,
		&action,
		&subjectType,
		&subjectID,
		&detailsJSON,
	); err != nil {
		t.Fatal(err)
	}
	if actorUserID <= 0 || action != audit.ActionOIDCConnectionDraftSaved || subjectType != audit.SubjectTypeOIDCConnection || subjectID != "1" {
		t.Fatalf("unexpected audit identity: actor=%d action=%q subject=%s/%s", actorUserID, action, subjectType, subjectID)
	}
	var details map[string]any
	if err := json.Unmarshal([]byte(detailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if len(details) != 3 || details["revision"] != float64(revision) || details["secret_replaced"] != secretReplaced || details["domain_count"] != float64(domainCount) {
		t.Fatalf("unexpected sanitized audit details: %s", detailsJSON)
	}
	for _, forbidden := range []string{"Example IdP", "https://id.example.test", "client-id", "example.test", "ciphertext", testClientSecret} {
		if strings.Contains(strings.ToLower(detailsJSON), strings.ToLower(forbidden)) {
			t.Fatalf("audit details contain forbidden value %q: %s", forbidden, detailsJSON)
		}
	}
}

func companyOIDCTestMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}

type leakingErrorStore struct {
	secret string
}

func (s leakingErrorStore) Encrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("failed for " + s.secret)
}

func (leakingErrorStore) Decrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}
