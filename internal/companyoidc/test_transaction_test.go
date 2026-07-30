package companyoidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/secrets"
)

const testSignInSessionID = "test-sign-in-local-session"

const (
	testSignInTokenEndpoint = "https://id.example.test/token"
	testSignInJWKSURI       = "https://id.example.test/jwks"
	testSignInRedirectURI   = "http://localhost:8080" + TestSignInCallbackPath
)

var testSignInNow = time.Date(2026, 7, 29, 14, 30, 0, 123456789, time.UTC)

func TestTestSignInMaterialUsesCanonicalRandomTokensAndS256(t *testing.T) {
	material, err := newTestSignInMaterial(bytes.NewReader(testSignInRandomBytes(0x11, 0x22, 0x33)))
	if err != nil {
		t.Fatal(err)
	}
	wantState := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, testSignInTokenBytes))
	wantNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, testSignInTokenBytes))
	wantVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, testSignInTokenBytes))
	if material.state != wantState || material.nonce != wantNonce || material.pkceVerifier != wantVerifier {
		t.Fatalf("unexpected deterministic material: %#v", material)
	}
	for name, value := range map[string]string{
		"state":    material.state,
		"nonce":    material.nonce,
		"verifier": material.pkceVerifier,
	} {
		if len(value) != 43 || !canonicalTestToken(value) || strings.Contains(value, "=") {
			t.Fatalf("%s is not a canonical 256-bit base64url token: %q", name, value)
		}
	}
	if material.state == material.nonce || material.state == material.pkceVerifier || material.nonce == material.pkceVerifier {
		t.Fatal("independent Test sign-in values unexpectedly matched")
	}
	if material.pkceChallenge != pkceS256Challenge(material.pkceVerifier) {
		t.Fatal("PKCE challenge was not derived from the verifier")
	}

	const rfcVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if got := pkceS256Challenge(rfcVerifier); got != rfcChallenge {
		t.Fatalf("RFC 7636 S256 challenge = %q, want %q", got, rfcChallenge)
	}
	if _, err := newTestSignInMaterial(bytes.NewReader(make([]byte, 3*testSignInTokenBytes-1))); err == nil {
		t.Fatal("accepted a short cryptographic random read")
	}
}

func TestCanonicalTestTokenRejectsWrongLengthBeforeDecoding(t *testing.T) {
	canonical := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, testSignInTokenBytes))
	oversized := strings.Repeat("A", 1<<20)
	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "exact canonical 43-character state", value: canonical, want: true},
		{name: "shorter input", value: canonical[:len(canonical)-1]},
		{name: "longer input", value: canonical + "A"},
		{name: "very large input", value: oversized},
		{name: "padded base64url", value: canonical + "="},
		{name: "malformed base64url", value: strings.Repeat("!", len(canonical))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalTestToken(tc.value); got != tc.want {
				t.Fatalf("canonicalTestToken() = %v, want %v", got, tc.want)
			}
		})
	}
	if got := len(canonical); got != base64.RawURLEncoding.EncodedLen(testSignInTokenBytes) || got != 43 {
		t.Fatalf("canonical token length = %d, want 43", got)
	}
	if allocations := testing.AllocsPerRun(10, func() {
		_ = canonicalTestToken(oversized)
	}); allocations != 0 {
		t.Fatalf("oversized token validation allocated %.1f times; length must be rejected before decoding", allocations)
	}
}

func TestTestSignInDigestsUseDistinctVersionedDomains(t *testing.T) {
	const value = "same protocol material"
	if testSignInStateDigestPurpose != "thawguard:company-oidc-test-state:v1" ||
		testSignInNonceDigestPurpose != "thawguard:company-oidc-test-nonce:v1" ||
		testSignInSessionDigestPurpose != "thawguard:company-oidc-test-session:v1" {
		t.Fatal("Test sign-in digest purposes changed without a version change")
	}

	raw := sha256.Sum256([]byte(value))
	digests := [][sha256.Size]byte{
		testSignInDigest(testSignInStateDigestPurpose, value),
		testSignInDigest(testSignInNonceDigestPurpose, value),
		testSignInDigest(testSignInSessionDigestPurpose, value),
	}
	for i, digest := range digests {
		if digest == raw {
			t.Fatalf("digest %d is not domain-separated from raw SHA-256", i)
		}
		for j := 0; j < i; j++ {
			if digest == digests[j] {
				t.Fatalf("digest domains %d and %d collide", j, i)
			}
		}
	}
}

func TestPrepareTestSignInPersistsOnlyBoundProtectedMaterial(t *testing.T) {
	fixture := newServiceFixture(t)
	configureReadyTestSignInDraft(t, fixture)
	insertTestSignInSession(t, fixture, testSignInSessionID, fixture.adminID, testSignInNow.Add(time.Hour))
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x11, 0x22, 0x33))

	var auditsBefore int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&auditsBefore); err != nil {
		t.Fatal(err)
	}
	initiation, err := fixture.service.prepareTestSignIn(fixture.ctx, TestSignInInitiationInput{
		ActorUserID:      fixture.adminID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: 1,
		TokenEndpoint:    testSignInTokenEndpoint,
		JWKSURI:          testSignInJWKSURI,
		RedirectURI:      testSignInRedirectURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantState := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, testSignInTokenBytes))
	wantNonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, testSignInTokenBytes))
	wantVerifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, testSignInTokenBytes))
	if initiation.State != wantState || initiation.Nonce != wantNonce ||
		initiation.PKCEChallenge != pkceS256Challenge(wantVerifier) ||
		initiation.Issuer != "https://id.example.test/tenant" ||
		initiation.ClientID != "client-id" {
		t.Fatalf("unexpected initiation result: %#v", initiation)
	}
	if _, exposed := reflect.TypeOf(initiation).FieldByName("PKCEVerifier"); exposed {
		t.Fatal("initiation model exposes the PKCE verifier")
	}

	var stateDigest, sessionDigest, nonceDigest, ciphertext []byte
	var connectionID, revision, actorID int64
	var tokenEndpoint, jwksURI, redirectURI string
	var createdAtText, expiresAtText string
	if err := fixture.database.QueryRow(`
SELECT state_digest, connection_id, config_revision, actor_user_id,
  session_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
FROM company_oidc_test_transactions`).Scan(
		&stateDigest,
		&connectionID,
		&revision,
		&actorID,
		&sessionDigest,
		&nonceDigest,
		&ciphertext,
		&tokenEndpoint,
		&jwksURI,
		&redirectURI,
		&createdAtText,
		&expiresAtText,
	); err != nil {
		t.Fatal(err)
	}
	wantStateDigest := testSignInDigest(testSignInStateDigestPurpose, wantState)
	wantSessionDigest := testSessionBindingDigest(testSignInSessionID)
	wantNonceDigest := testSignInDigest(testSignInNonceDigestPurpose, wantNonce)
	if !bytes.Equal(stateDigest, wantStateDigest[:]) ||
		!bytes.Equal(sessionDigest, wantSessionDigest[:]) ||
		!bytes.Equal(nonceDigest, wantNonceDigest[:]) {
		t.Fatal("stored Test sign-in digests do not bind the issued material")
	}
	if connectionID != 1 || revision != 1 || actorID != fixture.adminID {
		t.Fatalf("unexpected transaction binding: connection=%d revision=%d actor=%d", connectionID, revision, actorID)
	}
	if tokenEndpoint != testSignInTokenEndpoint || jwksURI != testSignInJWKSURI || redirectURI != testSignInRedirectURI {
		t.Fatalf("unexpected pinned protocol metadata: token=%q jwks=%q redirect=%q", tokenEndpoint, jwksURI, redirectURI)
	}
	createdAt, err := parseCompanyOIDCTime(createdAtText)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt, err := parseCompanyOIDCTime(expiresAtText)
	if err != nil {
		t.Fatal(err)
	}
	if !createdAt.Equal(testSignInNow) || !expiresAt.Equal(testSignInNow.Add(10*time.Minute)) {
		t.Fatalf("transaction interval = %s through %s", createdAt, expiresAt)
	}
	plaintext, err := fixture.secretStore.Decrypt(fixture.ctx, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != wantVerifier {
		t.Fatalf("decrypted verifier = %q, want exact generated verifier", plaintext)
	}
	clear(plaintext)

	for name, stored := range map[string][]byte{
		"state digest":   stateDigest,
		"session digest": sessionDigest,
		"nonce digest":   nonceDigest,
		"ciphertext":     ciphertext,
	} {
		for _, forbidden := range []string{wantState, wantNonce, wantVerifier, testSignInSessionID} {
			if bytes.Contains(stored, []byte(forbidden)) {
				t.Fatalf("%s contains plaintext protocol material", name)
			}
		}
	}
	var auditText string
	if err := fixture.database.QueryRow(`SELECT coalesce(group_concat(action || details_json, '|'), '') FROM audit_events`).Scan(&auditText); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{wantState, wantNonce, wantVerifier, testSignInSessionID} {
		if strings.Contains(auditText, forbidden) {
			t.Fatalf("audit contains plaintext protocol material %q", forbidden)
		}
	}
	var auditsAfter int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&auditsAfter); err != nil {
		t.Fatal(err)
	}
	if auditsAfter != auditsBefore {
		t.Fatalf("initiation wrote %d audit events; terminal completion owns Test sign-in audit", auditsAfter-auditsBefore)
	}
}

func TestPrepareTestSignInRequiresReadyExactDraftAndCurrentAdministratorSession(t *testing.T) {
	t.Run("missing Draft", func(t *testing.T) {
		fixture := newServiceFixture(t)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if !errors.Is(err, ErrNoDraft) {
			t.Fatalf("expected missing Draft, got %v", err)
		}
	})

	t.Run("missing metadata evidence", func(t *testing.T) {
		fixture := newServiceFixture(t)
		createTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if !errors.Is(err, ErrTestSignInUnavailable) {
			t.Fatalf("expected unavailable Test sign-in, got %v", err)
		}
	})

	t.Run("failed metadata evidence", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureTestSignInDraft(t, fixture, SetupCheckJWKSUnavailable)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if !errors.Is(err, ErrTestSignInUnavailable) {
			t.Fatalf("expected failed metadata evidence rejection, got %v", err)
		}
	})

	t.Run("stale metadata revision", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureReadyTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		if _, err := fixture.database.Exec(`UPDATE company_oidc_setup_checks SET config_revision = 2 WHERE connection_id = 1`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if !errors.Is(err, ErrTestSignInUnavailable) {
			t.Fatalf("expected stale evidence rejection, got %v", err)
		}
	})

	t.Run("expected revision mismatch", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureReadyTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 2))
		if !errors.Is(err, ErrTestSignInUnavailable) {
			t.Fatalf("expected revision fence rejection, got %v", err)
		}
	})

	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *serviceFixture)
	}{
		{
			name: "disabled Administrator",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				_, err := fixture.database.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, formatCompanyOIDCTime(testSignInNow), fixture.adminID)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "demoted Administrator",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				_, err := fixture.database.Exec(`DELETE FROM user_roles WHERE user_id = ? AND role = 'admin'`, fixture.adminID)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "forced password session",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				forceTestSignInPasswordChange(t, fixture)
			},
		},
		{
			name: "expired session",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				_, err := fixture.database.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, testSignInNow.Format(time.RFC3339Nano), testSignInSessionID)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "revoked session",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				_, err := fixture.database.Exec(`DELETE FROM sessions WHERE id = ?`, testSignInSessionID)
				if err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			configureReadyTestSignInDraft(t, fixture)
			prepareTestSignInSession(t, fixture, fixture.adminID)
			tc.mutate(t, fixture)
			_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
			if !errors.Is(err, ErrTestSignInAuthorization) {
				t.Fatalf("expected current Administrator session rejection, got %v", err)
			}
		})
	}
}

func TestPrepareTestSignInSamplesTimeAfterWriterOwnership(t *testing.T) {
	fixture := newServiceFixture(t)
	configureReadyTestSignInDraft(t, fixture)
	sessionExpiry := testSignInNow.Add(time.Minute)
	insertTestSignInSession(t, fixture, testSignInSessionID, fixture.adminID, sessionExpiry)
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x11, 0x22, 0x33))

	var clock atomic.Int64
	clock.Store(sessionExpiry.Add(-time.Nanosecond).UnixNano())
	fixture.service.now = func() time.Time {
		return time.Unix(0, clock.Load()).UTC()
	}
	writer := holdTestSignInWriter(t, fixture)
	result := make(chan error, 1)
	go func() {
		_, err := fixture.service.prepareTestSignIn(
			fixture.ctx,
			validTestSignInInput(fixture.adminID, 1),
		)
		result <- err
	}()

	waitForTestSignInConnections(t, fixture.database, 2)
	clock.Store(sessionExpiry.UnixNano())
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrTestSignInAuthorization) {
			t.Fatalf("expected post-lock expired-session rejection, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Test sign-in initiation did not resume after writer release")
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestPrepareTestSignInRejectsMalformedStateAndSanitizesFailures(t *testing.T) {
	t.Run("malformed setup-check timestamp", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureReadyTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		if _, err := fixture.database.Exec(`UPDATE company_oidc_setup_checks SET checked_at = '2026-02-30T10:00:00.000000000Z' WHERE connection_id = 1`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if !errors.Is(err, ErrTestSignInUnavailable) {
			t.Fatalf("expected malformed setup-check rejection, got %v", err)
		}
	})

	t.Run("malformed saved issuer", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureReadyTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		if _, err := fixture.database.Exec(`UPDATE company_oidc_connections SET issuer = 'http://invalid.example' WHERE id = 1`); err != nil {
			t.Fatal(err)
		}
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if !errors.Is(err, ErrTestSignInUnavailable) {
			t.Fatalf("expected malformed snapshot rejection, got %v", err)
		}
	})

	t.Run("encryption error", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureReadyTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x41, 0x42, 0x43))
		fixture.service.secrets = verifierLeakingErrorStore{}
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if err == nil || err.Error() != "encrypt company OIDC Test sign-in verifier" {
			t.Fatalf("unexpected sanitized encryption error: %v", err)
		}
		for _, forbidden := range []string{
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, testSignInTokenBytes)),
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, testSignInTokenBytes)),
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, testSignInTokenBytes)),
		} {
			if strings.Contains(err.Error(), forbidden) {
				t.Fatalf("encryption error leaked protocol material %q", forbidden)
			}
		}
		assertTestSignInTransactionCount(t, fixture.database, 0)
	})

	t.Run("insert conflict rolls back replacement", func(t *testing.T) {
		fixture := newServiceFixture(t)
		configureReadyTestSignInDraft(t, fixture)
		prepareTestSignInSession(t, fixture, fixture.adminID)
		fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x51, 0x52, 0x53))
		state := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x51}, testSignInTokenBytes))
		stateDigest := testSignInDigest(testSignInStateDigestPurpose, state)
		insertTestTransactionRow(
			t,
			fixture,
			stateDigest,
			testSessionBindingDigest("another-session"),
			testSignInNow,
			testSignInNow.Add(testSignInTransactionTTL),
		)
		_, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1))
		if err == nil || strings.Contains(err.Error(), state) {
			t.Fatalf("expected sanitized insert conflict, got %v", err)
		}
		assertTestSignInTransactionCount(t, fixture.database, 1)
	})
}

func TestClaimTestSignInIsStrictlyOneTimeAndSessionBound(t *testing.T) {
	fixture := newServiceFixture(t)
	initiation, verifier := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
	claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     initiation.State,
		SessionID: testSignInSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantNonceDigest := testSignInDigest(testSignInNonceDigestPurpose, initiation.Nonce)
	if claim.issuer != initiation.Issuer || claim.clientID != initiation.ClientID ||
		claimVerifier(t, fixture, claim) != verifier || claim.nonceDigest != wantNonceDigest ||
		claim.configRevision != 1 || !claim.createdAt.Equal(testSignInNow) {
		t.Fatalf("unexpected claimed transaction: %#v", claim)
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
	if _, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     initiation.State,
		SessionID: testSignInSessionID,
	}); !errors.Is(err, ErrTestTransactionUnavailable) {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	t.Run("different local session consumes transaction", func(t *testing.T) {
		fixture := newServiceFixture(t)
		initiation, _ := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
		const otherSession = "other-current-session"
		insertTestSignInSession(t, fixture, otherSession, fixture.adminID, testSignInNow.Add(time.Hour))
		_, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
			State:     initiation.State,
			SessionID: otherSession,
		})
		if !errors.Is(err, ErrTestTransactionUnavailable) {
			t.Fatalf("expected generic session mismatch rejection, got %v", err)
		}
		assertTestSignInTransactionCount(t, fixture.database, 0)
	})

	t.Run("missing local session consumes transaction", func(t *testing.T) {
		fixture := newServiceFixture(t)
		initiation, _ := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
		_, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
			State: initiation.State,
		})
		if !errors.Is(err, ErrTestTransactionUnavailable) {
			t.Fatalf("expected generic missing-session rejection, got %v", err)
		}
		assertTestSignInTransactionCount(t, fixture.database, 0)
	})
}

func TestClaimTestSignInSurvivesProcessRestartWithoutCreatingAuthority(t *testing.T) {
	fixture := newServiceFixture(t)
	initiation, verifier := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
	restarted := NewService(fixture.database, fixture.secretStore, nil)
	restarted.now = func() time.Time { return testSignInNow.Add(time.Minute) }
	claim, err := restarted.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     initiation.State,
		SessionID: testSignInSessionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if claimVerifier(t, fixture, claim) != verifier || claim.configRevision != 1 {
		t.Fatalf("restarted service returned wrong protected transaction: %#v", claim)
	}
	var sessions int
	if err := fixture.database.QueryRow(`SELECT count(*) FROM sessions WHERE id = ?`, testSignInSessionID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("claim created or replaced local session authority: session count=%d", sessions)
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestClaimTestSignInConsumesExpiredRevokedAndInvalidatedTransactions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *serviceFixture)
	}{
		{
			name: "strict expiry",
			mutate: func(_ *testing.T, fixture *serviceFixture) {
				fixture.service.now = func() time.Time { return testSignInNow.Add(testSignInTransactionTTL) }
			},
		},
		{
			name: "disabled Administrator",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`UPDATE users SET disabled_at = ? WHERE id = ?`, formatCompanyOIDCTime(testSignInNow), fixture.adminID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "demoted Administrator",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`DELETE FROM user_roles WHERE user_id = ? AND role = 'admin'`, fixture.adminID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "forced password",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				forceTestSignInPasswordChange(t, fixture)
			},
		},
		{
			name: "expired local session",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`UPDATE sessions SET expires_at = ? WHERE id = ?`, testSignInNow.Format(time.RFC3339Nano), testSignInSessionID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "revoked session",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`DELETE FROM sessions WHERE id = ?`, testSignInSessionID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "changed Draft revision",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				input := validEditInput(1)
				input.ProviderLabel = "Changed while in flight"
				if err := fixture.service.Edit(fixture.ctx, fixture.adminID, input); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing verified evidence",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`DELETE FROM company_oidc_setup_checks WHERE connection_id = 1`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed current Draft",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`UPDATE company_oidc_connections SET client_id = char(10) WHERE id = 1`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed setup-check evidence",
			mutate: func(t *testing.T, fixture *serviceFixture) {
				if _, err := fixture.database.Exec(`UPDATE company_oidc_setup_checks SET checked_at = '2026-02-30T10:00:00.000000000Z' WHERE connection_id = 1`); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			initiation, _ := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
			tc.mutate(t, fixture)
			_, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
				State:     initiation.State,
				SessionID: testSignInSessionID,
			})
			if !errors.Is(err, ErrTestTransactionUnavailable) {
				t.Fatalf("expected generic terminal rejection, got %v", err)
			}
			assertTestSignInTransactionCount(t, fixture.database, 0)
		})
	}

	t.Run("malformed encrypted verifier", func(t *testing.T) {
		fixture := newServiceFixture(t)
		initiation, _ := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
		if _, err := fixture.database.Exec(`UPDATE company_oidc_test_transactions SET pkce_verifier_ciphertext = x'01'`); err != nil {
			t.Fatal(err)
		}
		claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
			State:     initiation.State,
			SessionID: testSignInSessionID,
		})
		if err != nil || len(claim.pkceCiphertext) != 1 {
			t.Fatalf("expected claim to capture malformed ciphertext for post-claim result mapping, claim=%#v err=%v", claim, err)
		}
		assertTestSignInTransactionCount(t, fixture.database, 0)
	})

	for name, state := range map[string]string{
		"missing":      "",
		"malformed":    "not-a-state",
		"noncanonical": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x71}, testSignInTokenBytes)) + "=",
	} {
		t.Run(name+" callback state", func(t *testing.T) {
			fixture := newServiceFixture(t)
			_, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
				State:     state,
				SessionID: testSignInSessionID,
			})
			if !errors.Is(err, ErrTestTransactionUnavailable) {
				t.Fatalf("expected generic malformed callback rejection, got %v", err)
			}
		})
	}
}

func TestClaimTestSignInPreservesTransactionOnOperationalSnapshotFailure(t *testing.T) {
	fixture := newServiceFixture(t)
	initiation, verifier := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
	if _, err := fixture.database.Exec(`ALTER TABLE company_oidc_setup_checks RENAME TO unavailable_company_oidc_setup_checks`); err != nil {
		t.Fatal(err)
	}

	claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     initiation.State,
		SessionID: testSignInSessionID,
	})
	if !errors.Is(err, ErrTestTransactionUnavailable) || err != ErrTestTransactionUnavailable {
		t.Fatalf("expected generic operational snapshot error, got %v", err)
	}
	if !reflect.DeepEqual(claim, testSignInClaim{}) {
		t.Fatalf("operational snapshot failure returned protocol material: %#v", claim)
	}
	assertTestSignInTransactionCount(t, fixture.database, 1)

	if _, err := fixture.database.Exec(`ALTER TABLE unavailable_company_oidc_setup_checks RENAME TO company_oidc_setup_checks`); err != nil {
		t.Fatal(err)
	}
	retry, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
		State:     initiation.State,
		SessionID: testSignInSessionID,
	})
	if err != nil {
		t.Fatalf("retry after operational snapshot failure: %v", err)
	}
	if claimVerifier(t, fixture, retry) != verifier {
		t.Fatal("retry returned the wrong verifier")
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestClaimTestSignInSamplesTimeAfterWriterOwnership(t *testing.T) {
	fixture := newServiceFixture(t)
	initiation, _ := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
	transactionExpiry := testSignInNow.Add(testSignInTransactionTTL)

	var clock atomic.Int64
	clock.Store(transactionExpiry.Add(-time.Nanosecond).UnixNano())
	fixture.service.now = func() time.Time {
		return time.Unix(0, clock.Load()).UTC()
	}
	writer := holdTestSignInWriter(t, fixture)
	type claimResult struct {
		claim testSignInClaim
		err   error
	}
	result := make(chan claimResult, 1)
	go func() {
		claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
			State:     initiation.State,
			SessionID: testSignInSessionID,
		})
		result <- claimResult{claim: claim, err: err}
	}()

	waitForTestSignInConnections(t, fixture.database, 2)
	clock.Store(transactionExpiry.UnixNano())
	if err := writer.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-result:
		if !errors.Is(result.err, ErrTestTransactionUnavailable) {
			t.Fatalf("expected post-lock expired-transaction rejection, got %v", result.err)
		}
		if !reflect.DeepEqual(result.claim, testSignInClaim{}) {
			t.Fatalf("expired transaction returned protocol material: %#v", result.claim)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Test sign-in claim did not resume after writer release")
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestClaimTestSignInAllowsExactlyOneConcurrentWinner(t *testing.T) {
	fixture := newServiceFixture(t)
	initiation, verifier := prepareReadyTestSignIn(t, fixture, testSignInSessionID)
	start := make(chan struct{})
	results := make(chan struct {
		claim testSignInClaim
		err   error
	}, 2)
	for range 2 {
		go func() {
			<-start
			claim, err := fixture.service.claimTestSignIn(fixture.ctx, testSignInClaimInput{
				State:     initiation.State,
				SessionID: testSignInSessionID,
			})
			results <- struct {
				claim testSignInClaim
				err   error
			}{claim: claim, err: err}
		}()
	}
	close(start)
	winners := 0
	losers := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			winners++
			if claimVerifier(t, fixture, result.claim) != verifier {
				t.Fatal("winning callback received wrong verifier")
			}
			continue
		}
		if !errors.Is(result.err, ErrTestTransactionUnavailable) {
			t.Fatalf("losing callback received unexpected error: %v", result.err)
		}
		losers++
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("concurrent callbacks produced %d winners and %d losers", winners, losers)
	}
	assertTestSignInTransactionCount(t, fixture.database, 0)
}

func TestPrepareTestSignInCleansBoundedExpiredRowsAndPreservesLiveRows(t *testing.T) {
	fixture := newServiceFixture(t)
	configureReadyTestSignInDraft(t, fixture)
	insertTestSignInSession(t, fixture, testSignInSessionID, fixture.adminID, testSignInNow.Add(time.Hour))
	for i := range testSignInCleanupLimit + 5 {
		state := sha256.Sum256([]byte(fmt.Sprintf("expired-state-%03d", i)))
		session := sha256.Sum256([]byte(fmt.Sprintf("expired-session-%03d", i)))
		insertTestTransactionRow(
			t,
			fixture,
			state,
			session,
			testSignInNow.Add(-20*time.Minute),
			testSignInNow.Add(-time.Minute),
		)
	}
	liveState := sha256.Sum256([]byte("preexisting-live-state"))
	liveSession := sha256.Sum256([]byte("preexisting-live-session"))
	insertTestTransactionRow(t, fixture, liveState, liveSession, testSignInNow, testSignInNow.Add(time.Minute))
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x61, 0x62, 0x63))
	if _, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1)); err != nil {
		t.Fatal(err)
	}

	var expired, live int
	if err := fixture.database.QueryRow(
		`SELECT count(*) FROM company_oidc_test_transactions WHERE expires_at <= ?`,
		formatCompanyOIDCTime(testSignInNow),
	).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.QueryRow(
		`SELECT count(*) FROM company_oidc_test_transactions WHERE expires_at > ?`,
		formatCompanyOIDCTime(testSignInNow),
	).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if expired != 5 || live != 2 {
		t.Fatalf("bounded cleanup left expired=%d live=%d, want 5 and 2", expired, live)
	}
	var preserved int
	if err := fixture.database.QueryRow(
		`SELECT count(*) FROM company_oidc_test_transactions WHERE state_digest = ?`,
		liveState[:],
	).Scan(&preserved); err != nil {
		t.Fatal(err)
	}
	if preserved != 1 {
		t.Fatal("opportunistic cleanup deleted a live transaction")
	}
}

func TestPrepareTestSignInDoesNotDecryptClientSecret(t *testing.T) {
	fixture := newServiceFixture(t)
	createTestSignInDraft(t, fixture)
	store := &countingTestSignInStore{delegate: fixture.secretStore}
	fixture.service.secrets = store
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		return setupCheckReport(SetupCheckVerified, "", 1)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err != nil {
		t.Fatal(err)
	}
	prepareTestSignInSession(t, fixture, fixture.adminID)
	if _, err := fixture.service.prepareTestSignIn(fixture.ctx, validTestSignInInput(fixture.adminID, 1)); err != nil {
		t.Fatal(err)
	}
	if store.decrypts != 0 {
		t.Fatalf("metadata or initiation decrypted stored secret material %d times", store.decrypts)
	}
	if store.encrypts != 1 {
		t.Fatalf("expected one verifier encryption, got %d", store.encrypts)
	}
}

type countingTestSignInStore struct {
	delegate secrets.Store
	encrypts int
	decrypts int
}

func (s *countingTestSignInStore) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	s.encrypts++
	return s.delegate.Encrypt(ctx, plaintext)
}

func (s *countingTestSignInStore) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	s.decrypts++
	return s.delegate.Decrypt(ctx, ciphertext)
}

type verifierLeakingErrorStore struct{}

func (verifierLeakingErrorStore) Encrypt(_ context.Context, plaintext []byte) ([]byte, error) {
	return nil, errors.New("failed to encrypt " + string(plaintext))
}

func (verifierLeakingErrorStore) Decrypt(context.Context, []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func configureReadyTestSignInDraft(t *testing.T, fixture *serviceFixture) {
	t.Helper()
	configureTestSignInDraft(t, fixture, SetupCheckVerified)
}

func configureTestSignInDraft(t *testing.T, fixture *serviceFixture, result SetupCheckResultCode) {
	t.Helper()
	createTestSignInDraft(t, fixture)
	fixture.service.check = func(context.Context, string) SetupCheckReport {
		candidates := int64(-1)
		if result == SetupCheckVerified {
			candidates = 1
		}
		return setupCheckReport(result, "", candidates)
	}
	if _, err := fixture.service.Check(fixture.ctx, fixture.adminID); err != nil {
		t.Fatal(err)
	}
}

func createTestSignInDraft(t *testing.T, fixture *serviceFixture) {
	t.Helper()
	fixture.service.now = func() time.Time { return testSignInNow }
	if err := fixture.service.Create(fixture.ctx, fixture.adminID, validCreateInput(testClientSecret)); err != nil {
		t.Fatal(err)
	}
}

func prepareReadyTestSignIn(
	t *testing.T,
	fixture *serviceFixture,
	sessionID string,
) (TestSignInInitiation, string) {
	t.Helper()
	configureReadyTestSignInDraft(t, fixture)
	insertTestSignInSession(t, fixture, sessionID, fixture.adminID, testSignInNow.Add(time.Hour))
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x11, 0x22, 0x33))
	initiation, err := fixture.service.prepareTestSignIn(fixture.ctx, TestSignInInitiationInput{
		ActorUserID:      fixture.adminID,
		SessionID:        sessionID,
		ExpectedRevision: 1,
		TokenEndpoint:    testSignInTokenEndpoint,
		JWKSURI:          testSignInJWKSURI,
		RedirectURI:      testSignInRedirectURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, testSignInTokenBytes))
	return initiation, verifier
}

func prepareTestSignInSession(t *testing.T, fixture *serviceFixture, actorID int64) {
	t.Helper()
	fixture.service.now = func() time.Time { return testSignInNow }
	fixture.service.random = bytes.NewReader(testSignInRandomBytes(0x11, 0x22, 0x33))
	insertTestSignInSession(t, fixture, testSignInSessionID, actorID, testSignInNow.Add(time.Hour))
}

func insertTestSignInSession(
	t *testing.T,
	fixture *serviceFixture,
	sessionID string,
	actorID int64,
	expiresAt time.Time,
) {
	t.Helper()
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO sessions(id, user_id, csrf_token, expires_at, created_at)
VALUES (?, ?, 'test-csrf-token', ?, ?)`,
		sessionID,
		actorID,
		expiresAt.UTC().Format(time.RFC3339Nano),
		testSignInNow.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
}

func forceTestSignInPasswordChange(t *testing.T, fixture *serviceFixture) {
	t.Helper()
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO local_credentials(user_id, password_hash, must_change_password, created_at, updated_at)
VALUES (?, 'test-password-hash', 1, ?, ?)`,
		fixture.adminID,
		testSignInNow.Format(time.RFC3339Nano),
		testSignInNow.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatal(err)
	}
}

func validTestSignInInput(actorID, revision int64) TestSignInInitiationInput {
	return TestSignInInitiationInput{
		ActorUserID:      actorID,
		SessionID:        testSignInSessionID,
		ExpectedRevision: revision,
		TokenEndpoint:    testSignInTokenEndpoint,
		JWKSURI:          testSignInJWKSURI,
		RedirectURI:      testSignInRedirectURI,
	}
}

func testSignInRandomBytes(values ...byte) []byte {
	result := make([]byte, 0, len(values)*testSignInTokenBytes)
	for _, value := range values {
		result = append(result, bytes.Repeat([]byte{value}, testSignInTokenBytes)...)
	}
	return result
}

func insertTestTransactionRow(
	t *testing.T,
	fixture *serviceFixture,
	stateDigest [sha256.Size]byte,
	sessionDigest [sha256.Size]byte,
	createdAt time.Time,
	expiresAt time.Time,
) {
	t.Helper()
	nonceDigest := sha256.Sum256([]byte("test nonce digest"))
	if _, err := fixture.database.ExecContext(fixture.ctx, `
INSERT INTO company_oidc_test_transactions(
  state_digest, connection_id, config_revision, actor_user_id,
  session_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (?, 1, 1, ?, ?, ?, x'01', ?, ?, ?, ?, ?)`,
		stateDigest[:],
		fixture.adminID,
		sessionDigest[:],
		nonceDigest[:],
		testSignInTokenEndpoint,
		testSignInJWKSURI,
		testSignInRedirectURI,
		formatCompanyOIDCTime(createdAt),
		formatCompanyOIDCTime(expiresAt),
	); err != nil {
		t.Fatal(err)
	}
}

func holdTestSignInWriter(t *testing.T, fixture *serviceFixture) *sql.Tx {
	t.Helper()
	tx, err := fixture.database.BeginTx(fixture.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.ExecContext(
		fixture.ctx,
		`UPDATE users SET updated_at = updated_at WHERE id = ?`,
		fixture.adminID,
	); err != nil {
		t.Fatal(err)
	}
	return tx
}

func waitForTestSignInConnections(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for database.Stats().InUse < want {
		if time.Now().After(deadline) {
			t.Fatalf("database has %d connections in use, want at least %d", database.Stats().InUse, want)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertTestSignInTransactionCount(t *testing.T, database *sql.DB, want int) {
	t.Helper()
	var got int
	if err := database.QueryRow(`SELECT count(*) FROM company_oidc_test_transactions`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Test sign-in transaction count = %d, want %d", got, want)
	}
}

func claimVerifier(t *testing.T, fixture *serviceFixture, claim testSignInClaim) string {
	t.Helper()
	plaintext, err := fixture.secretStore.Decrypt(fixture.ctx, claim.pkceCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plaintext)
	return string(plaintext)
}
