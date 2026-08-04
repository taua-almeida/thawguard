package auth

import (
	"context"
	"database/sql"
	"testing"
)

const (
	companyOIDCTestRevision   = int64(3)
	companyOIDCTestGeneration = int64(5)
	companyOIDCTestTimestamp  = "2026-07-29T10:00:00.000000000Z"
)

func insertEnabledCompanyOIDCConnection(t *testing.T, ctx context.Context, database *sql.DB, linkedUserID int64) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext,
  revision, enabled, activation_generation, created_at, updated_at
)
VALUES (1, 'Example IdP', 'https://id.example.test', 'client-id', x'01', ?, 1, ?, ?, ?)`,
		companyOIDCTestRevision,
		companyOIDCTestGeneration,
		companyOIDCTestTimestamp,
		companyOIDCTestTimestamp,
	); err != nil {
		t.Fatalf("insert enabled company OIDC connection: %v", err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_identities(
  connection_id, user_id, issuer, client_id, subject, email, config_revision, linked_at
)
VALUES (1, ?, 'https://id.example.test', 'client-id', 'linked-subject', 'linked@example.test', ?, ?)`,
		linkedUserID,
		companyOIDCTestRevision,
		companyOIDCTestTimestamp,
	); err != nil {
		t.Fatalf("insert linked company OIDC identity: %v", err)
	}
}

func validCompanyOIDCSessionParams(userID int64) CreateCompanyOIDCSessionParams {
	return CreateCompanyOIDCSessionParams{
		UserID:               userID,
		ConnectionRevision:   companyOIDCTestRevision,
		ActivationGeneration: companyOIDCTestGeneration,
	}
}

func countRows(t *testing.T, ctx context.Context, database *sql.DB, query string, args ...any) int {
	t.Helper()
	var got int
	if err := database.QueryRowContext(ctx, query, args...).Scan(&got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestVerifyCurrentPasswordReportsGenericFailure(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := service.VerifyCurrentPassword(ctx, admin.User.ID, accountTestPassword); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	if err := service.VerifyCurrentPassword(ctx, admin.User.ID, "wrong password"); !IsAuthenticationError(err) {
		t.Fatalf("wrong password error = %v, want authentication error", err)
	}
	if err := service.VerifyCurrentPassword(ctx, admin.User.ID, ""); !IsAuthenticationError(err) {
		t.Fatalf("empty password error = %v, want authentication error", err)
	}
	if err := service.VerifyCurrentPassword(ctx, admin.User.ID+100, accountTestPassword); !IsAuthenticationError(err) {
		t.Fatalf("unknown user error = %v, want authentication error", err)
	}
}

func TestCreateCompanyOIDCSessionCarriesProvenanceThroughLookupAndLogout(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)

	session, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !session.CompanyOIDC || session.User.ID != admin.User.ID || session.CSRFToken == "" {
		t.Fatalf("company OIDC session = %+v, want provenance for user %d", session, admin.User.ID)
	}

	loaded, found, err := service.SessionByID(ctx, session.ID)
	if err != nil || !found {
		t.Fatalf("load company OIDC session: found=%v err=%v", found, err)
	}
	if !loaded.CompanyOIDC {
		t.Fatal("provenance did not reach the loaded session")
	}
	local, found, err := service.SessionByID(ctx, admin.ID)
	if err != nil || !found {
		t.Fatalf("load local session: found=%v err=%v", found, err)
	}
	if local.CompanyOIDC {
		t.Fatal("local password session reported company OIDC provenance")
	}

	if err := service.Logout(ctx, session.ID); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, session.ID); got != 0 {
		t.Fatal("logout left the company OIDC session behind")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_sessions`); got != 0 {
		t.Fatal("logout left provenance rows behind")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, admin.ID); got != 1 {
		t.Fatal("logout of the OIDC session deleted the local session")
	}
}

func TestCreateCompanyOIDCSessionRejectsEveryStaleOrIneligibleState(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams
	}{
		{
			name: "unknown user",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				return validCompanyOIDCSessionParams(adminID + 100)
			},
		},
		{
			name: "stale revision",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				params := validCompanyOIDCSessionParams(adminID)
				params.ConnectionRevision++
				return params
			},
		},
		{
			name: "stale activation generation",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				params := validCompanyOIDCSessionParams(adminID)
				params.ActivationGeneration++
				return params
			},
		},
		{
			name: "connection disabled",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				if _, err := database.ExecContext(ctx, `UPDATE company_oidc_connections SET enabled = 0 WHERE id = 1`); err != nil {
					t.Fatal(err)
				}
				return validCompanyOIDCSessionParams(adminID)
			},
		},
		{
			name: "identity removed",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				if _, err := database.ExecContext(ctx, `DELETE FROM company_oidc_identities`); err != nil {
					t.Fatal(err)
				}
				return validCompanyOIDCSessionParams(adminID)
			},
		},
		{
			name: "user disabled",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				if _, err := database.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, companyOIDCTestTimestamp, adminID); err != nil {
					t.Fatal(err)
				}
				return validCompanyOIDCSessionParams(adminID)
			},
		},
		{
			name: "user demoted",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				if _, err := database.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, adminID); err != nil {
					t.Fatal(err)
				}
				return validCompanyOIDCSessionParams(adminID)
			},
		},
		{
			name: "forced password change",
			mutate: func(t *testing.T, ctx context.Context, database *sql.DB, service *Service, adminID int64) CreateCompanyOIDCSessionParams {
				if _, err := database.ExecContext(ctx, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, adminID); err != nil {
					t.Fatal(err)
				}
				return validCompanyOIDCSessionParams(adminID)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
				Email:       "admin@example.test",
				DisplayName: "Admin",
				Password:    accountTestPassword,
			})
			if err != nil {
				t.Fatal(err)
			}
			insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
			sessionsBefore := countRows(t, ctx, database, `SELECT count(*) FROM sessions`)

			params := tc.mutate(t, ctx, database, service, admin.User.ID)
			if _, err := service.CreateCompanyOIDCSession(ctx, params); !IsAuthenticationError(err) {
				t.Fatalf("CreateCompanyOIDCSession error = %v, want authentication error", err)
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions`); got != sessionsBefore {
				t.Fatalf("rejected session creation changed session count from %d to %d", sessionsBefore, got)
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_sessions`); got != 0 {
				t.Fatal("rejected session creation recorded provenance")
			}
		})
	}
}

func TestCredentialMutationsRevokeCompanyOIDCSessions(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64)
	}{
		{
			name: "password change",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64) {
				if _, err := service.ChangePassword(ctx, ChangePasswordParams{
					UserID:          linkedID,
					CurrentPassword: accountTestPassword,
					NewPassword:     "an entirely new passphrase",
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "administrative password reset",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64) {
				if err := service.ResetPassword(ctx, ResetPasswordParams{
					ActorUserID:       actorID,
					UserID:            linkedID,
					TemporaryPassword: "a temporary reset passphrase",
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "account disable",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64) {
				if _, err := service.DisableUser(ctx, actorID, linkedID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
				Email:       "admin@example.test",
				DisplayName: "Admin",
				Password:    accountTestPassword,
			})
			if err != nil {
				t.Fatal(err)
			}
			actor := mustCreateUser(t, ctx, service, "actor@example.test", true)
			insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
			oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
			if err != nil {
				t.Fatal(err)
			}
			actorSession, err := service.Login(ctx, LoginParams{Email: "actor@example.test", Password: accountTestPassword})
			if err != nil {
				t.Fatal(err)
			}

			tc.mutate(t, ctx, service, actor.ID, admin.User.ID)

			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, oidcSession.ID); got != 0 {
				t.Fatal("credential mutation left the company OIDC session alive")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_sessions`); got != 0 {
				t.Fatal("credential mutation left provenance rows behind")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, actorSession.ID); got != 1 {
				t.Fatal("credential mutation revoked an unrelated user's session")
			}
		})
	}
}

func TestPasswordRecoveryRemovesLinkedIdentityAndDisablesCompanyLogin(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := mustCreateUser(t, ctx, service, "actor@example.test", true)
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
	oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_login_transactions(
  state_digest, connection_id, config_revision, activation_generation,
  browser_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (x'A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1', 1, ?, ?,
  x'B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2',
  x'C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3', x'0D',
  'https://id.example.test/token', 'https://id.example.test/jwks',
  'http://localhost:8080/settings/authentication/oidc/callback',
  '2026-07-29T10:01:00.000000000Z', '2026-07-29T10:11:00.000000000Z')`,
		companyOIDCTestRevision,
		companyOIDCTestGeneration,
	); err != nil {
		t.Fatal(err)
	}

	recovery, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{
		ActorUserID: actor.ID,
		UserID:      admin.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
		Token:       recovery.Token,
		NewPassword: "a recovered fresh passphrase",
	}); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_identities`); got != 0 {
		t.Fatal("recovery left the linked identity usable")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND enabled = 0 AND activation_generation = ?`, companyOIDCTestGeneration+1); got != 1 {
		t.Fatal("recovery did not disable company login and advance the activation generation")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_login_transactions`); got != 0 {
		t.Fatal("recovery left pending login transactions behind")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, oidcSession.ID); got != 0 {
		t.Fatal("recovery left the company OIDC session alive")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_identity.unlinked' AND actor_user_id IS NULL AND details_json = ?`, `{"revision":3,"cause":"recovery"}`); got != 1 {
		t.Fatal("recovery did not record the system unlink audit event")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_connection.disabled' AND actor_user_id IS NULL AND details_json = ?`, `{"revision":3,"cause":"recovery"}`); got != 1 {
		t.Fatal("recovery did not record the system disable audit event")
	}

	if _, err := service.Login(ctx, LoginParams{Email: "admin@example.test", Password: "a recovered fresh passphrase"}); err != nil {
		t.Fatalf("recovered password rejected: %v", err)
	}
}

func TestPasswordRecoveryWithoutLinkedIdentityLeavesOIDCStateUntouched(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := mustCreateUser(t, ctx, service, "target@example.test", false)
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)

	recovery, err := service.IssuePasswordRecoveryToken(ctx, IssuePasswordRecoveryParams{
		ActorUserID: admin.User.ID,
		UserID:      target.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CompletePasswordRecovery(ctx, CompletePasswordRecoveryParams{
		Token:       recovery.Token,
		NewPassword: "a recovered fresh passphrase",
	}); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_identities`); got != 1 {
		t.Fatal("recovery for an unlinked user removed another user's identity")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND enabled = 1 AND activation_generation = ?`, companyOIDCTestGeneration); got != 1 {
		t.Fatal("recovery for an unlinked user changed company login state")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action IN ('oidc_identity.unlinked', 'oidc_connection.disabled')`); got != 0 {
		t.Fatal("recovery for an unlinked user recorded OIDC audit events")
	}
}

func insertCompanyOIDCLoginTransactionRow(t *testing.T, ctx context.Context, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_login_transactions(
  state_digest, connection_id, config_revision, activation_generation,
  browser_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (x'D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4D4', 1, ?, ?,
  x'E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5E5',
  x'F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6F6', x'0D',
  'https://id.example.test/token', 'https://id.example.test/jwks',
  'http://localhost:8080/settings/authentication/oidc/callback',
  '2026-07-29T10:01:00.000000000Z', '2026-07-29T10:11:00.000000000Z')`,
		companyOIDCTestRevision,
		companyOIDCTestGeneration,
	); err != nil {
		t.Fatal(err)
	}
}

func insertCompanyOIDCLinkTransactionRow(t *testing.T, ctx context.Context, database *sql.DB, actorUserID int64) {
	t.Helper()
	if _, err := database.ExecContext(ctx, `
INSERT INTO company_oidc_link_transactions(
  state_digest, connection_id, config_revision, activation_generation,
  actor_user_id, session_binding_digest, nonce_digest, pkce_verifier_ciphertext,
  token_endpoint, jwks_uri, redirect_uri, created_at, expires_at
)
VALUES (x'1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A', 1, ?, ?, ?,
  x'2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B2B',
  x'3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C3C', x'0D',
  'https://id.example.test/token', 'https://id.example.test/jwks',
  'http://localhost:8080/settings/authentication/oidc/callback',
  '2026-07-29T10:01:00.000000000Z', '2026-07-29T10:11:00.000000000Z')`,
		companyOIDCTestRevision,
		companyOIDCTestGeneration,
		actorUserID,
	); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityLossDisablesCompanyLoginAndRetainsIdentity(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64)
	}{
		{
			name: "admin demotion",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64) {
				if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: linkedID, Admin: false}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "account disable",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64) {
				if _, err := service.DisableUser(ctx, actorID, linkedID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "forced password reset",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, linkedID int64) {
				if err := service.ResetPassword(ctx, ResetPasswordParams{
					ActorUserID:       actorID,
					UserID:            linkedID,
					TemporaryPassword: "a temporary reset passphrase",
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
				Email:       "admin@example.test",
				DisplayName: "Admin",
				Password:    accountTestPassword,
			})
			if err != nil {
				t.Fatal(err)
			}
			actor := mustCreateUser(t, ctx, service, "actor@example.test", true)
			insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
			insertCompanyOIDCLoginTransactionRow(t, ctx, database)
			insertCompanyOIDCLinkTransactionRow(t, ctx, database, admin.User.ID)
			oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
			if err != nil {
				t.Fatal(err)
			}
			actorSession, err := service.Login(ctx, LoginParams{Email: "actor@example.test", Password: accountTestPassword})
			if err != nil {
				t.Fatal(err)
			}

			tc.mutate(t, ctx, service, actor.ID, admin.User.ID)

			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND enabled = 0 AND activation_generation = ?`, companyOIDCTestGeneration+1); got != 1 {
				t.Fatal("authority loss did not disable company login and advance the activation generation")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_link_transactions`); got != 0 {
				t.Fatal("authority loss left pending link transactions behind")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_login_transactions`); got != 0 {
				t.Fatal("authority loss left pending login transactions behind")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, oidcSession.ID); got != 0 {
				t.Fatal("authority loss left the company OIDC session alive")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_identities WHERE user_id = ?`, admin.User.ID); got != 1 {
				t.Fatal("authority loss removed the linked identity")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_connection.disabled' AND actor_user_id = ? AND details_json = ?`, actor.ID, `{"revision":3,"cause":"authority-loss"}`); got != 1 {
				t.Fatal("authority loss did not record the attributed disable audit event")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_identity.unlinked'`); got != 0 {
				t.Fatal("authority loss recorded an unlink audit event for a retained identity")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, actorSession.ID); got != 1 {
				t.Fatal("authority loss revoked the acting Administrator's session")
			}
		})
	}
}

func TestAuthorityLossOnDisabledConnectionAdvancesGenerationWithoutAudit(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := mustCreateUser(t, ctx, service, "actor@example.test", true)
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
	if _, err := database.ExecContext(ctx, `UPDATE company_oidc_connections SET enabled = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}

	if _, err := service.DisableUser(ctx, actor.ID, admin.User.ID); err != nil {
		t.Fatal(err)
	}

	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND enabled = 0 AND activation_generation = ?`, companyOIDCTestGeneration+1); got != 1 {
		t.Fatal("authority loss on a disabled connection did not advance the activation generation")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_connection.disabled'`); got != 0 {
		t.Fatal("authority loss recorded a disable audit event for an already disabled connection")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_identities WHERE user_id = ?`, admin.User.ID); got != 1 {
		t.Fatal("authority loss removed the linked identity")
	}
}

func TestAuthorityMutationsOfUnlinkedUserLeaveOIDCStateUntouched(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, ctx context.Context, service *Service, actorID, targetID int64)
	}{
		{
			name: "admin demotion",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, targetID int64) {
				if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actorID, UserID: targetID, Admin: false}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "account disable",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, targetID int64) {
				if _, err := service.DisableUser(ctx, actorID, targetID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "forced password reset",
			mutate: func(t *testing.T, ctx context.Context, service *Service, actorID, targetID int64) {
				if err := service.ResetPassword(ctx, ResetPasswordParams{
					ActorUserID:       actorID,
					UserID:            targetID,
					TemporaryPassword: "a temporary reset passphrase",
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
				Email:       "admin@example.test",
				DisplayName: "Admin",
				Password:    accountTestPassword,
			})
			if err != nil {
				t.Fatal(err)
			}
			target := mustCreateUser(t, ctx, service, "target@example.test", true)
			insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
			oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
			if err != nil {
				t.Fatal(err)
			}

			tc.mutate(t, ctx, service, admin.User.ID, target.ID)

			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND enabled = 1 AND activation_generation = ?`, companyOIDCTestGeneration); got != 1 {
				t.Fatal("mutation of an unlinked user changed company login state")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_identities`); got != 1 {
				t.Fatal("mutation of an unlinked user removed the linked identity")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, oidcSession.ID); got != 1 {
				t.Fatal("mutation of an unlinked user revoked the company OIDC session")
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_connection.disabled'`); got != 0 {
				t.Fatal("mutation of an unlinked user recorded an OIDC disable audit event")
			}
		})
	}
}

func TestRejectedDemotionRollsBackCompanyOIDCShutdown(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := mustCreateUser(t, ctx, service, "actor@example.test", true)
	// A credential-less Admin keeps full authority but does not satisfy the
	// recovery invariant, so demoting the linked Administrator must fail.
	if _, err := database.ExecContext(ctx, `DELETE FROM local_credentials WHERE user_id = ?`, actor.ID); err != nil {
		t.Fatal(err)
	}
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
	oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actor.ID, UserID: admin.User.ID, Admin: false}); !IsValidationError(err) {
		t.Fatalf("SetUserAdmin error = %v, want validation error", err)
	}

	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_connections WHERE id = 1 AND enabled = 1 AND activation_generation = ?`, companyOIDCTestGeneration); got != 1 {
		t.Fatal("rejected demotion changed company login state")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, oidcSession.ID); got != 1 {
		t.Fatal("rejected demotion revoked the company OIDC session")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM user_roles WHERE user_id = ? AND role = 'admin'`, admin.User.ID); got != 1 {
		t.Fatal("rejected demotion removed the admin role")
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM audit_events WHERE action = 'oidc_connection.disabled'`); got != 0 {
		t.Fatal("rejected demotion recorded an OIDC disable audit event")
	}
}

func TestStaleLoginCallbackAfterAuthorityLossIsRejected(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := mustCreateUser(t, ctx, service, "actor@example.test", true)
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)

	if _, err := service.SetUserAdmin(ctx, SetUserAdminParams{ActorUserID: actor.ID, UserID: admin.User.ID, Admin: false}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID)); !IsAuthenticationError(err) {
		t.Fatalf("stale callback error = %v, want authentication error", err)
	}
	if got := countRows(t, ctx, database, `SELECT count(*) FROM company_oidc_sessions`); got != 0 {
		t.Fatal("stale callback created a company OIDC session after authority loss")
	}
}

func TestSessionByIDRejectsCompanyOIDCSessionOnAuthorityDrift(t *testing.T) {
	cases := []struct {
		name  string
		drift func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64)
	}{
		{
			name: "admin role removed",
			drift: func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64) {
				if _, err := database.ExecContext(ctx, `DELETE FROM user_roles WHERE user_id = ?`, adminID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "user disabled",
			drift: func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64) {
				if _, err := database.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, companyOIDCTestTimestamp, adminID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "forced password change",
			drift: func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64) {
				if _, err := database.ExecContext(ctx, `UPDATE local_credentials SET must_change_password = 1 WHERE user_id = ?`, adminID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "local credential removed",
			drift: func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64) {
				if _, err := database.ExecContext(ctx, `DELETE FROM local_credentials WHERE user_id = ?`, adminID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "identity removed",
			drift: func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64) {
				if _, err := database.ExecContext(ctx, `DELETE FROM company_oidc_identities`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "connection disabled",
			drift: func(t *testing.T, ctx context.Context, database *sql.DB, adminID int64) {
				if _, err := database.ExecContext(ctx, `UPDATE company_oidc_connections SET enabled = 0 WHERE id = 1`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database := newAuthTestDB(t, ctx)
			service := NewService(database)
			admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
				Email:       "admin@example.test",
				DisplayName: "Admin",
				Password:    accountTestPassword,
			})
			if err != nil {
				t.Fatal(err)
			}
			insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
			oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
			if err != nil {
				t.Fatal(err)
			}

			tc.drift(t, ctx, database, admin.User.ID)

			if _, found, err := service.SessionByID(ctx, oidcSession.ID); err != nil || found {
				t.Fatalf("drifted company OIDC session lookup: found=%v err=%v, want rejection", found, err)
			}
			if got := countRows(t, ctx, database, `SELECT count(*) FROM sessions WHERE id = ?`, oidcSession.ID); got != 0 {
				t.Fatal("rejected company OIDC session row was not revoked")
			}
		})
	}
}

func TestSessionByIDKeepsIntactCompanyOIDCAndLocalSessions(t *testing.T) {
	ctx := context.Background()
	database := newAuthTestDB(t, ctx)
	service := NewService(database)
	admin, err := service.CreateFirstAdmin(ctx, CreateFirstAdminParams{
		Email:       "admin@example.test",
		DisplayName: "Admin",
		Password:    accountTestPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	insertEnabledCompanyOIDCConnection(t, ctx, database, admin.User.ID)
	oidcSession, err := service.CreateCompanyOIDCSession(ctx, validCompanyOIDCSessionParams(admin.User.ID))
	if err != nil {
		t.Fatal(err)
	}

	if _, found, err := service.SessionByID(ctx, oidcSession.ID); err != nil || !found {
		t.Fatalf("intact company OIDC session lookup: found=%v err=%v", found, err)
	}

	// A local password session must survive connection disable; only company
	// OIDC provenance is tied to connection state.
	if _, err := database.ExecContext(ctx, `UPDATE company_oidc_connections SET enabled = 0 WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, found, err := service.SessionByID(ctx, admin.ID); err != nil || !found {
		t.Fatalf("local session lookup after connection disable: found=%v err=%v", found, err)
	}
}
