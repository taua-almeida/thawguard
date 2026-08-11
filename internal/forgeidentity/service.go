package forgeidentity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/taua-almeida/thawguard/internal/secrets"
)

type Service struct {
	db        *sql.DB
	secrets   secrets.Store
	client    *http.Client
	publicURL string
	now       func() time.Time
	random    io.Reader
}

// NewService wires the Forgejo identity service. transport carries provider
// requests; redirects are never followed, so a redirecting provider fails
// the strict 200-only response checks instead of moving the credential.
func NewService(db *sql.DB, secretStore secrets.Store, transport http.RoundTripper, publicURL string) *Service {
	return &Service{
		db:      db,
		secrets: secretStore,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		publicURL: publicURL,
		now:       func() time.Time { return time.Now().UTC() },
		random:    rand.Reader,
	}
}

// redirectURI is the exact string displayed, stored, authorized, and sent
// to the token endpoint.
func (s *Service) redirectURI() string {
	return s.publicURL + CallbackPath
}

func linkDigest(purpose, value string) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write([]byte(purpose))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(value))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

// randomLinkToken returns a canonical 43-character base64url encoding of 32
// random bytes, used for the state and the browser binding token.
func randomLinkToken(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("forge identity random source is unavailable")
	}
	value := make([]byte, 32)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// randomPKCEVerifier returns a 64-character RFC 7636 code verifier: the
// base64url encoding of 48 random bytes uses only unreserved characters.
func randomPKCEVerifier(random io.Reader) (string, error) {
	if random == nil {
		return "", errors.New("forge identity random source is unavailable")
	}
	value := make([]byte, 48)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// canonicalLinkToken reports whether value is exactly the canonical
// 43-character base64url encoding of 32 bytes.
func canonicalLinkToken(value string) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func pkceS256Challenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// lockEnabledCredentialedActor takes the writer on the actor's user row
// first, then rechecks inside the transaction that the actor is an enabled
// user holding a local credential without a forced change. Roles are not
// required: linking is identity-only.
func lockEnabledCredentialedActor(ctx context.Context, tx *sql.Tx, actorUserID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, actorUserID); err != nil {
		return fmt.Errorf("lock forge identity actor: %w", err)
	}
	var allowed int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN local_credentials lc ON lc.user_id = u.id
  WHERE u.id = ? AND u.disabled_at IS NULL AND lc.must_change_password = 0
)`, actorUserID).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize forge identity actor: %w", err)
	}
	if allowed != 1 {
		return ErrAuthorization
	}
	return nil
}

// lockEnabledAdminActor is the Administrator variant used by OAuth client
// administration and purge.
func lockEnabledAdminActor(ctx context.Context, tx *sql.Tx, actorUserID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, actorUserID); err != nil {
		return fmt.Errorf("lock forge identity admin actor: %w", err)
	}
	var allowed int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
  WHERE u.id = ? AND u.disabled_at IS NULL
)`, actorUserID).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize forge identity admin actor: %w", err)
	}
	if allowed != 1 {
		return ErrAdminOnly
	}
	return nil
}

// currentCredentialedSession requires a live persistent session for the
// actor whose account holds a local credential without a forced change.
func currentCredentialedSession(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	sessionID string,
	now time.Time,
) (bool, error) {
	var userID int64
	var hasCSRF int
	var expiresAt string
	var mustChangePassword int64
	err := tx.QueryRowContext(ctx, `
SELECT s.user_id, s.csrf_token != '', s.expires_at, lc.must_change_password
FROM sessions s
JOIN local_credentials lc ON lc.user_id = s.user_id
WHERE s.id = ?`, sessionID).Scan(&userID, &hasCSRF, &expiresAt, &mustChangePassword)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	parsedExpiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return false, nil
	}
	return userID == actorUserID && hasCSRF == 1 && now.Before(parsedExpiry.UTC()) &&
		mustChangePassword == 0, nil
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
