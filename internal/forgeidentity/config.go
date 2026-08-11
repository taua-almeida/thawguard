package forgeidentity

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

// connectionSnapshot is the minimal Forge connection state this package
// reads. It never carries the service PAT ciphertext.
type connectionSnapshot struct {
	ID       int64
	Revision int64
	BaseURL  string
}

// oauthClientRecord is the internal load model, secret ciphertext included.
// It never leaves this package.
type oauthClientRecord struct {
	ConnectionID           int64
	Enabled                bool
	ClientID               string
	ClientSecretCiphertext []byte
	BoundBaseURL           string
	Revision               int64
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func loadConnectionSnapshot(ctx context.Context, q queryer) (connectionSnapshot, bool, error) {
	var snapshot connectionSnapshot
	err := q.QueryRowContext(ctx, `
SELECT id, config_revision, base_url
FROM forge_connections
WHERE provider = 'forgejo'`).Scan(&snapshot.ID, &snapshot.Revision, &snapshot.BaseURL)
	if errors.Is(err, sql.ErrNoRows) {
		return connectionSnapshot{}, false, nil
	}
	if err != nil {
		return connectionSnapshot{}, false, fmt.Errorf("read forge connection for identity linking: %w", err)
	}
	if snapshot.ID <= 0 || snapshot.Revision <= 0 || !validBoundBaseURL(snapshot.BaseURL) {
		return connectionSnapshot{}, false, errors.New("forge connection data is malformed")
	}
	return snapshot, true, nil
}

func loadOAuthClientRecord(ctx context.Context, q queryer, connectionID int64) (oauthClientRecord, bool, error) {
	var record oauthClientRecord
	var enabled int64
	var clientID, boundBaseURL sql.NullString
	var ciphertext []byte
	err := q.QueryRowContext(ctx, `
SELECT connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision
FROM forgejo_identity_oauth_clients
WHERE connection_id = ?`, connectionID).Scan(
		&record.ConnectionID,
		&enabled,
		&clientID,
		&ciphertext,
		&boundBaseURL,
		&record.Revision,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return oauthClientRecord{}, false, nil
	}
	if err != nil {
		return oauthClientRecord{}, false, fmt.Errorf("read forgejo OAuth client: %w", err)
	}
	record.Enabled = enabled == 1
	if clientID.Valid {
		record.ClientID = clientID.String
	}
	if boundBaseURL.Valid {
		record.BoundBaseURL = boundBaseURL.String
	}
	record.ClientSecretCiphertext = ciphertext
	malformed := record.Revision <= 0 ||
		record.Enabled != (record.ClientID != "") ||
		record.Enabled != (len(record.ClientSecretCiphertext) > 0) ||
		record.Enabled != (record.BoundBaseURL != "")
	if !malformed && record.Enabled {
		malformed = validateClientID(record.ClientID) != nil ||
			len(record.ClientSecretCiphertext) > maxCiphertextBytes ||
			!validBoundBaseURL(record.BoundBaseURL)
	}
	if malformed {
		return oauthClientRecord{}, false, errors.New("forgejo OAuth client data is malformed")
	}
	return record, true, nil
}

func (record oauthClientRecord) public() OAuthClient {
	return OAuthClient{
		ConnectionID: record.ConnectionID,
		Enabled:      record.Enabled,
		ClientID:     record.ClientID,
		BoundBaseURL: record.BoundBaseURL,
		Revision:     record.Revision,
	}
}

// OAuthClient returns the saved OAuth client configuration for the single
// Forgejo connection. Found is false when either the connection or the
// configuration row is absent (unconfigured revision 0).
func (s *Service) OAuthClient(ctx context.Context) (OAuthClient, bool, error) {
	if s == nil || s.db == nil {
		return OAuthClient{}, false, errors.New("forge identity service has no database")
	}
	connection, found, err := loadConnectionSnapshot(ctx, s.db)
	if err != nil || !found {
		return OAuthClient{}, false, err
	}
	record, found, err := loadOAuthClientRecord(ctx, s.db, connection.ID)
	if err != nil || !found {
		return OAuthClient{}, false, err
	}
	return record.public(), true, nil
}

// SaveOAuthClient inserts or replaces the OAuth client configuration with
// fresh credentials and enables it. Every save deletes every link ceremony
// for the connection: no transaction started under an older configuration
// may complete under the new one.
func (s *Service) SaveOAuthClient(ctx context.Context, actorUserID int64, input SaveOAuthClientInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge identity service has no database")
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedConnectionRevision <= 0 || input.ExpectedOAuthRevision < 0 {
		return ValidationError{Message: "the expected connection id and revisions must identify the configuration being saved"}
	}
	if err := validateClientID(input.ClientID); err != nil {
		return err
	}
	if err := validateClientSecret(input.ClientSecret); err != nil {
		return err
	}
	if s.secrets == nil {
		return ErrConfiguration
	}
	ciphertext, err := encryptOAuthClientSecret(ctx, s.secrets, input.ClientSecret)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forgejo OAuth client save: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	connection, found, err := loadConnectionSnapshot(ctx, tx)
	if err != nil {
		return err
	}
	if !found || connection.ID != input.ExpectedConnectionID || connection.Revision != input.ExpectedConnectionRevision {
		return ErrConflict
	}
	existing, configured, err := loadOAuthClientRecord(ctx, tx, connection.ID)
	if err != nil {
		return err
	}
	currentRevision := int64(0)
	if configured {
		currentRevision = existing.Revision
	}
	if currentRevision != input.ExpectedOAuthRevision {
		return ErrConflict
	}
	if currentRevision == math.MaxInt64 {
		return errors.New("forgejo OAuth client revision is exhausted")
	}
	newRevision := currentRevision + 1

	if configured {
		updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forgejo_identity_oauth_clients
SET enabled = 1, client_id = ?, client_secret_ciphertext = ?, bound_base_url = ?, oauth_revision = ?
WHERE connection_id = ? AND oauth_revision = ?`,
			input.ClientID,
			ciphertext,
			connection.BaseURL,
			newRevision,
			connection.ID,
			currentRevision,
		)
		if err != nil {
			return fmt.Errorf("update forgejo OAuth client: %w", err)
		}
		if !updated {
			return ErrConflict
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO forgejo_identity_oauth_clients(
  connection_id, enabled, client_id, client_secret_ciphertext, bound_base_url, oauth_revision
)
VALUES (?, 1, ?, ?, ?, ?)`,
			connection.ID,
			input.ClientID,
			ciphertext,
			connection.BaseURL,
			newRevision,
		); err != nil {
			return fmt.Errorf("insert forgejo OAuth client: %w", err)
		}
	}
	if err := deleteConnectionLinkTransactions(ctx, tx, connection.ID); err != nil {
		return err
	}
	if err := recordOAuthClientEvent(ctx, tx, actorUserID, audit.ActionForgeOAuthClientUpdated, connection.ID, newRevision); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

// DisableOAuthClient destroys the stored credentials and disables linking.
// The revision advances so every outstanding form and ceremony is fenced
// out; at the maximum revision the disable is terminal at the same
// revision — the counter never wraps and the client can never be re-enabled.
func (s *Service) DisableOAuthClient(ctx context.Context, actorUserID int64, input DisableOAuthClientInput) error {
	if s == nil || s.db == nil {
		return errors.New("forge identity service has no database")
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedConnectionRevision <= 0 || input.ExpectedOAuthRevision <= 0 {
		return ValidationError{Message: "the expected connection id and revisions must identify the configuration being disabled"}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin forgejo OAuth client disable: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	connection, found, err := loadConnectionSnapshot(ctx, tx)
	if err != nil {
		return err
	}
	if !found || connection.ID != input.ExpectedConnectionID || connection.Revision != input.ExpectedConnectionRevision {
		return ErrConflict
	}
	existing, configured, err := loadOAuthClientRecord(ctx, tx, connection.ID)
	if err != nil {
		return err
	}
	if !configured || existing.Revision != input.ExpectedOAuthRevision || !existing.Enabled {
		return ErrConflict
	}
	newRevision := existing.Revision + 1
	if existing.Revision == math.MaxInt64 {
		newRevision = existing.Revision
	}
	updated, err := execExpectingOneRow(ctx, tx, `
UPDATE forgejo_identity_oauth_clients
SET enabled = 0, client_id = NULL, client_secret_ciphertext = NULL, bound_base_url = NULL, oauth_revision = ?
WHERE connection_id = ? AND oauth_revision = ?`,
		newRevision,
		connection.ID,
		existing.Revision,
	)
	if err != nil {
		return fmt.Errorf("disable forgejo OAuth client: %w", err)
	}
	if !updated {
		return ErrConflict
	}
	if err := deleteConnectionLinkTransactions(ctx, tx, connection.ID); err != nil {
		return err
	}
	if err := recordOAuthClientEvent(ctx, tx, actorUserID, audit.ActionForgeOAuthClientDisabled, connection.ID, newRevision); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

func encryptOAuthClientSecret(ctx context.Context, store secrets.Store, secret string) ([]byte, error) {
	envelope := wrapEnvelope(oauthClientSecretEnvelopeHeader, secret)
	ciphertext, err := store.Encrypt(ctx, envelope)
	clearBytes(envelope)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxCiphertextBytes {
		return nil, errors.New("encrypt forgejo OAuth client secret")
	}
	return ciphertext, nil
}

func deleteConnectionLinkTransactions(ctx context.Context, tx *sql.Tx, connectionID int64) error {
	if _, err := tx.ExecContext(
		ctx,
		`DELETE FROM forgejo_identity_link_transactions WHERE connection_id = ?`,
		connectionID,
	); err != nil {
		return fmt.Errorf("delete forgejo link transactions: %w", err)
	}
	return nil
}

// recordOAuthClientEvent writes the sanitized audit event for one OAuth
// client change. Details carry only the new revision — never a client id,
// secret, or URL.
func recordOAuthClientEvent(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	action string,
	connectionID int64,
	revision int64,
) error {
	details, err := json.Marshal(struct {
		OAuthRevision int64 `json:"oauth_revision"`
	}{OAuthRevision: revision})
	if err != nil {
		return errors.New("encode forgejo OAuth client audit evidence")
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      action,
		SubjectType: audit.SubjectTypeForgeConnection,
		SubjectID:   strconv.FormatInt(connectionID, 10),
		DetailsJSON: string(details),
	}); err != nil {
		return fmt.Errorf("record forgejo OAuth client audit event: %w", err)
	}
	return nil
}
