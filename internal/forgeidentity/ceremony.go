package forgeidentity

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/taua-almeida/thawguard/internal/audit"
)

const (
	maxCallbackRawQueryBytes = 8 << 10
	maxCallbackCodeBytes     = 4096
	maxCallbackErrorBytes    = 256
)

// linkTransactionRecord is the internal load model of one ceremony row.
type linkTransactionRecord struct {
	connectionID       int64
	userID             int64
	status             string
	sessionDigest      [sha256.Size]byte
	browserDigest      [sha256.Size]byte
	pkceCiphertext     []byte
	redirectURI        string
	boundBaseURL       string
	connectionRevision int64
	oauthRevision      int64
	createdAt          time.Time
	expiresAt          time.Time
}

// linkClaim carries one claimed ceremony from the claim transaction to the
// provider exchange and the completion transaction. Ciphertexts stay
// encrypted until the exchange needs them.
type linkClaim struct {
	stateDigest            [sha256.Size]byte
	connectionID           int64
	userID                 int64
	sessionID              string
	sessionDigest          [sha256.Size]byte
	browserDigest          [sha256.Size]byte
	clientID               string
	clientSecretCiphertext []byte
	pkceCiphertext         []byte
	redirectURI            string
	boundBaseURL           string
	connectionRevision     int64
	oauthRevision          int64
}

// StartLink begins the link ceremony for the acting user. The caller has
// already verified the current password; this acquires the SQLite writer
// first, reauthorizes the session, user, and configuration inside that
// transaction, deletes only expired ceremony state, and rejects an existing
// live row before any cookie can be set.
func (s *Service) StartLink(ctx context.Context, input StartLinkInput) (LinkStart, error) {
	if s == nil || s.db == nil {
		return LinkStart{}, ErrUnavailable
	}
	if input.ActorUserID <= 0 || !validSessionID(input.SessionID) {
		return LinkStart{}, ErrAuthorization
	}
	if input.ExpectedConnectionID <= 0 || input.ExpectedOAuthRevision <= 0 {
		return LinkStart{}, ErrUnavailable
	}
	if s.secrets == nil {
		return LinkStart{}, ErrConfiguration
	}
	redirectURI := s.redirectURI()
	if !validBoundBaseURL(s.publicURL) || len(redirectURI) > 2048 {
		return LinkStart{}, ErrUnavailable
	}

	state, err := randomLinkToken(s.random)
	if err != nil {
		return LinkStart{}, errors.New("prepare forge identity link state")
	}
	browserToken, err := randomLinkToken(s.random)
	if err != nil {
		return LinkStart{}, errors.New("prepare forge identity browser token")
	}
	verifier, err := randomPKCEVerifier(s.random)
	if err != nil {
		return LinkStart{}, errors.New("prepare forge identity PKCE verifier")
	}
	challenge := pkceS256Challenge(verifier)
	verifierCiphertext, err := encryptPKCEVerifier(ctx, s, verifier)
	if err != nil {
		return LinkStart{}, err
	}

	stateDigest := linkDigest(linkStateDigestPurpose, state)
	sessionDigest := linkDigest(linkSessionDigestPurpose, input.SessionID)
	browserDigest := linkDigest(linkBrowserDigestPurpose, browserToken)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LinkStart{}, errors.New("begin forge identity link start")
	}
	defer tx.Rollback()

	// The actor lock's UPDATE takes writer ownership before any read below.
	if err := lockEnabledCredentialedActor(ctx, tx, input.ActorUserID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return LinkStart{}, ErrAuthorization
		}
		return LinkStart{}, errors.New("authorize forge identity link start")
	}
	now := s.now().UTC()
	authorized, err := currentCredentialedSession(ctx, tx, input.ActorUserID, input.SessionID, now)
	if err != nil {
		return LinkStart{}, errors.New("authorize forge identity link session")
	}
	if !authorized {
		return LinkStart{}, ErrAuthorization
	}
	connection, oauth, err := currentLinkConfiguration(ctx, tx)
	if err != nil {
		return LinkStart{}, err
	}
	if connection.ID != input.ExpectedConnectionID || oauth.Revision != input.ExpectedOAuthRevision {
		return LinkStart{}, ErrUnavailable
	}
	var linked int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM forgejo_identities WHERE connection_id = ? AND user_id = ?)`,
		connection.ID, input.ActorUserID).Scan(&linked); err != nil {
		return LinkStart{}, errors.New("check existing forge identity")
	}
	if linked == 1 {
		return LinkStart{}, ErrUnavailable
	}
	if err := cleanupExpiredLinkTransactions(ctx, tx, now); err != nil {
		return LinkStart{}, errors.New("clean expired forge identity link transactions")
	}
	// The bounded batch above may miss the actor's own expired row behind a
	// large backlog; delete it explicitly so only a genuinely live row can
	// reject the restart below.
	if _, err := tx.ExecContext(ctx, `
DELETE FROM forgejo_identity_link_transactions
WHERE connection_id = ? AND user_id = ? AND expires_at <= ?`,
		connection.ID, input.ActorUserID, formatForgeIdentityTime(now)); err != nil {
		return LinkStart{}, errors.New("clean the actor's expired forge identity link transaction")
	}
	var live int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM forgejo_identity_link_transactions WHERE connection_id = ? AND user_id = ?)`,
		connection.ID, input.ActorUserID).Scan(&live); err != nil {
		return LinkStart{}, errors.New("check live forge identity link transaction")
	}
	if live == 1 {
		return LinkStart{}, ErrLinkInProgress
	}

	authorizationURL, err := buildAuthorizationURL(oauth.BoundBaseURL, oauth.ClientID, redirectURI, state, challenge)
	if err != nil {
		return LinkStart{}, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO forgejo_identity_link_transactions(
  state_digest, connection_id, user_id, status,
  session_binding_digest, browser_binding_digest, pkce_verifier_ciphertext,
  redirect_uri, bound_base_url, connection_revision, oauth_revision,
  created_at, expires_at
)
VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		stateDigest[:],
		connection.ID,
		input.ActorUserID,
		sessionDigest[:],
		browserDigest[:],
		verifierCiphertext,
		redirectURI,
		oauth.BoundBaseURL,
		connection.Revision,
		oauth.Revision,
		formatForgeIdentityTime(now),
		formatForgeIdentityTime(now.Add(linkTransactionTTL)),
	); err != nil {
		return LinkStart{}, errors.New("store forge identity link transaction")
	}
	if err := tx.Commit(); err != nil {
		return LinkStart{}, ErrOutcomeUnknown
	}
	return LinkStart{
		AuthorizationURL: authorizationURL,
		BrowserToken:     browserToken,
		Handle:           StartHandle{stateDigest: stateDigest[:]},
	}, nil
}

// CancelStart removes exactly the pending row a failed same-request render
// left behind. It is best-effort: a row it cannot remove expires inertly.
func (s *Service) CancelStart(ctx context.Context, handle StartHandle) error {
	if s == nil || s.db == nil || len(handle.stateDigest) != sha256.Size {
		return nil
	}
	if _, err := s.db.ExecContext(
		ctx,
		`DELETE FROM forgejo_identity_link_transactions WHERE state_digest = ? AND status = 'pending'`,
		handle.stateDigest,
	); err != nil {
		return fmt.Errorf("cancel forge identity link start: %w", err)
	}
	return nil
}

// currentLinkConfiguration loads the connection and its enabled OAuth
// client inside the caller's transaction and rechecks that the stored
// bound base URL still exactly matches the connection.
func currentLinkConfiguration(ctx context.Context, tx *sql.Tx) (connectionSnapshot, oauthClientRecord, error) {
	connection, found, err := loadConnectionSnapshot(ctx, tx)
	if err != nil {
		return connectionSnapshot{}, oauthClientRecord{}, err
	}
	if !found {
		return connectionSnapshot{}, oauthClientRecord{}, ErrUnavailable
	}
	oauth, configured, err := loadOAuthClientRecord(ctx, tx, connection.ID)
	if err != nil {
		return connectionSnapshot{}, oauthClientRecord{}, err
	}
	if !configured || !oauth.Enabled || oauth.BoundBaseURL != connection.BaseURL {
		return connectionSnapshot{}, oauthClientRecord{}, ErrUnavailable
	}
	return connection, oauth, nil
}

// buildAuthorizationURL assembles the exact generated authorization request.
func buildAuthorizationURL(baseURL, clientID, redirectURI, state, challenge string) (string, error) {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", clientID)
	values.Set("redirect_uri", redirectURI)
	values.Set("scope", "read:user")
	values.Set("state", state)
	values.Set("code_challenge", challenge)
	values.Set("code_challenge_method", "S256")
	authorizationURL := baseURL + "/login/oauth/authorize?" + values.Encode()
	if len(authorizationURL) > maxAuthorizeURLBytes {
		return "", errors.New("forge identity authorization URL exceeds the generated maximum")
	}
	return authorizationURL, nil
}

func encryptPKCEVerifier(ctx context.Context, s *Service, verifier string) ([]byte, error) {
	envelope := wrapEnvelope(pkceVerifierEnvelopeHeader, verifier)
	ciphertext, err := s.secrets.Encrypt(ctx, envelope)
	clearBytes(envelope)
	if err != nil || len(ciphertext) == 0 || len(ciphertext) > maxCiphertextBytes {
		return nil, errors.New("encrypt forge identity PKCE verifier")
	}
	return ciphertext, nil
}

// callbackResponse is the strictly parsed authorization response: exactly
// one canonical state and exactly one of code or providerError.
type callbackResponse struct {
	state         string
	code          string
	providerError string
}

// parseCallbackQuery enforces the callback boundary on the raw query:
// bounded size, exactly one 43-character canonical state, exactly one of a
// bounded code or bounded error, rejection of duplicate or ASCII-case-fold
// aliases of the known keys, and silent dismissal of bounded ancillary or
// unknown data. Provider text is never surfaced.
func parseCallbackQuery(rawQuery string) (callbackResponse, bool) {
	if len(rawQuery) > maxCallbackRawQueryBytes {
		return callbackResponse{}, false
	}
	known := []string{"state", "code", "error"}
	values := map[string][]string{}
	for field := range strings.SplitSeq(rawQuery, "&") {
		rawKey, rawValue, _ := strings.Cut(field, "=")
		key, err := url.QueryUnescape(rawKey)
		if err != nil {
			continue
		}
		matched := ""
		for _, name := range known {
			if key == name {
				matched = name
				break
			}
			if strings.EqualFold(key, name) {
				return callbackResponse{}, false
			}
		}
		if matched == "" {
			continue
		}
		value, err := url.QueryUnescape(rawValue)
		if err != nil || !utf8.ValidString(value) {
			return callbackResponse{}, false
		}
		values[matched] = append(values[matched], value)
	}
	if len(values["state"]) != 1 || !canonicalLinkToken(values["state"][0]) {
		return callbackResponse{}, false
	}
	if len(values["code"]) > 1 || len(values["error"]) > 1 {
		return callbackResponse{}, false
	}
	hasCode := len(values["code"]) == 1 && validCallbackValue(values["code"][0], maxCallbackCodeBytes)
	hasError := len(values["error"]) == 1 && validCallbackValue(values["error"][0], maxCallbackErrorBytes)
	if hasCode == hasError || len(values["code"])+len(values["error"]) != 1 {
		return callbackResponse{}, false
	}
	response := callbackResponse{state: values["state"][0]}
	if hasCode {
		response.code = values["code"][0]
	} else {
		response.providerError = values["error"][0]
	}
	return response, true
}

func validCallbackValue(value string, maxBytes int) bool {
	if len(value) < 1 || len(value) > maxBytes {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == 0x2028 || character == 0x2029 {
			return false
		}
	}
	return true
}

// CompleteLinkCallback consumes one callback end to end: strict parse,
// claim (CAS pending to claimed, committed before any provider I/O),
// provider exchange, and the atomic completion transaction. Sanitized
// results carry no provider text.
func (s *Service) CompleteLinkCallback(ctx context.Context, input CallbackInput) (LinkResultCode, error) {
	if s == nil || s.db == nil {
		return LinkStale, nil
	}
	response, valid := parseCallbackQuery(input.RawQuery)
	if !valid {
		return LinkStale, nil
	}
	claim, result, err := s.claimLink(ctx, response.state, input.SessionID, input.BrowserToken)
	if err != nil {
		return "", err
	}
	if result != "" {
		return result, nil
	}

	if response.providerError != "" {
		s.cleanupClaimedRow(ctx, claim.stateDigest)
		return providerAuthorizationErrorResult(response.providerError), nil
	}
	remoteUser, exchangeResult := s.exchangeAndReadUser(ctx, claim, response.code)
	if exchangeResult != LinkLinked {
		s.cleanupClaimedRow(ctx, claim.stateDigest)
		return exchangeResult, nil
	}
	return s.completeLink(ctx, claim, remoteUser)
}

func providerAuthorizationErrorResult(providerError string) LinkResultCode {
	switch providerError {
	case "access_denied", "interaction_required", "login_required", "account_selection_required", "consent_required":
		return LinkProviderDenied
	case "server_error", "temporarily_unavailable":
		return LinkProviderUnavailable
	default:
		return LinkProviderInvalid
	}
}

// claimLink verifies every binding and fence inside one writer transaction
// and moves the row from pending to claimed. A returned non-empty result
// short-circuits the callback; a returned claim proceeds to provider I/O.
func (s *Service) claimLink(
	ctx context.Context,
	state string,
	sessionID string,
	browserToken string,
) (linkClaim, LinkResultCode, error) {
	stateDigest := linkDigest(linkStateDigestPurpose, state)
	bindingsPresent := validSessionID(sessionID) && canonicalLinkToken(browserToken)
	var sessionDigest, browserDigest [sha256.Size]byte
	if bindingsPresent {
		sessionDigest = linkDigest(linkSessionDigestPurpose, sessionID)
		browserDigest = linkDigest(linkBrowserDigestPurpose, browserToken)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return linkClaim{}, LinkStale, nil
	}
	defer tx.Rollback()
	// Take writer ownership on the ceremony row before any read.
	if _, err := tx.ExecContext(
		ctx,
		`UPDATE forgejo_identity_link_transactions SET state_digest = state_digest WHERE state_digest = ?`,
		stateDigest[:],
	); err != nil {
		return linkClaim{}, LinkStale, nil
	}
	now := s.now().UTC()
	if err := cleanupExpiredLinkTransactions(ctx, tx, now); err != nil {
		return linkClaim{}, LinkStale, nil
	}
	record, found, err := loadLinkTransaction(ctx, tx, stateDigest)
	if err != nil {
		if found {
			return s.consumeLinkTransaction(ctx, tx, stateDigest)
		}
		return linkClaim{}, LinkStale, nil
	}
	if !found {
		if err := tx.Commit(); err != nil {
			return linkClaim{}, "", ErrOutcomeUnknown
		}
		return linkClaim{}, LinkStale, nil
	}
	if record.status != "pending" {
		// Another callback holds the claim; leave its row alone.
		if err := tx.Commit(); err != nil {
			return linkClaim{}, "", ErrOutcomeUnknown
		}
		return linkClaim{}, LinkStale, nil
	}
	sessionMatches := subtle.ConstantTimeCompare(sessionDigest[:], record.sessionDigest[:]) == 1
	browserMatches := subtle.ConstantTimeCompare(browserDigest[:], record.browserDigest[:]) == 1
	if !bindingsPresent || !now.Before(record.expiresAt) || !sessionMatches || !browserMatches {
		return s.consumeLinkTransaction(ctx, tx, stateDigest)
	}
	if err := lockEnabledCredentialedActor(ctx, tx, record.userID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return s.consumeLinkTransaction(ctx, tx, stateDigest)
		}
		return linkClaim{}, LinkStale, nil
	}
	authorized, err := currentCredentialedSession(ctx, tx, record.userID, sessionID, now)
	if err != nil {
		return linkClaim{}, LinkStale, nil
	}
	if !authorized {
		return s.consumeLinkTransaction(ctx, tx, stateDigest)
	}
	connection, oauth, err := currentLinkConfiguration(ctx, tx)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return s.consumeLinkTransaction(ctx, tx, stateDigest)
		}
		return linkClaim{}, LinkStale, nil
	}
	if connection.ID != record.connectionID ||
		connection.Revision != record.connectionRevision ||
		oauth.Revision != record.oauthRevision ||
		oauth.BoundBaseURL != record.boundBaseURL ||
		record.redirectURI != s.redirectURI() {
		return s.consumeLinkTransaction(ctx, tx, stateDigest)
	}
	claimed, err := execExpectingOneRow(ctx, tx, `
UPDATE forgejo_identity_link_transactions
SET status = 'claimed'
WHERE state_digest = ? AND status = 'pending'`, stateDigest[:])
	if err != nil || !claimed {
		return linkClaim{}, LinkStale, nil
	}
	if err := tx.Commit(); err != nil {
		return linkClaim{}, "", ErrOutcomeUnknown
	}
	return linkClaim{
		stateDigest:            stateDigest,
		connectionID:           record.connectionID,
		userID:                 record.userID,
		sessionID:              sessionID,
		sessionDigest:          record.sessionDigest,
		browserDigest:          record.browserDigest,
		clientID:               oauth.ClientID,
		clientSecretCiphertext: oauth.ClientSecretCiphertext,
		pkceCiphertext:         record.pkceCiphertext,
		redirectURI:            record.redirectURI,
		boundBaseURL:           record.boundBaseURL,
		connectionRevision:     record.connectionRevision,
		oauthRevision:          record.oauthRevision,
	}, "", nil
}

// consumeLinkTransaction deletes a row whose bindings or fences failed and
// commits that deletion, reporting the sanitized stale result.
func (s *Service) consumeLinkTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) (linkClaim, LinkResultCode, error) {
	deleted, err := execExpectingOneRow(
		ctx,
		tx,
		`DELETE FROM forgejo_identity_link_transactions WHERE state_digest = ?`,
		stateDigest[:],
	)
	if err != nil || !deleted {
		return linkClaim{}, LinkStale, nil
	}
	if err := tx.Commit(); err != nil {
		return linkClaim{}, "", ErrOutcomeUnknown
	}
	return linkClaim{}, LinkStale, nil
}

// cleanupClaimedRow removes the claimed row after a terminal provider
// failure. It is bounded best-effort: an ambiguous failure leaves only an
// inert claimed row that expires on its own.
func (s *Service) cleanupClaimedRow(ctx context.Context, stateDigest [sha256.Size]byte) {
	_, _ = s.db.ExecContext(
		ctx,
		`DELETE FROM forgejo_identity_link_transactions WHERE state_digest = ? AND status = 'claimed'`,
		stateDigest[:],
	)
}

// remoteAccount is the verified provider identity used for completion.
type remoteAccount struct {
	remoteUserID string
	username     string
}

// completeLink is the single completion writer transaction: recheck
// everything the claim proved, consume the claimed row, and insert the
// identity atomically with its audit event.
func (s *Service) completeLink(ctx context.Context, claim linkClaim, account remoteAccount) (LinkResultCode, error) {
	if !validRemoteUserID(account.remoteUserID) || !validUsernameAtLink(account.username) {
		s.cleanupClaimedRow(ctx, claim.stateDigest)
		return LinkProviderInvalid, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return LinkStale, nil
	}
	defer tx.Rollback()
	if err := lockEnabledCredentialedActor(ctx, tx, claim.userID); err != nil {
		if errors.Is(err, ErrAuthorization) {
			return s.rejectClaimedRow(ctx, tx, claim, LinkStale, "")
		}
		return LinkStale, nil
	}
	now := s.now().UTC()
	authorized, err := currentCredentialedSession(ctx, tx, claim.userID, claim.sessionID, now)
	if err != nil {
		return LinkStale, nil
	}
	if !authorized {
		return s.rejectClaimedRow(ctx, tx, claim, LinkStale, "")
	}
	record, found, err := loadLinkTransaction(ctx, tx, claim.stateDigest)
	if err != nil || !found {
		return LinkStale, nil
	}
	// Known fence failures consume the exact claimed row: leaving it would
	// report a phantom in-progress ceremony that also blocks a restart
	// until expiry. Only ambiguous database failures leave the inert row.
	sessionMatches := subtle.ConstantTimeCompare(record.sessionDigest[:], claim.sessionDigest[:]) == 1
	browserMatches := subtle.ConstantTimeCompare(record.browserDigest[:], claim.browserDigest[:]) == 1
	if record.status != "claimed" ||
		record.connectionID != claim.connectionID ||
		record.userID != claim.userID ||
		!sessionMatches || !browserMatches ||
		!now.Before(record.expiresAt) ||
		record.redirectURI != s.redirectURI() {
		return s.rejectClaimedRow(ctx, tx, claim, LinkStale, "")
	}
	connection, oauth, err := currentLinkConfiguration(ctx, tx)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return s.rejectClaimedRow(ctx, tx, claim, LinkStale, "")
		}
		return LinkStale, nil
	}
	if connection.ID != claim.connectionID ||
		connection.Revision != claim.connectionRevision ||
		oauth.Revision != claim.oauthRevision ||
		oauth.BoundBaseURL != claim.boundBaseURL {
		return s.rejectClaimedRow(ctx, tx, claim, LinkStale, "")
	}
	var ownIdentity int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM forgejo_identities WHERE connection_id = ? AND user_id = ?)`,
		claim.connectionID, claim.userID).Scan(&ownIdentity); err != nil {
		return LinkStale, nil
	}
	if ownIdentity == 1 {
		return s.rejectClaimedRow(ctx, tx, claim, LinkAlreadyLinked, "")
	}
	var collision int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM forgejo_identities WHERE connection_id = ? AND remote_user_id = ?)`,
		claim.connectionID, account.remoteUserID).Scan(&collision); err != nil {
		return LinkStale, nil
	}
	if collision == 1 {
		return s.rejectClaimedRow(ctx, tx, claim, LinkCollision, audit.ActionForgeIdentityLinkRejected)
	}
	// Linking atomically advances the connection's access-identity revision,
	// which fences shadow-access snapshots against identity churn. A
	// saturated revision blocks the link: unlike unlink and purge, a link
	// may never ride the terminal same-revision reduction.
	advanced, err := advanceAccessIdentityRevision(ctx, tx, claim.connectionID)
	if err != nil {
		return LinkStale, nil
	}
	if !advanced {
		return s.rejectClaimedRow(ctx, tx, claim, LinkConfigurationUnavailable, "")
	}
	deleted, err := execExpectingOneRow(
		ctx,
		tx,
		`DELETE FROM forgejo_identity_link_transactions WHERE state_digest = ? AND status = 'claimed'`,
		claim.stateDigest[:],
	)
	if err != nil || !deleted {
		return LinkStale, nil
	}
	result, err := tx.ExecContext(ctx, `
INSERT INTO forgejo_identities(connection_id, user_id, remote_user_id, username_at_link, linked_at)
VALUES (?, ?, ?, ?, ?)`,
		claim.connectionID,
		claim.userID,
		account.remoteUserID,
		account.username,
		formatForgeIdentityTime(now),
	)
	if err != nil {
		return LinkStale, nil
	}
	identityID, err := result.LastInsertId()
	if err != nil || identityID <= 0 {
		return LinkStale, nil
	}
	if err := recordIdentityEvent(ctx, tx, claim.userID, audit.ActionForgeIdentityLinked, identityID, claim.connectionID); err != nil {
		return LinkStale, nil
	}
	if err := tx.Commit(); err != nil {
		return "", ErrOutcomeUnknown
	}
	return LinkLinked, nil
}

// rejectClaimedRow deletes the exact claimed row inside the caller's
// completion transaction and commits. A non-empty rejectionAction records
// fixed collision evidence that never names the other account.
func (s *Service) rejectClaimedRow(
	ctx context.Context,
	tx *sql.Tx,
	claim linkClaim,
	result LinkResultCode,
	rejectionAction string,
) (LinkResultCode, error) {
	deleted, err := execExpectingOneRow(
		ctx,
		tx,
		`DELETE FROM forgejo_identity_link_transactions WHERE state_digest = ? AND status = 'claimed'`,
		claim.stateDigest[:],
	)
	if err != nil || !deleted {
		return LinkStale, nil
	}
	if rejectionAction != "" {
		details, err := json.Marshal(struct {
			Reason string `json:"reason"`
		}{Reason: "remote_identity_collision"})
		if err != nil {
			return LinkStale, nil
		}
		actor := claim.userID
		if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
			ActorUserID: &actor,
			Action:      rejectionAction,
			SubjectType: audit.SubjectTypeForgeConnection,
			SubjectID:   strconv.FormatInt(claim.connectionID, 10),
			DetailsJSON: string(details),
		}); err != nil {
			return LinkStale, nil
		}
	}
	if err := tx.Commit(); err != nil {
		return "", ErrOutcomeUnknown
	}
	return result, nil
}

func recordIdentityEvent(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	action string,
	identityID int64,
	connectionID int64,
) error {
	details, err := json.Marshal(struct {
		ConnectionID int64 `json:"connection_id"`
	}{ConnectionID: connectionID})
	if err != nil {
		return errors.New("encode forge identity audit evidence")
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      action,
		SubjectType: audit.SubjectTypeForgeIdentity,
		SubjectID:   strconv.FormatInt(identityID, 10),
		DetailsJSON: string(details),
	}); err != nil {
		return fmt.Errorf("record forge identity audit event: %w", err)
	}
	return nil
}

func loadLinkTransaction(
	ctx context.Context,
	tx *sql.Tx,
	stateDigest [sha256.Size]byte,
) (linkTransactionRecord, bool, error) {
	var record linkTransactionRecord
	var sessionDigest, browserDigest []byte
	var createdAt, expiresAt string
	err := tx.QueryRowContext(ctx, `
SELECT connection_id, user_id, status, session_binding_digest, browser_binding_digest,
  pkce_verifier_ciphertext, redirect_uri, bound_base_url,
  connection_revision, oauth_revision, created_at, expires_at
FROM forgejo_identity_link_transactions
WHERE state_digest = ?`, stateDigest[:]).Scan(
		&record.connectionID,
		&record.userID,
		&record.status,
		&sessionDigest,
		&browserDigest,
		&record.pkceCiphertext,
		&record.redirectURI,
		&record.boundBaseURL,
		&record.connectionRevision,
		&record.oauthRevision,
		&createdAt,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return linkTransactionRecord{}, false, nil
	}
	if err != nil {
		return linkTransactionRecord{}, false, err
	}
	malformed := errors.New("forge identity link transaction is malformed")
	if record.connectionID <= 0 || record.userID <= 0 ||
		(record.status != "pending" && record.status != "claimed") ||
		len(sessionDigest) != sha256.Size || len(browserDigest) != sha256.Size ||
		len(record.pkceCiphertext) < 1 || len(record.pkceCiphertext) > maxCiphertextBytes ||
		len(record.redirectURI) < 1 || len(record.redirectURI) > 2048 ||
		!validBoundBaseURL(record.boundBaseURL) ||
		record.connectionRevision <= 0 || record.oauthRevision <= 0 {
		return linkTransactionRecord{}, true, malformed
	}
	copy(record.sessionDigest[:], sessionDigest)
	copy(record.browserDigest[:], browserDigest)
	record.createdAt, err = parseForgeIdentityTime(createdAt)
	if err != nil {
		return linkTransactionRecord{}, true, malformed
	}
	record.expiresAt, err = parseForgeIdentityTime(expiresAt)
	if err != nil || !record.expiresAt.After(record.createdAt) {
		return linkTransactionRecord{}, true, malformed
	}
	return record, true, nil
}

// cleanupExpiredLinkTransactions deletes only expired ceremony rows, in a
// bounded batch so a hostile backlog cannot stall the caller's transaction.
func cleanupExpiredLinkTransactions(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `
DELETE FROM forgejo_identity_link_transactions
WHERE state_digest IN (
  SELECT state_digest
  FROM forgejo_identity_link_transactions
  WHERE expires_at <= ?
  ORDER BY expires_at, state_digest
  LIMIT ?
)`, formatForgeIdentityTime(now), linkCleanupLimit)
	return err
}
