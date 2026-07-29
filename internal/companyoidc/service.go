package companyoidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/secrets"
)

const (
	singletonConnectionID int64 = 1
	companyOIDCTimeFormat       = "2006-01-02T15:04:05.000000000Z"
)

type Connection struct {
	ProviderLabel string
	Issuer        string
	ClientID      string
	Domains       []string
	Revision      int64
}

type CreateInput struct {
	ProviderLabel string
	Issuer        string
	ClientID      string
	ClientSecret  string
	Domains       []string
}

type EditInput struct {
	ProviderLabel           string
	Issuer                  string
	ClientID                string
	ReplacementClientSecret string
	Domains                 []string
	ExpectedRevision        int64
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

var (
	ErrConflict       = errors.New("the company OIDC Draft changed; reload it before saving again")
	ErrConfiguration  = errors.New("company OIDC client-secret encryption is not configured")
	ErrAuthorization  = errors.New("only an enabled Administrator can save the company OIDC Draft")
	ErrOutcomeUnknown = errors.New("the company OIDC Draft save outcome could not be confirmed")
)

type Service struct {
	db      *sql.DB
	secrets secrets.Store
	now     func() time.Time
}

func NewService(db *sql.DB, secretStore secrets.Store) *Service {
	return &Service{
		db:      db,
		secrets: secretStore,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Current(ctx context.Context) (Connection, bool, error) {
	if s == nil || s.db == nil {
		return Connection{}, false, errors.New("company OIDC service has no database")
	}
	record, found, err := loadConnectionRecord(ctx, s.db)
	if err != nil || !found {
		return Connection{}, found, err
	}
	connection, err := publicConnection(record)
	if err != nil {
		return Connection{}, false, err
	}
	return connection, true, nil
}

func (s *Service) Create(ctx context.Context, actorUserID int64, input CreateInput) error {
	if s == nil || s.db == nil {
		return errors.New("company OIDC service has no database")
	}
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		return err
	}
	if s.secrets == nil {
		return ErrConfiguration
	}
	ciphertext, err := encryptClientSecret(ctx, s.secrets, normalized.ClientSecret)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin company OIDC Draft creation: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	if _, found, err := loadConnectionRecord(ctx, tx); err != nil {
		return err
	} else if found {
		return ErrConflict
	}

	now := s.now().UTC()
	record := connectionRecord{
		ProviderLabel:          normalized.ProviderLabel,
		Issuer:                 normalized.Issuer,
		ClientID:               normalized.ClientID,
		ClientSecretCiphertext: ciphertext,
		Domains:                normalized.Domains,
		Revision:               1,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := insertConnection(ctx, tx, record); err != nil {
		return err
	}
	if err := recordDraftSaved(ctx, tx, actorUserID, record.Revision, false, len(record.Domains)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

func (s *Service) Edit(ctx context.Context, actorUserID int64, input EditInput) error {
	if s == nil || s.db == nil {
		return errors.New("company OIDC service has no database")
	}
	normalized, err := normalizeEditInput(input)
	if err != nil {
		return err
	}
	if s.secrets == nil {
		return ErrConfiguration
	}
	var replacementCiphertext []byte
	if normalized.ReplacementClientSecret != "" {
		replacementCiphertext, err = encryptClientSecret(ctx, s.secrets, normalized.ReplacementClientSecret)
		if err != nil {
			return err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin company OIDC Draft edit: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return err
	}
	existing, found, err := loadConnectionRecord(ctx, tx)
	if err != nil {
		return err
	}
	if !found || existing.Revision != normalized.ExpectedRevision {
		return ErrConflict
	}
	secretReplaced := len(replacementCiphertext) > 0
	if !secretReplaced &&
		existing.ProviderLabel == normalized.ProviderLabel &&
		existing.Issuer == normalized.Issuer &&
		existing.ClientID == normalized.ClientID &&
		slices.Equal(existing.Domains, normalized.Domains) {
		return nil
	}
	if existing.Revision == math.MaxInt64 {
		return errors.New("company OIDC Draft revision is exhausted")
	}

	now := s.now().UTC()
	if !now.After(existing.UpdatedAt) {
		now = existing.UpdatedAt.Add(time.Nanosecond)
	}
	updated := connectionRecord{
		ProviderLabel:          normalized.ProviderLabel,
		Issuer:                 normalized.Issuer,
		ClientID:               normalized.ClientID,
		ClientSecretCiphertext: existing.ClientSecretCiphertext,
		Domains:                normalized.Domains,
		Revision:               existing.Revision + 1,
		CreatedAt:              existing.CreatedAt,
		UpdatedAt:              now,
	}
	if secretReplaced {
		updated.ClientSecretCiphertext = replacementCiphertext
	}
	if err := updateConnection(ctx, tx, updated); err != nil {
		return err
	}
	if err := recordDraftSaved(ctx, tx, actorUserID, updated.Revision, secretReplaced, len(updated.Domains)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return ErrOutcomeUnknown
	}
	return nil
}

type normalizedConnectionInput struct {
	ProviderLabel           string
	Issuer                  string
	ClientID                string
	ClientSecret            string
	ReplacementClientSecret string
	Domains                 []string
	ExpectedRevision        int64
}

func normalizeCreateInput(input CreateInput) (normalizedConnectionInput, error) {
	normalized, err := normalizeNonSecretInput(input.ProviderLabel, input.Issuer, input.ClientID, input.Domains)
	if err != nil {
		return normalizedConnectionInput{}, err
	}
	if err := validateClientSecret(input.ClientSecret); err != nil {
		return normalizedConnectionInput{}, err
	}
	normalized.ClientSecret = input.ClientSecret
	return normalized, nil
}

func normalizeEditInput(input EditInput) (normalizedConnectionInput, error) {
	if input.ExpectedRevision <= 0 {
		return normalizedConnectionInput{}, ValidationError{Message: "expected revision must identify the Draft being edited"}
	}
	normalized, err := normalizeNonSecretInput(input.ProviderLabel, input.Issuer, input.ClientID, input.Domains)
	if err != nil {
		return normalizedConnectionInput{}, err
	}
	if input.ReplacementClientSecret != "" {
		if err := validateClientSecret(input.ReplacementClientSecret); err != nil {
			return normalizedConnectionInput{}, err
		}
	}
	normalized.ReplacementClientSecret = input.ReplacementClientSecret
	normalized.ExpectedRevision = input.ExpectedRevision
	return normalized, nil
}

func normalizeNonSecretInput(providerLabel, issuer, clientID string, domains []string) (normalizedConnectionInput, error) {
	providerLabel, err := normalizeProviderLabel(providerLabel)
	if err != nil {
		return normalizedConnectionInput{}, err
	}
	issuer, err = normalizeIssuer(issuer)
	if err != nil {
		return normalizedConnectionInput{}, err
	}
	clientID, err = normalizeClientID(clientID)
	if err != nil {
		return normalizedConnectionInput{}, err
	}
	domains, err = normalizeDomains(domains)
	if err != nil {
		return normalizedConnectionInput{}, err
	}
	return normalizedConnectionInput{
		ProviderLabel: providerLabel,
		Issuer:        issuer,
		ClientID:      clientID,
		Domains:       domains,
	}, nil
}

func normalizeProviderLabel(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", ValidationError{Message: "provider label must be valid UTF-8"}
	}
	value = strings.TrimSpace(value)
	if count := utf8.RuneCountInString(value); count < 1 || count > 80 {
		return "", ValidationError{Message: "provider label must be between 1 and 80 characters"}
	}
	if containsControlOrLineSeparator(value) {
		return "", ValidationError{Message: "provider label contains invalid characters"}
	}
	return value, nil
}

func normalizeIssuer(value string) (string, error) {
	value = trimASCIIWhitespace(value)
	if len(value) < 1 || len(value) > 2048 {
		return "", ValidationError{Message: "issuer must be between 1 and 2048 bytes"}
	}
	for i := range len(value) {
		if value[i] > 0x7f || value[i] < 0x20 || value[i] == 0x7f {
			return "", ValidationError{Message: "issuer must contain only printable ASCII characters"}
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return "", ValidationError{Message: "issuer must be an absolute HTTPS URL with a host"}
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", ValidationError{Message: "issuer must use HTTPS"}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(value, "#") {
		return "", ValidationError{Message: "issuer must not contain user information, a query, or a fragment"}
	}
	if !validRawIssuerPath(rawIssuerPath(value)) {
		return "", ValidationError{Message: "issuer path must use valid URI escaping"}
	}
	return value, nil
}

func rawIssuerPath(value string) string {
	schemeEnd := strings.Index(value, "://")
	if schemeEnd < 0 {
		return ""
	}
	authorityAndPath := value[schemeEnd+3:]
	pathStart := strings.IndexByte(authorityAndPath, '/')
	if pathStart < 0 {
		return ""
	}
	return authorityAndPath[pathStart:]
}

func validRawIssuerPath(path string) bool {
	for i := 0; i < len(path); i++ {
		character := path[i]
		if isURIUnreserved(character) || strings.ContainsRune("!$&'()*+,;=:@/", rune(character)) {
			continue
		}
		if character == '%' && i+2 < len(path) && isHexDigit(path[i+1]) && isHexDigit(path[i+2]) {
			i += 2
			continue
		}
		return false
	}
	return true
}

func isURIUnreserved(character byte) bool {
	return character >= 'a' && character <= 'z' ||
		character >= 'A' && character <= 'Z' ||
		character >= '0' && character <= '9' ||
		strings.ContainsRune("-._~", rune(character))
}

func isHexDigit(character byte) bool {
	return character >= '0' && character <= '9' ||
		character >= 'a' && character <= 'f' ||
		character >= 'A' && character <= 'F'
}

func normalizeClientID(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", ValidationError{Message: "Client ID must be valid UTF-8"}
	}
	value = trimASCIIWhitespace(value)
	if len(value) < 1 || len(value) > 512 {
		return "", ValidationError{Message: "Client ID must be between 1 and 512 bytes"}
	}
	if containsControlOrLineSeparator(value) {
		return "", ValidationError{Message: "Client ID contains invalid characters"}
	}
	return value, nil
}

func validateClientSecret(value string) error {
	if !utf8.ValidString(value) {
		return ValidationError{Message: "client secret must be valid UTF-8"}
	}
	if len(value) < 1 || len(value) > 4096 {
		return ValidationError{Message: "client secret must be between 1 and 4096 bytes"}
	}
	if strings.IndexByte(value, 0) >= 0 {
		return ValidationError{Message: "client secret contains an invalid NUL character"}
	}
	return nil
}

func normalizeDomains(values []string) ([]string, error) {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		for i := range len(value) {
			if value[i] > 0x7f {
				return nil, ValidationError{Message: "allowed domains must use ASCII DNS names"}
			}
		}
		value = strings.ToLower(value)
		if err := validateDomain(value); err != nil {
			return nil, err
		}
		unique[value] = struct{}{}
	}
	if len(unique) < 1 || len(unique) > 20 {
		return nil, ValidationError{Message: "provide between 1 and 20 allowed domains"}
	}
	domains := make([]string, 0, len(unique))
	for domain := range unique {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains, nil
}

func validateDomain(value string) error {
	invalid := func() error {
		return ValidationError{Message: "allowed domains must be exact lower-case ASCII DNS names"}
	}
	if len(value) < 1 || len(value) > 253 || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return invalid()
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return invalid()
		}
		for i := range len(label) {
			character := label[i]
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return invalid()
			}
		}
	}
	return nil
}

func containsControlOrLineSeparator(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}

func trimASCIIWhitespace(value string) string {
	return strings.Trim(value, " \t\n\r\v\f")
}

func encryptClientSecret(ctx context.Context, store secrets.Store, plaintext string) ([]byte, error) {
	ciphertext, err := store.Encrypt(ctx, []byte(plaintext))
	if err != nil || len(ciphertext) == 0 {
		return nil, errors.New("encrypt company OIDC client secret")
	}
	return ciphertext, nil
}

type connectionRecord struct {
	ProviderLabel          string
	Issuer                 string
	ClientID               string
	ClientSecretCiphertext []byte
	Domains                []string
	Revision               int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

type connectionQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func loadConnectionRecord(ctx context.Context, q connectionQueryer) (connectionRecord, bool, error) {
	rows, err := q.QueryContext(ctx, `
SELECT c.provider_label, c.issuer, c.client_id, c.client_secret_ciphertext,
  c.revision, c.created_at, c.updated_at, d.domain
FROM company_oidc_connections c
LEFT JOIN company_oidc_allowed_domains d ON d.connection_id = c.id
WHERE c.id = 1
ORDER BY d.domain`)
	if err != nil {
		return connectionRecord{}, false, fmt.Errorf("read company OIDC Draft: %w", err)
	}
	defer rows.Close()
	var record connectionRecord
	record.Domains = make([]string, 0)
	found := false
	for rows.Next() {
		var providerLabel, issuer, clientID, createdAt, updatedAt string
		var ciphertext []byte
		var revision int64
		var domain sql.NullString
		if err := rows.Scan(
			&providerLabel,
			&issuer,
			&clientID,
			&ciphertext,
			&revision,
			&createdAt,
			&updatedAt,
			&domain,
		); err != nil {
			return connectionRecord{}, false, fmt.Errorf("scan company OIDC Draft: %w", err)
		}
		if !found {
			record.ProviderLabel = providerLabel
			record.Issuer = issuer
			record.ClientID = clientID
			record.ClientSecretCiphertext = ciphertext
			record.Revision = revision
			record.CreatedAt, err = parseCompanyOIDCTime(createdAt)
			if err != nil {
				return connectionRecord{}, false, errors.New("company OIDC Draft data is malformed")
			}
			record.UpdatedAt, err = parseCompanyOIDCTime(updatedAt)
			if err != nil {
				return connectionRecord{}, false, errors.New("company OIDC Draft data is malformed")
			}
			found = true
		}
		if domain.Valid {
			record.Domains = append(record.Domains, domain.String)
		}
	}
	if err := rows.Err(); err != nil {
		return connectionRecord{}, false, fmt.Errorf("read company OIDC Draft rows: %w", err)
	}
	return record, found, nil
}

func publicConnection(record connectionRecord) (Connection, error) {
	normalized, err := normalizeNonSecretInput(record.ProviderLabel, record.Issuer, record.ClientID, record.Domains)
	if err != nil ||
		normalized.ProviderLabel != record.ProviderLabel ||
		normalized.Issuer != record.Issuer ||
		normalized.ClientID != record.ClientID ||
		!slices.Equal(normalized.Domains, record.Domains) ||
		record.Revision <= 0 ||
		len(record.ClientSecretCiphertext) == 0 ||
		record.CreatedAt.IsZero() ||
		record.UpdatedAt.IsZero() ||
		record.UpdatedAt.Before(record.CreatedAt) {
		return Connection{}, errors.New("company OIDC Draft data is malformed")
	}
	return Connection{
		ProviderLabel: record.ProviderLabel,
		Issuer:        record.Issuer,
		ClientID:      record.ClientID,
		Domains:       slices.Clone(record.Domains),
		Revision:      record.Revision,
	}, nil
}

func lockEnabledAdminActor(ctx context.Context, tx *sql.Tx, actorUserID int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE users SET updated_at = updated_at WHERE id = ?`, actorUserID); err != nil {
		return fmt.Errorf("lock company OIDC Draft actor: %w", err)
	}
	var allowed int
	if err := tx.QueryRowContext(ctx, `
SELECT EXISTS (
  SELECT 1
  FROM users u
  JOIN user_roles ur ON ur.user_id = u.id AND ur.role = 'admin'
  WHERE u.id = ? AND u.disabled_at IS NULL
)`, actorUserID).Scan(&allowed); err != nil {
		return fmt.Errorf("authorize company OIDC Draft actor: %w", err)
	}
	if allowed != 1 {
		return ErrAuthorization
	}
	return nil
}

func insertConnection(ctx context.Context, tx *sql.Tx, record connectionRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_connections(
  id, provider_label, issuer, client_id, client_secret_ciphertext, revision, created_at, updated_at
)
VALUES (1, ?, ?, ?, ?, ?, ?, ?)`,
		record.ProviderLabel,
		record.Issuer,
		record.ClientID,
		record.ClientSecretCiphertext,
		record.Revision,
		formatCompanyOIDCTime(record.CreatedAt),
		formatCompanyOIDCTime(record.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("insert company OIDC Draft: %w", err)
	}
	return insertDomains(ctx, tx, record.Domains)
}

func updateConnection(ctx context.Context, tx *sql.Tx, record connectionRecord) error {
	result, err := tx.ExecContext(ctx, `
UPDATE company_oidc_connections
SET provider_label = ?, issuer = ?, client_id = ?, client_secret_ciphertext = ?, revision = ?, updated_at = ?
WHERE id = 1`,
		record.ProviderLabel,
		record.Issuer,
		record.ClientID,
		record.ClientSecretCiphertext,
		record.Revision,
		formatCompanyOIDCTime(record.UpdatedAt),
	)
	if err != nil {
		return fmt.Errorf("update company OIDC Draft: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count updated company OIDC Draft rows: %w", err)
	}
	if updated != 1 {
		return fmt.Errorf("update company OIDC Draft affected %d rows", updated)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM company_oidc_allowed_domains WHERE connection_id = 1`); err != nil {
		return fmt.Errorf("replace company OIDC allowed domains: %w", err)
	}
	return insertDomains(ctx, tx, record.Domains)
}

func insertDomains(ctx context.Context, tx *sql.Tx, domains []string) error {
	for _, domain := range domains {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_allowed_domains(connection_id, domain)
VALUES (1, ?)`, domain); err != nil {
			return fmt.Errorf("insert company OIDC allowed domain: %w", err)
		}
	}
	return nil
}

func recordDraftSaved(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	revision int64,
	secretReplaced bool,
	domainCount int,
) error {
	details, err := json.Marshal(struct {
		Revision       int64 `json:"revision"`
		SecretReplaced bool  `json:"secret_replaced"`
		DomainCount    int   `json:"domain_count"`
	}{
		Revision:       revision,
		SecretReplaced: secretReplaced,
		DomainCount:    domainCount,
	})
	if err != nil {
		return errors.New("encode company OIDC Draft audit evidence")
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      audit.ActionOIDCConnectionDraftSaved,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   strconv.FormatInt(singletonConnectionID, 10),
		DetailsJSON: string(details),
	}); err != nil {
		return fmt.Errorf("record company OIDC Draft audit event: %w", err)
	}
	return nil
}

func formatCompanyOIDCTime(value time.Time) string {
	return value.UTC().Format(companyOIDCTimeFormat)
}

func parseCompanyOIDCTime(value string) (time.Time, error) {
	parsed, err := time.Parse(companyOIDCTimeFormat, value)
	if err != nil || formatCompanyOIDCTime(parsed) != value {
		return time.Time{}, errors.New("company OIDC timestamp is malformed")
	}
	return parsed, nil
}
