package webhook

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

const (
	deliveryTimeFormat             = "2006-01-02T15:04:05.000000000Z07:00"
	deliveryProcessingClaimTimeout = 10 * time.Minute
)

type deliveryDatabase interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type DeliveryStore struct {
	db  deliveryDatabase
	now func() time.Time
}

type Delivery struct {
	ID                  int64
	RepositoryID        int64
	DeliveryID          string
	Event               string
	Action              string
	ReceivedAt          time.Time
	Verified            bool
	ProcessingStartedAt *time.Time
	ProcessedAt         *time.Time
	Error               string
}

type DeliveryRecordParams struct {
	RepositoryID int64
	DeliveryID   string
	Event        string
	Action       string
	Verified     bool
}

type DeliveryProcessParams struct {
	RepositoryID        int64
	Action              string
	Error               string
	ProcessingStartedAt *time.Time
}

func NewDeliveryStore(db *sql.DB) *DeliveryStore {
	if db == nil {
		return newDeliveryStore(nil)
	}
	return newDeliveryStore(db)
}

func newDeliveryStore(db deliveryDatabase) *DeliveryStore {
	return &DeliveryStore{db: db, now: func() time.Time { return time.Now().UTC() }}
}

func (s *DeliveryStore) Record(ctx context.Context, params DeliveryRecordParams) (Delivery, error) {
	if s == nil || s.db == nil {
		return Delivery{}, errors.New("webhook delivery store has no database")
	}
	params = normalizeDeliveryRecordParams(params)
	if err := validateDeliveryRecordParams(params); err != nil {
		return Delivery{}, err
	}
	if existing, found, err := s.FindByRepositoryDeliveryID(ctx, params.RepositoryID, params.DeliveryID); err != nil {
		return Delivery{}, err
	} else if found {
		return existing, ValidationError{Message: "webhook delivery already recorded"}
	}

	receivedAt := formatDeliveryTime(s.now())
	insert, err := s.db.ExecContext(ctx, `
INSERT INTO webhook_deliveries(repository_id, delivery_id, event, action, received_at, verified)
VALUES (?, ?, ?, ?, ?, ?)`, nullableDeliveryInt64(params.RepositoryID), params.DeliveryID, params.Event, nullableDeliveryString(params.Action), receivedAt, boolInt(params.Verified))
	if err != nil {
		if isDuplicateDeliveryError(err) {
			if existing, found, findErr := s.FindByRepositoryDeliveryID(ctx, params.RepositoryID, params.DeliveryID); findErr == nil && found {
				return existing, ValidationError{Message: "webhook delivery already recorded"}
			}
		}
		return Delivery{}, recordDeliveryError(err)
	}
	id, err := insert.LastInsertId()
	if err != nil {
		return Delivery{}, fmt.Errorf("recorded webhook delivery id: %w", err)
	}
	return s.Get(ctx, id)
}

func (s *DeliveryStore) ClaimForProcessing(ctx context.Context, id int64) (Delivery, bool, error) {
	if s == nil || s.db == nil {
		return Delivery{}, false, errors.New("webhook delivery store has no database")
	}
	if id <= 0 {
		return Delivery{}, false, ValidationError{Message: "webhook delivery id is required"}
	}
	now := s.now().UTC()
	processingStartedAt := formatDeliveryTime(now)
	staleBefore := formatDeliveryTime(now.Add(-deliveryProcessingClaimTimeout))
	update, err := s.db.ExecContext(ctx, `
UPDATE webhook_deliveries
SET processing_started_at = ?,
    error = NULL
WHERE id = ? AND processed_at IS NULL AND (processing_started_at IS NULL OR processing_started_at < ?)`, processingStartedAt, id, staleBefore)
	if err != nil {
		return Delivery{}, false, fmt.Errorf("claim webhook delivery for processing: %w", err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return Delivery{}, false, fmt.Errorf("claim webhook delivery for processing rows: %w", err)
	}
	delivery, getErr := s.Get(ctx, id)
	if getErr != nil {
		return Delivery{}, false, getErr
	}
	return delivery, affected > 0, nil
}

func (s *DeliveryStore) MarkProcessed(ctx context.Context, id int64, params DeliveryProcessParams) (Delivery, error) {
	if s == nil || s.db == nil {
		return Delivery{}, errors.New("webhook delivery store has no database")
	}
	params = normalizeDeliveryProcessParams(params)
	if err := validateDeliveryProcessParams(id, params); err != nil {
		return Delivery{}, err
	}
	processedAt := formatDeliveryTime(s.now())
	processingStartedAt := formatDeliveryTime(*params.ProcessingStartedAt)
	update, err := s.db.ExecContext(ctx, `
UPDATE webhook_deliveries
SET repository_id = COALESCE(?, repository_id),
    action = COALESCE(?, action),
    processing_started_at = NULL,
    processed_at = ?,
    error = ?
WHERE id = ? AND processing_started_at = ?`, nullableDeliveryInt64(params.RepositoryID), nullableDeliveryString(params.Action), processedAt, nullableDeliveryString(params.Error), id, processingStartedAt)
	if err != nil {
		return Delivery{}, fmt.Errorf("mark webhook delivery processed: %w", err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return Delivery{}, fmt.Errorf("mark webhook delivery processed rows: %w", err)
	}
	if affected == 0 {
		return Delivery{}, sql.ErrNoRows
	}
	return s.Get(ctx, id)
}

func (s *DeliveryStore) MarkProcessingFailed(ctx context.Context, id int64, message string, processingStartedAt time.Time) (Delivery, error) {
	if s == nil || s.db == nil {
		return Delivery{}, errors.New("webhook delivery store has no database")
	}
	message = strings.TrimSpace(message)
	if id <= 0 {
		return Delivery{}, ValidationError{Message: "webhook delivery id is required"}
	}
	if processingStartedAt.IsZero() {
		return Delivery{}, ValidationError{Message: "webhook delivery processing claim is required"}
	}
	if invalidOptionalDeliveryText(message, 1000) {
		return Delivery{}, ValidationError{Message: "webhook delivery error is invalid"}
	}
	processingStartedAtText := formatDeliveryTime(processingStartedAt)
	update, err := s.db.ExecContext(ctx, `
UPDATE webhook_deliveries
SET processing_started_at = NULL,
    processed_at = NULL,
    error = ?
WHERE id = ? AND processing_started_at = ?`, nullableDeliveryString(message), id, processingStartedAtText)
	if err != nil {
		return Delivery{}, fmt.Errorf("mark webhook delivery processing failed: %w", err)
	}
	affected, err := update.RowsAffected()
	if err != nil {
		return Delivery{}, fmt.Errorf("mark webhook delivery processing failed rows: %w", err)
	}
	if affected == 0 {
		return Delivery{}, sql.ErrNoRows
	}
	return s.Get(ctx, id)
}

func (s *DeliveryStore) Get(ctx context.Context, id int64) (Delivery, error) {
	if s == nil || s.db == nil {
		return Delivery{}, errors.New("webhook delivery store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, delivery_id, event, action, received_at, verified, processing_started_at, processed_at, error
FROM webhook_deliveries
WHERE id = ?`, id)
	return scanDelivery(row)
}

func (s *DeliveryStore) FindByRepositoryDeliveryID(ctx context.Context, repositoryID int64, deliveryID string) (Delivery, bool, error) {
	if s == nil || s.db == nil {
		return Delivery{}, false, errors.New("webhook delivery store has no database")
	}
	if repositoryID <= 0 {
		return Delivery{}, false, ValidationError{Message: "webhook delivery repository is required"}
	}
	deliveryID = strings.TrimSpace(deliveryID)
	if deliveryID == "" {
		return Delivery{}, false, ValidationError{Message: "webhook delivery id is required"}
	}
	if invalidDeliveryText(deliveryID, 255) {
		return Delivery{}, false, ValidationError{Message: "webhook delivery id is invalid"}
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, delivery_id, event, action, received_at, verified, processing_started_at, processed_at, error
FROM webhook_deliveries
WHERE repository_id = ? AND delivery_id = ?`, repositoryID, deliveryID)
	delivery, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, false, nil
	}
	if err != nil {
		return Delivery{}, false, err
	}
	return delivery, true, nil
}

func (s *DeliveryStore) LatestVerifiedPullRequestByRepository(ctx context.Context, repositoryID int64) (Delivery, bool, error) {
	if s == nil || s.db == nil {
		return Delivery{}, false, errors.New("webhook delivery store has no database")
	}
	if repositoryID <= 0 {
		return Delivery{}, false, ValidationError{Message: "webhook delivery repository is required"}
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, repository_id, delivery_id, event, action, received_at, verified, processing_started_at, processed_at, error
FROM webhook_deliveries
WHERE repository_id = ? AND verified = 1 AND event = 'pull_request'
ORDER BY received_at DESC, id DESC
LIMIT 1`, repositoryID)
	delivery, err := scanDelivery(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Delivery{}, false, nil
	}
	if err != nil {
		return Delivery{}, false, err
	}
	return delivery, true, nil
}

// DeliveryOrder selects one fixed ordering for paged delivery lists. It is a
// closed set: every value maps to a constant ORDER BY clause and nothing
// user-supplied reaches the SQL.
type DeliveryOrder string

const (
	DeliveryOrderReceivedDesc  DeliveryOrder = "received_desc"
	DeliveryOrderReceivedAsc   DeliveryOrder = "received_asc"
	DeliveryOrderProcessedDesc DeliveryOrder = "processed_desc"
	DeliveryOrderProcessedAsc  DeliveryOrder = "processed_asc"
)

// Derived processing states accepted by ListPage's processing filter. They
// partition all rows with the same precedence as the UI badge derivation.
const (
	DeliveryProcessingReceived           = "received"
	DeliveryProcessingProcessing         = "processing"
	DeliveryProcessingProcessed          = "processed"
	DeliveryProcessingProcessedWithError = "processed_with_error"
	DeliveryProcessingRetryableFailure   = "retryable_failure"
)

// deliveryProcessingConditions maps each derived processing state to its WHERE
// fragment. The error column stores NULL for "no error", so comparisons go
// through COALESCE to match the Go-side Error == "" derivation.
var deliveryProcessingConditions = map[string]string{
	DeliveryProcessingProcessed:          "processed_at IS NOT NULL AND COALESCE(error, '') = ''",
	DeliveryProcessingProcessedWithError: "processed_at IS NOT NULL AND COALESCE(error, '') != ''",
	DeliveryProcessingProcessing:         "processed_at IS NULL AND processing_started_at IS NOT NULL",
	DeliveryProcessingRetryableFailure:   "processed_at IS NULL AND processing_started_at IS NULL AND COALESCE(error, '') != ''",
	DeliveryProcessingReceived:           "processed_at IS NULL AND processing_started_at IS NULL AND COALESCE(error, '') = ''",
}

// deliveryOrderClause maps a DeliveryOrder to its fixed ORDER BY clause;
// unknown orders fall back to newest received first. Processed orders sort
// missing processed_at last in both directions.
func deliveryOrderClause(order DeliveryOrder) string {
	switch order {
	case DeliveryOrderReceivedAsc:
		return "ORDER BY received_at ASC, id ASC"
	case DeliveryOrderProcessedDesc:
		return "ORDER BY processed_at IS NULL, processed_at DESC, id DESC"
	case DeliveryOrderProcessedAsc:
		return "ORDER BY processed_at IS NULL, processed_at ASC, id ASC"
	default:
		return "ORDER BY received_at DESC, id DESC"
	}
}

// deliveryPageFilter builds the shared WHERE clause for the paged list
// queries: the scope's visibility predicate, an optional derived
// processing-state partition, and an optional exact repository filter, always
// intersected so a filter can only narrow the scope. An unknown processing
// value matches nothing.
func deliveryPageFilter(scope repositoryscope.ReadScope, processing string, repositoryID int64) (string, []any) {
	predicate, args := scope.SQLPredicate("repository_id")
	where := "WHERE " + predicate
	if processing != "" {
		condition, known := deliveryProcessingConditions[processing]
		if !known {
			condition = "1 = 0"
		}
		where += " AND " + condition
	}
	if repositoryID > 0 {
		where += " AND repository_id = ?"
		args = append(args, repositoryID)
	}
	return where, args
}

// ListPage returns one page of deliveries plus the total count matching the
// same filters. An empty processing value or zero repositoryID leaves that
// filter off.
func (s *DeliveryStore) ListPage(ctx context.Context, processing string, repositoryID int64, order DeliveryOrder, offset, limit int) ([]Delivery, int, error) {
	return s.ListPageForScope(ctx, repositoryscope.All(), processing, repositoryID, order, offset, limit)
}

// ListPageForScope pages webhook deliveries visible through the caller's read
// scope. The scope, processing filter, and repository filter all intersect
// inside SQL before ordering and pagination, and the count query shares the
// identical conditions, so rows and total always agree and a filter can never
// widen past the scope.
func (s *DeliveryStore) ListPageForScope(ctx context.Context, scope repositoryscope.ReadScope, processing string, repositoryID int64, order DeliveryOrder, offset, limit int) ([]Delivery, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("webhook delivery store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	where, filterArgs := deliveryPageFilter(scope, processing, repositoryID)

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM webhook_deliveries "+where, filterArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count webhook deliveries: %w", err)
	}

	args := append(append([]any{}, filterArgs...), limit, offset)
	rows, err := s.db.QueryContext(ctx, `
SELECT id, repository_id, delivery_id, event, action, received_at, verified, processing_started_at, processed_at, error
FROM webhook_deliveries
`+where+`
`+deliveryOrderClause(order)+`
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list webhook deliveries page: %w", err)
	}
	defer rows.Close()

	deliveries := make([]Delivery, 0)
	for rows.Next() {
		delivery, err := scanDelivery(rows)
		if err != nil {
			return nil, 0, err
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list webhook deliveries page rows: %w", err)
	}
	return deliveries, total, nil
}

func recordDeliveryError(err error) error {
	if isDuplicateDeliveryError(err) {
		return ValidationError{Message: "webhook delivery already recorded"}
	}
	return fmt.Errorf("record webhook delivery: %w", err)
}

func isDuplicateDeliveryError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "UNIQUE constraint failed: webhook_deliveries.repository_id, webhook_deliveries.delivery_id") ||
		strings.Contains(message, "UNIQUE constraint failed: webhook_deliveries.delivery_id") ||
		strings.Contains(message, "constraint failed: UNIQUE constraint failed: webhook_deliveries")
}

func normalizeDeliveryRecordParams(params DeliveryRecordParams) DeliveryRecordParams {
	params.DeliveryID = strings.TrimSpace(params.DeliveryID)
	params.Event = strings.TrimSpace(params.Event)
	params.Action = strings.TrimSpace(params.Action)
	return params
}

func normalizeDeliveryProcessParams(params DeliveryProcessParams) DeliveryProcessParams {
	params.Action = strings.TrimSpace(params.Action)
	params.Error = strings.TrimSpace(params.Error)
	return params
}

func validateDeliveryRecordParams(params DeliveryRecordParams) error {
	if params.RepositoryID <= 0 {
		return ValidationError{Message: "webhook delivery repository is required"}
	}
	var missing []string
	if params.DeliveryID == "" {
		missing = append(missing, "delivery id")
	}
	if params.Event == "" {
		missing = append(missing, "event")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required webhook delivery fields: %s", strings.Join(missing, ", "))}
	}
	if invalidDeliveryText(params.DeliveryID, 255) {
		return ValidationError{Message: "webhook delivery id is invalid"}
	}
	if invalidDeliveryText(params.Event, 100) {
		return ValidationError{Message: "webhook delivery event is invalid"}
	}
	if invalidOptionalDeliveryText(params.Action, 100) {
		return ValidationError{Message: "webhook delivery action is invalid"}
	}
	return nil
}

func validateDeliveryProcessParams(id int64, params DeliveryProcessParams) error {
	if id <= 0 {
		return ValidationError{Message: "webhook delivery id is required"}
	}
	if params.RepositoryID < 0 {
		return ValidationError{Message: "webhook delivery repository is invalid"}
	}
	if params.ProcessingStartedAt == nil || params.ProcessingStartedAt.IsZero() {
		return ValidationError{Message: "webhook delivery processing claim is required"}
	}
	if invalidOptionalDeliveryText(params.Action, 100) {
		return ValidationError{Message: "webhook delivery action is invalid"}
	}
	if invalidOptionalDeliveryText(params.Error, 1000) {
		return ValidationError{Message: "webhook delivery error is invalid"}
	}
	return nil
}

func invalidDeliveryText(value string, limit int) bool {
	return value == "" || len(value) > limit || containsDeliveryControl(value)
}

func invalidOptionalDeliveryText(value string, limit int) bool {
	return value != "" && invalidDeliveryText(value, limit)
}

func containsDeliveryControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func nullableDeliveryInt64(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func nullableDeliveryString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func formatDeliveryTime(value time.Time) string {
	return value.UTC().Format(deliveryTimeFormat)
}

func parseDeliveryTime(field string, value string) (time.Time, error) {
	parsed, err := time.Parse(deliveryTimeFormat, value)
	if err == nil {
		return parsed, nil
	}
	if fallback, fallbackErr := time.Parse(time.RFC3339Nano, value); fallbackErr == nil {
		return fallback, nil
	}
	return time.Time{}, fmt.Errorf("parse webhook delivery %s: %w", field, err)
}

type deliveryScanner interface {
	Scan(dest ...any) error
}

func scanDelivery(row deliveryScanner) (Delivery, error) {
	var delivery Delivery
	var repositoryID sql.NullInt64
	var action sql.NullString
	var receivedAt string
	var verified int
	var processedAt sql.NullString
	var processingStartedAt sql.NullString
	var deliveryError sql.NullString
	if err := row.Scan(&delivery.ID, &repositoryID, &delivery.DeliveryID, &delivery.Event, &action, &receivedAt, &verified, &processingStartedAt, &processedAt, &deliveryError); err != nil {
		return Delivery{}, fmt.Errorf("scan webhook delivery: %w", err)
	}
	if repositoryID.Valid {
		delivery.RepositoryID = repositoryID.Int64
	}
	if action.Valid {
		delivery.Action = action.String
	}
	parsedReceivedAt, err := parseDeliveryTime("received_at", receivedAt)
	if err != nil {
		return Delivery{}, err
	}
	delivery.ReceivedAt = parsedReceivedAt
	delivery.Verified = verified != 0
	if processingStartedAt.Valid {
		parsedProcessingStartedAt, err := parseDeliveryTime("processing_started_at", processingStartedAt.String)
		if err != nil {
			return Delivery{}, err
		}
		delivery.ProcessingStartedAt = &parsedProcessingStartedAt
	}
	if processedAt.Valid {
		parsedProcessedAt, err := parseDeliveryTime("processed_at", processedAt.String)
		if err != nil {
			return Delivery{}, err
		}
		delivery.ProcessedAt = &parsedProcessedAt
	}
	if deliveryError.Valid {
		delivery.Error = deliveryError.String
	}
	return delivery, nil
}
