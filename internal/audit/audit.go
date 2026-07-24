package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

const (
	ActionRepositoryCreated                  = "repository.created"
	ActionRepositoryWebhookSecretConfigured  = "repository.webhook_secret_configured"
	ActionRepositoryStatusTokenConfigured    = "repository.status_token_configured"
	ActionRepositoryOpenPullRequestsSynced   = "repository.open_pull_requests_synced"
	ActionRepositoryBranchAdded              = "repository.branch_added"
	ActionRepositoryBranchRemoved            = "repository.branch_removed"
	ActionRepositorySetupCheckRun            = "repository.setup_check_run"
	ActionRepositorySetupDriftDetected       = "repository.setup_drift_detected"
	ActionRepositoryStatusPostVerified       = "repository.status_post_verified"
	ActionRepositoryStatusPostVerifyFailed   = "repository.status_post_verification_failed"
	ActionRepositoryEnforcementActivated     = "repository.enforcement_activated"
	ActionRepositoryEnforcementDeactivated   = "repository.enforcement_deactivated"
	ActionRepositoryEnforcementActivateFail  = "repository.enforcement_activation_failed"
	ActionRepositoryEnforcementReconciled    = "repository.enforcement_reconcile_succeeded"
	ActionRepositoryEnforcementReconcileFail = "repository.enforcement_reconcile_failed"
	ActionRepositoryEnforcementRecovered     = "repository.enforcement_recovery_succeeded"
	ActionRepositoryEnforcementRecoverFail   = "repository.enforcement_recovery_failed"
	ActionRepositoryRuntimeConvergenceFail   = "repository.runtime_convergence_failed"
	ActionRepositoryGrantAdded               = "repository_grant.added"
	ActionRepositoryGrantRevoked             = "repository_grant.revoked"
	ActionBranchFreezeCreated                = "branch_freeze.created"
	ActionBranchFreezeEnded                  = "branch_freeze.ended"
	ActionBranchFreezeCancelled              = "branch_freeze.cancelled"
	ActionBranchFreezePlannedUnfreeze        = "branch_freeze.planned_unfreeze"
	ActionFreezeScheduleCreated              = "freeze_schedule.created"
	ActionFreezeScheduleUpdated              = "freeze_schedule.updated"
	ActionFreezeScheduleCancelled            = "freeze_schedule.cancelled"
	ActionFreezeScheduleActivated            = "freeze_schedule.activated"
	ActionFreezeScheduleStartedNow           = "freeze_schedule.started_now"
	ActionFreezeSchedulePlannedUnfreeze      = "freeze_schedule.planned_unfreeze_executed"
	ActionScheduleCreated                    = "schedule.created"
	ActionScheduleDeleted                    = "schedule.deleted"
	ActionScheduleRulesAdded                 = "schedule.rules_added"
	ActionScheduleRuleRemoved                = "schedule.rule_removed"
	ActionScheduleWindowAdded                = "schedule.window_added"
	ActionScheduleWindowRemoved              = "schedule.window_removed"
	ActionScheduleActivated                  = "schedule.activated"
	ActionSchedulePaused                     = "schedule.paused"
	ActionScheduleSuppressed                 = "schedule.suppressed"
	ActionThawExceptionApproved              = "thaw_exception.approved"
	ActionThawExceptionSharedHeadApproved    = "thaw_exception.shared_head_approved"
	ActionUserCreated                        = "user.created"
	ActionUserRolesUpdated                   = "user.roles_updated"
	ActionUserDisabled                       = "user.disabled"
	ActionUserEnabled                        = "user.enabled"
	ActionUserPasswordChanged                = "user.password_changed"
	ActionUserPasswordReset                  = "user.password_reset"
	ActionUserPasswordRecoveryIssued         = "user.password_recovery_issued"
	ActionUserPasswordRecoveryCompleted      = "user.password_recovery_completed"

	ActorKindPasswordRecoveryLink = "recovery_link"

	SubjectTypeRepository    = "repository"
	SubjectTypeSchedule      = "schedule"
	SubjectTypeBranchFreeze  = "branch_freeze"
	SubjectTypeThawException = "thaw_exception"
	SubjectTypeUser          = "user"
)

// KnownActions returns every audit action the application currently writes.
// Presentation layers use this list to make missing curated mappings visible
// in tests when a new action is introduced.
func KnownActions() []string {
	return []string{
		ActionRepositoryCreated,
		ActionRepositoryWebhookSecretConfigured,
		ActionRepositoryStatusTokenConfigured,
		ActionRepositoryOpenPullRequestsSynced,
		ActionRepositoryBranchAdded,
		ActionRepositoryBranchRemoved,
		ActionRepositorySetupCheckRun,
		ActionRepositorySetupDriftDetected,
		ActionRepositoryStatusPostVerified,
		ActionRepositoryStatusPostVerifyFailed,
		ActionRepositoryEnforcementActivated,
		ActionRepositoryEnforcementDeactivated,
		ActionRepositoryEnforcementActivateFail,
		ActionRepositoryEnforcementReconciled,
		ActionRepositoryEnforcementReconcileFail,
		ActionRepositoryEnforcementRecovered,
		ActionRepositoryEnforcementRecoverFail,
		ActionRepositoryRuntimeConvergenceFail,
		ActionRepositoryGrantAdded,
		ActionRepositoryGrantRevoked,
		ActionBranchFreezeCreated,
		ActionBranchFreezeEnded,
		ActionBranchFreezeCancelled,
		ActionBranchFreezePlannedUnfreeze,
		ActionFreezeScheduleCreated,
		ActionFreezeScheduleUpdated,
		ActionFreezeScheduleCancelled,
		ActionFreezeScheduleActivated,
		ActionFreezeScheduleStartedNow,
		ActionFreezeSchedulePlannedUnfreeze,
		ActionScheduleCreated,
		ActionScheduleDeleted,
		ActionScheduleRulesAdded,
		ActionScheduleRuleRemoved,
		ActionScheduleWindowAdded,
		ActionScheduleWindowRemoved,
		ActionScheduleActivated,
		ActionSchedulePaused,
		ActionScheduleSuppressed,
		ActionThawExceptionApproved,
		ActionThawExceptionSharedHeadApproved,
		ActionUserCreated,
		ActionUserRolesUpdated,
		ActionUserDisabled,
		ActionUserEnabled,
		ActionUserPasswordChanged,
		ActionUserPasswordReset,
		ActionUserPasswordRecoveryIssued,
		ActionUserPasswordRecoveryCompleted,
	}
}

// Repository association for scoped reads.
//
// Bounded read scopes may only receive audit events whose repository can be
// derived safely. Classification is exact: an event associates with a
// repository only when its action is listed in exactly one family below and
// its stored subject_type matches that family's expected subject. User
// actions, unknown actions, mismatched subjects, and unusable IDs derive a
// NULL association, which bounded scopes exclude and repositoryscope.All()
// keeps, so a new action stays admin-only until it is classified here.

// repositorySubjectActions expect subject_type "repository". Their
// repository is details_json.repository_id when that is safely positive;
// otherwise the numeric subject id. repository.created and the
// repository-grant events store no repository_id detail, so the subject
// fallback is required.
var repositorySubjectActions = []string{
	ActionRepositoryCreated,
	ActionRepositoryWebhookSecretConfigured,
	ActionRepositoryStatusTokenConfigured,
	ActionRepositoryOpenPullRequestsSynced,
	ActionRepositoryBranchAdded,
	ActionRepositoryBranchRemoved,
	ActionRepositorySetupCheckRun,
	ActionRepositorySetupDriftDetected,
	ActionRepositoryStatusPostVerified,
	ActionRepositoryStatusPostVerifyFailed,
	ActionRepositoryEnforcementActivated,
	ActionRepositoryEnforcementDeactivated,
	ActionRepositoryEnforcementActivateFail,
	ActionRepositoryEnforcementReconciled,
	ActionRepositoryEnforcementReconcileFail,
	ActionRepositoryEnforcementRecovered,
	ActionRepositoryEnforcementRecoverFail,
	ActionRepositoryRuntimeConvergenceFail,
	ActionRepositoryGrantAdded,
	ActionRepositoryGrantRevoked,
}

// branchFreezeSubjectActions expect subject_type "branch_freeze". The
// subject id is the freeze id, never a repository id, so only
// details_json.repository_id may associate.
var branchFreezeSubjectActions = []string{
	ActionBranchFreezeCreated,
	ActionBranchFreezeEnded,
	ActionBranchFreezeCancelled,
	ActionBranchFreezePlannedUnfreeze,
	ActionFreezeScheduleCreated,
	ActionFreezeScheduleUpdated,
	ActionFreezeScheduleCancelled,
	ActionFreezeScheduleActivated,
	ActionFreezeScheduleStartedNow,
	ActionFreezeSchedulePlannedUnfreeze,
}

// scheduleSubjectActions expect subject_type "schedule". The subject id is
// the schedule id, so only details_json.repository_id may associate.
var scheduleSubjectActions = []string{
	ActionScheduleCreated,
	ActionScheduleDeleted,
	ActionScheduleRulesAdded,
	ActionScheduleRuleRemoved,
	ActionScheduleWindowAdded,
	ActionScheduleWindowRemoved,
	ActionScheduleActivated,
	ActionSchedulePaused,
	ActionScheduleSuppressed,
}

// thawExceptionSubjectActions expect subject_type "thaw_exception". Subject
// ids — including shared-head ids — are never repository ids, so only
// details_json.repository_id may associate.
var thawExceptionSubjectActions = []string{
	ActionThawExceptionApproved,
	ActionThawExceptionSharedHeadApproved,
}

// User actions are deliberately absent from every family: account
// administration stays admin-only even when details carry a repository_id.

// scopedAuditEventsSQL derives a nullable associated_repository_id for
// every audit event entirely inside SQL, so read scopes filter before
// ordering, limits, offsets, and counts. Every JSON operation is guarded by
// nested CASE expressions — SQLite's only guaranteed short-circuit — so
// malformed historical rows derive NULL instead of failing the query. The
// accepted detail forms are deliberately narrower than a general JSON
// number parser: a JSON int64, or a positive canonical base-10 string
// trimmed of ordinary whitespace with no sign, leading zeros, or exotic
// whitespace. Production writers emit canonical decimal IDs, and
// under-association fails closed while over-association would leak events.
var scopedAuditEventsSQL = buildScopedAuditEventsSQL()

func buildScopedAuditEventsSQL() string {
	const columns = "id, actor_user_id, action, subject_type, subject_id, details_json, created_at"
	// Ordinary whitespace tolerated around a numeric string: space, tab,
	// line feed, carriage return, matching the strings.TrimSpace forms the
	// web renderer accepts for common historical rows.
	const whitespace = "' ' || char(9) || char(10) || char(13)"
	// A canonical positive base-10 int64: first digit 1-9, digits only, and
	// unchanged by a CAST round-trip, which rejects int64 overflow because
	// SQLite CAST saturates instead of failing.
	canonical := func(column string) string {
		return column + " GLOB '[1-9]*' AND " + column + " NOT GLOB '*[^0-9]*'" +
			" AND CAST(CAST(" + column + " AS INTEGER) AS TEXT) = " + column
	}
	return `
WITH audit_event_objects AS (
	SELECT ` + columns + `,
		CASE WHEN json_valid(details_json) THEN
			CASE WHEN json_type(details_json) = 'object' THEN details_json END
		END AS details_object
	FROM audit_events
),
audit_event_detail_counts AS (
	SELECT ` + columns + `, details_object,
		-- Multiple repository_id keys are ambiguous. Carry the count through
		-- every later CTE so repository-subject events cannot fall back to
		-- subject_id after duplicate details are rejected.
		CASE WHEN details_object IS NOT NULL THEN
			(SELECT COUNT(*) FROM json_each(details_object) WHERE json_each.key = 'repository_id')
		END AS repository_id_key_count
	FROM audit_event_objects
),
audit_event_detail_values AS (
	SELECT ` + columns + `, repository_id_key_count,
		CASE WHEN details_object IS NOT NULL THEN
			CASE WHEN repository_id_key_count = 1
			THEN json_extract(details_object, '$.repository_id') END
		END AS detail_value,
		CASE WHEN details_object IS NOT NULL THEN
			CASE WHEN repository_id_key_count = 1
			THEN json_type(details_object, '$.repository_id') END
		END AS detail_type
	FROM audit_event_detail_counts
),
audit_event_texts AS (
	SELECT ` + columns + `, repository_id_key_count, detail_value, detail_type,
		CASE WHEN detail_type = 'text' THEN trim(detail_value, ` + whitespace + `) END AS detail_text,
		trim(subject_id, ` + whitespace + `) AS subject_text
	FROM audit_event_detail_values
),
audit_event_ids AS (
	SELECT ` + columns + `, repository_id_key_count,
		CASE
			WHEN detail_type = 'integer' AND typeof(detail_value) = 'integer' AND detail_value > 0
				THEN detail_value
			WHEN ` + canonical("detail_text") + `
				THEN CAST(detail_text AS INTEGER)
		END AS detail_repository_id,
		CASE WHEN ` + canonical("subject_text") + ` THEN CAST(subject_text AS INTEGER) END AS subject_repository_id
	FROM audit_event_texts
),
scoped_audit_events AS (
	SELECT ` + columns + `,
		CASE
			WHEN subject_type = ` + sqlQuotedText(SubjectTypeRepository) + ` AND action IN (` + sqlQuotedList(repositorySubjectActions) + `)
				THEN CASE WHEN repository_id_key_count > 1 THEN NULL
					ELSE COALESCE(detail_repository_id, subject_repository_id) END
			WHEN subject_type = ` + sqlQuotedText(SubjectTypeBranchFreeze) + ` AND action IN (` + sqlQuotedList(branchFreezeSubjectActions) + `)
				THEN detail_repository_id
			WHEN subject_type = ` + sqlQuotedText(SubjectTypeSchedule) + ` AND action IN (` + sqlQuotedList(scheduleSubjectActions) + `)
				THEN detail_repository_id
			WHEN subject_type = ` + sqlQuotedText(SubjectTypeThawException) + ` AND action IN (` + sqlQuotedList(thawExceptionSubjectActions) + `)
				THEN detail_repository_id
		END AS associated_repository_id
	FROM audit_event_ids
)
`
}

// sqlQuotedText embeds a code-owned constant as a SQL text literal. Values
// come only from package constants, never user input; quotes are doubled
// defensively anyway.
func sqlQuotedText(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func sqlQuotedList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = sqlQuotedText(value)
	}
	return strings.Join(quoted, ", ")
}

type Event struct {
	ID          int64
	ActorUserID *int64
	Action      string
	SubjectType string
	SubjectID   string
	DetailsJSON string
	CreatedAt   time.Time
}

type database interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type Store struct {
	db  database
	now func() time.Time
}

func NewStore(db *sql.DB) *Store {
	if db == nil {
		return newStore(nil)
	}
	return newStore(db)
}

func NewStoreTx(tx *sql.Tx) *Store {
	if tx == nil {
		return newStore(nil)
	}
	return newStore(tx)
}

func newStore(db database) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) Record(ctx context.Context, event Event) error {
	if s == nil || s.db == nil {
		return errors.New("audit store has no database")
	}
	event = normalizeEvent(event, s.now())
	if err := validateEvent(event); err != nil {
		return err
	}

	var actorUserID any
	if event.ActorUserID != nil {
		actorUserID = *event.ActorUserID
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO audit_events(actor_user_id, action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?, ?)`, actorUserID, event.Action, event.SubjectType, event.SubjectID, event.DetailsJSON, event.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

func (s *Store) List(ctx context.Context, limit int) ([]Event, error) {
	return s.ListForScope(ctx, repositoryscope.All(), limit)
}

// ListForScope lists the newest audit events visible through the caller's
// read scope. The scope filters on the SQL-derived repository association
// before ordering and the limit, so invisible rows never consume result
// slots. repositoryscope.All() preserves the complete trail — user,
// unknown, unassociated, and malformed rows included — while bounded scopes
// fail closed to events with a safely derived repository.
func (s *Store) ListForScope(ctx context.Context, scope repositoryscope.ReadScope, limit int) ([]Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	predicate, scopeArgs := scope.SQLPredicate("associated_repository_id")

	rows, err := s.db.QueryContext(ctx, scopedAuditEventsSQL+`
SELECT id, actor_user_id, action, subject_type, subject_id, details_json, created_at
FROM scoped_audit_events
WHERE `+predicate+`
ORDER BY julianday(created_at) DESC, id DESC
LIMIT ?`, append(append([]any{}, scopeArgs...), limit)...)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit events rows: %w", err)
	}
	return events, nil
}

// ListPage returns one page of audit events newest first plus the total
// number of matching events. A non-empty actions list restricts the result
// to those exact action names; nil or empty means all actions.
func (s *Store) ListPage(ctx context.Context, actions []string, offset, limit int) ([]Event, int, error) {
	return s.ListPageForScope(ctx, repositoryscope.All(), actions, offset, limit)
}

// ListPageForScope returns one page of the audit events visible through the
// caller's read scope, newest first, plus the total number of visible
// matching events. The scope and the exact-action filter intersect inside
// the same SQL WHERE before ordering and pagination, and the count query
// shares identical conditions and argument order, so rows and total always
// agree and an action filter can never widen past the scope.
func (s *Store) ListPageForScope(ctx context.Context, scope repositoryscope.ReadScope, actions []string, offset, limit int) ([]Event, int, error) {
	if s == nil || s.db == nil {
		return nil, 0, errors.New("audit store has no database")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	predicate, filterArgs := scope.SQLPredicate("associated_repository_id")
	where := "WHERE " + predicate
	if len(actions) > 0 {
		where += " AND action IN (?" + strings.Repeat(", ?", len(actions)-1) + ")"
		for _, action := range actions {
			filterArgs = append(filterArgs, action)
		}
	}

	var total int
	if err := s.db.QueryRowContext(ctx, scopedAuditEventsSQL+"SELECT COUNT(*) FROM scoped_audit_events "+where, filterArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}

	args := append(append([]any{}, filterArgs...), limit, offset)
	rows, err := s.db.QueryContext(ctx, scopedAuditEventsSQL+`
SELECT id, actor_user_id, action, subject_type, subject_id, details_json, created_at
FROM scoped_audit_events
`+where+`
ORDER BY julianday(created_at) DESC, id DESC
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit events page: %w", err)
	}
	defer rows.Close()

	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list audit events page rows: %w", err)
	}
	return events, total, nil
}

func normalizeEvent(event Event, now time.Time) Event {
	if event.DetailsJSON == "" {
		event.DetailsJSON = "{}"
	}
	event.CreatedAt = now.UTC()
	return event
}

func validateEvent(event Event) error {
	if event.Action == "" {
		return errors.New("audit event action is required")
	}
	if event.SubjectType == "" {
		return errors.New("audit event subject type is required")
	}
	if event.SubjectID == "" {
		return errors.New("audit event subject id is required")
	}
	if !json.Valid([]byte(event.DetailsJSON)) {
		return errors.New("audit event details must be valid JSON")
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanEvent(row scanner) (Event, error) {
	var event Event
	var actorUserID sql.NullInt64
	var createdAt string
	if err := row.Scan(&event.ID, &actorUserID, &event.Action, &event.SubjectType, &event.SubjectID, &event.DetailsJSON, &createdAt); err != nil {
		return Event{}, fmt.Errorf("scan audit event: %w", err)
	}
	if actorUserID.Valid {
		id := actorUserID.Int64
		event.ActorUserID = &id
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return Event{}, fmt.Errorf("parse audit event created_at: %w", err)
	}
	event.CreatedAt = parsedCreatedAt
	return event, nil
}
