package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

// ErrRuleNotFound reports a rule id with no row under the given schedule; web
// handlers map it to 404 exactly like ErrNotFound.
var ErrRuleNotFound = errors.New("schedule rule not found")

// End-day modes for AddRulesParams. "same" and "next" are relative to each
// selected start weekday so one submission like "Mon–Fri 18:00 → next day
// 08:00" yields five rules; "specific" pins every rule to one end weekday.
const (
	EndDaySame     = "same"
	EndDayNext     = "next"
	EndDaySpecific = "specific"
)

// AddRulesParams carries one rule-form submission: one or more start weekdays
// sharing the same start time, end time, and end-day relation.
type AddRulesParams struct {
	ScheduleID int64
	Weekdays   []time.Weekday
	StartTime  string
	EndTime    string
	EndDayMode string
	// EndWeekday applies only when EndDayMode is EndDaySpecific.
	EndWeekday time.Weekday
}

// ListRules returns a schedule's weekly rules ordered Monday-first by start,
// matching how the rules card and the preview timeline present a week.
func (s *Store) ListRules(ctx context.Context, scheduleID int64) ([]domain.ScheduleWeeklyRule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, schedule_id, start_weekday, start_time, end_weekday, end_time, created_at
FROM schedule_weekly_rules WHERE schedule_id = ?
ORDER BY (start_weekday + 6) % 7, start_time, (end_weekday + 6) % 7, end_time`, scheduleID)
	if err != nil {
		return nil, fmt.Errorf("list schedule rules: %w", err)
	}
	defer rows.Close()
	rules := make([]domain.ScheduleWeeklyRule, 0)
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule rule: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schedule rules: %w", err)
	}
	return rules, nil
}

// AddRules validates and inserts one rule per selected weekday in a single
// INSERT statement, so a duplicate anywhere in the submission rejects the
// whole submission — no partial half-applied rule sets.
func (s *Store) AddRules(ctx context.Context, params AddRulesParams) ([]domain.ScheduleWeeklyRule, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule store has no database")
	}
	params = normalizeAddRulesParams(params)
	if err := validateAddRulesParams(params); err != nil {
		return nil, err
	}
	schedule, err := s.Get(ctx, params.ScheduleID)
	if err != nil {
		return nil, err
	}
	if schedule.Kind != domain.ScheduleKindWeekly {
		return nil, ValidationError{Message: "weekly rules can only be added to a weekly schedule"}
	}

	nowText := s.now().UTC().Format(sqliteTimestampFormat)
	placeholders := make([]string, 0, len(params.Weekdays))
	args := make([]any, 0, len(params.Weekdays)*6)
	for _, weekday := range params.Weekdays {
		end := ruleEndWeekday(weekday, params)
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?)")
		args = append(args, params.ScheduleID, int(weekday), params.StartTime, int(end), params.EndTime, nowText)
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO schedule_weekly_rules(schedule_id, start_weekday, start_time, end_weekday, end_time, created_at)
VALUES `+strings.Join(placeholders, ", "), args...)
	if err != nil {
		if isDuplicateRuleError(err) {
			return nil, ValidationError{Message: "an identical rule already exists on this schedule"}
		}
		return nil, fmt.Errorf("add schedule rules: %w", err)
	}

	added := make([]domain.ScheduleWeeklyRule, 0, len(params.Weekdays))
	for _, weekday := range params.Weekdays {
		end := ruleEndWeekday(weekday, params)
		row := s.db.QueryRowContext(ctx, `
SELECT id, schedule_id, start_weekday, start_time, end_weekday, end_time, created_at
FROM schedule_weekly_rules
WHERE schedule_id = ? AND start_weekday = ? AND start_time = ? AND end_weekday = ? AND end_time = ?`,
			params.ScheduleID, int(weekday), params.StartTime, int(end), params.EndTime)
		rule, err := scanRule(row)
		if err != nil {
			return nil, fmt.Errorf("load added schedule rule: %w", err)
		}
		added = append(added, rule)
	}
	return added, nil
}

// DeleteRule hard-deletes one rule and returns the deleted row so the caller
// can audit what was removed. The scheduleID scope stops a valid rule id from
// being deleted through another schedule's URL.
func (s *Store) DeleteRule(ctx context.Context, scheduleID, ruleID int64) (domain.ScheduleWeeklyRule, error) {
	if s == nil || s.db == nil {
		return domain.ScheduleWeeklyRule{}, errors.New("schedule store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, schedule_id, start_weekday, start_time, end_weekday, end_time, created_at
FROM schedule_weekly_rules WHERE id = ? AND schedule_id = ?`, ruleID, scheduleID)
	rule, err := scanRule(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ScheduleWeeklyRule{}, ErrRuleNotFound
	}
	if err != nil {
		return domain.ScheduleWeeklyRule{}, fmt.Errorf("load schedule rule: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM schedule_weekly_rules WHERE id = ? AND schedule_id = ?`, ruleID, scheduleID)
	if err != nil {
		return domain.ScheduleWeeklyRule{}, fmt.Errorf("delete schedule rule: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.ScheduleWeeklyRule{}, fmt.Errorf("deleted schedule rule rows: %w", err)
	}
	if affected == 0 {
		return domain.ScheduleWeeklyRule{}, ErrRuleNotFound
	}
	return rule, nil
}

func normalizeAddRulesParams(params AddRulesParams) AddRulesParams {
	params.StartTime = strings.TrimSpace(params.StartTime)
	params.EndTime = strings.TrimSpace(params.EndTime)
	params.EndDayMode = strings.TrimSpace(params.EndDayMode)
	return params
}

func validateAddRulesParams(params AddRulesParams) error {
	if params.ScheduleID <= 0 {
		return ValidationError{Message: "missing required fields: schedule"}
	}
	if len(params.Weekdays) == 0 {
		return ValidationError{Message: "select at least one day"}
	}
	seen := make(map[time.Weekday]bool, len(params.Weekdays))
	for _, weekday := range params.Weekdays {
		if weekday < time.Sunday || weekday > time.Saturday {
			return ValidationError{Message: "day must be a weekday between Sunday and Saturday"}
		}
		if seen[weekday] {
			return ValidationError{Message: "each day can only be selected once"}
		}
		seen[weekday] = true
	}
	startMinutes, ok := parseWallMinutes(params.StartTime)
	if !ok {
		return ValidationError{Message: "start time must be a valid HH:MM time"}
	}
	endMinutes, ok := parseWallMinutes(params.EndTime)
	if !ok {
		return ValidationError{Message: "end time must be a valid HH:MM time"}
	}
	switch params.EndDayMode {
	case EndDaySame, EndDayNext:
	case EndDaySpecific:
		if params.EndWeekday < time.Sunday || params.EndWeekday > time.Saturday {
			return ValidationError{Message: "end day must be a weekday between Sunday and Saturday"}
		}
	default:
		return ValidationError{Message: "end day must be same day, next day, or a specific day"}
	}
	for _, weekday := range params.Weekdays {
		end := ruleEndWeekday(weekday, params)
		if weekMinutes(weekday, startMinutes) == weekMinutes(end, endMinutes) {
			return ValidationError{Message: "a rule's end must differ from its start"}
		}
	}
	return nil
}

func ruleEndWeekday(start time.Weekday, params AddRulesParams) time.Weekday {
	switch params.EndDayMode {
	case EndDaySame:
		return start
	case EndDayNext:
		return (start + 1) % 7
	default:
		return params.EndWeekday
	}
}

// parseWallMinutes parses a strict zero-padded "HH:MM" wall clock into
// minutes since midnight.
func parseWallMinutes(value string) (int, bool) {
	if len(value) != 5 || value[2] != ':' {
		return 0, false
	}
	for _, i := range []int{0, 1, 3, 4} {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
	}
	hours := int(value[0]-'0')*10 + int(value[1]-'0')
	minutes := int(value[3]-'0')*10 + int(value[4]-'0')
	if hours > 23 || minutes > 59 {
		return 0, false
	}
	return hours*60 + minutes, true
}

// weekMinutes positions a weekday+wall-time inside one week. It is the basis
// of the wrap encoding: a rule whose end week-minute is at or before its
// start week-minute wraps into the following week.
func weekMinutes(weekday time.Weekday, minutes int) int {
	return int(weekday)*24*60 + minutes
}

// RuleWrapDays is the number of days from a rule's start weekday to its end
// weekday, honoring the wrap encoding: 0 = same day, 1 = next day, up to 7
// for a rule that ends the same weekday at or before its start time.
func RuleWrapDays(rule domain.ScheduleWeeklyRule) int {
	days := int(rule.EndWeekday) - int(rule.StartWeekday)
	startMinutes, _ := parseWallMinutes(rule.StartTime)
	endMinutes, _ := parseWallMinutes(rule.EndTime)
	if weekMinutes(rule.EndWeekday, endMinutes) <= weekMinutes(rule.StartWeekday, startMinutes) {
		days += 7
	}
	return days
}

func isDuplicateRuleError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: schedule_weekly_rules.")
}

func scanRule(row scanner) (domain.ScheduleWeeklyRule, error) {
	var rule domain.ScheduleWeeklyRule
	var startWeekday, endWeekday int
	var createdAt string
	if err := row.Scan(&rule.ID, &rule.ScheduleID, &startWeekday, &rule.StartTime, &endWeekday, &rule.EndTime, &createdAt); err != nil {
		return domain.ScheduleWeeklyRule{}, err
	}
	rule.StartWeekday = time.Weekday(startWeekday)
	rule.EndWeekday = time.Weekday(endWeekday)
	var err error
	if rule.CreatedAt, err = time.Parse(sqliteTimestampFormat, createdAt); err != nil {
		return domain.ScheduleWeeklyRule{}, fmt.Errorf("parse schedule rule created_at: %w", err)
	}
	return rule, nil
}
