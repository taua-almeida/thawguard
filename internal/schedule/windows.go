package schedule

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/taua-almeida/thawguard/internal/domain"
)

// ErrWindowNotFound reports a window id with no row under the given schedule;
// web handlers map it to 404 exactly like ErrRuleNotFound.
var ErrWindowNotFound = errors.New("schedule window not found")

// wallDateTimeFormat is the local wall-clock format stored for dated windows.
// It matches the browser's datetime-local input verbatim, and its fixed-width
// zero-padded layout makes lexicographic order chronological order, so the
// store can sort and compare timestamps as text.
const wallDateTimeFormat = "2006-01-02T15:04"

// AddWindowParams carries one window-form submission. StartsAt and EndsAt are
// local wall clocks in the schedule's timezone ("2006-01-02T15:04").
type AddWindowParams struct {
	ScheduleID int64
	Name       string
	StartsAt   string
	EndsAt     string
}

// ListWindows returns a dated schedule's windows ordered by start. Past
// windows are included — rows are kept for occurrence idempotency — and the
// UI filters them out.
func (s *Store) ListWindows(ctx context.Context, scheduleID int64) ([]domain.ScheduleDatedWindow, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("schedule store has no database")
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, schedule_id, name, starts_at, ends_at, created_at
FROM schedule_dated_windows WHERE schedule_id = ?
ORDER BY starts_at, ends_at, name`, scheduleID)
	if err != nil {
		return nil, fmt.Errorf("list schedule windows: %w", err)
	}
	defer rows.Close()
	windows := make([]domain.ScheduleDatedWindow, 0)
	for rows.Next() {
		window, err := scanWindow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan schedule window: %w", err)
		}
		windows = append(windows, window)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schedule windows: %w", err)
	}
	return windows, nil
}

// AddWindow validates and inserts one named date window. A window that has
// already ended is rejected — it would never freeze anything — but a window
// whose start is already past is accepted: coverage begins immediately, and
// the caller surfaces that as a note, not an error.
func (s *Store) AddWindow(ctx context.Context, params AddWindowParams) (domain.ScheduleDatedWindow, error) {
	if s == nil || s.db == nil {
		return domain.ScheduleDatedWindow{}, errors.New("schedule store has no database")
	}
	params = normalizeAddWindowParams(params)
	if err := validateAddWindowParams(params); err != nil {
		return domain.ScheduleDatedWindow{}, err
	}
	schedule, err := s.Get(ctx, params.ScheduleID)
	if err != nil {
		return domain.ScheduleDatedWindow{}, err
	}
	if schedule.Kind != domain.ScheduleKindDated {
		return domain.ScheduleDatedWindow{}, ValidationError{Message: "date windows can only be added to a dated schedule"}
	}
	start, end, err := resolveWindowBounds(schedule, domain.ScheduleDatedWindow{
		ScheduleID: schedule.ID,
		StartsAt:   params.StartsAt,
		EndsAt:     params.EndsAt,
	})
	if err != nil {
		return domain.ScheduleDatedWindow{}, err
	}
	if !end.After(start) {
		// The wall clocks were already ordered; only a DST transition swallowing
		// the whole window can land here, and such a window covers nothing.
		return domain.ScheduleDatedWindow{}, ValidationError{Message: "a window's end must be after its start"}
	}
	if !end.After(s.now()) {
		return domain.ScheduleDatedWindow{}, ValidationError{Message: "this window has already ended, so it would never freeze anything"}
	}

	nowText := s.now().UTC().Format(sqliteTimestampFormat)
	_, err = s.db.ExecContext(ctx, `
INSERT INTO schedule_dated_windows(schedule_id, name, starts_at, ends_at, created_at)
VALUES (?, ?, ?, ?, ?)`, params.ScheduleID, params.Name, params.StartsAt, params.EndsAt, nowText)
	if err != nil {
		if isDuplicateWindowError(err) {
			return domain.ScheduleDatedWindow{}, ValidationError{Message: "a window with this name already exists on this schedule"}
		}
		return domain.ScheduleDatedWindow{}, fmt.Errorf("add schedule window: %w", err)
	}

	row := s.db.QueryRowContext(ctx, `
SELECT id, schedule_id, name, starts_at, ends_at, created_at
FROM schedule_dated_windows WHERE schedule_id = ? AND name = ?`, params.ScheduleID, params.Name)
	window, err := scanWindow(row)
	if err != nil {
		return domain.ScheduleDatedWindow{}, fmt.Errorf("load added schedule window: %w", err)
	}
	return window, nil
}

// DeleteWindow hard-deletes one window and returns the deleted row so the
// caller can audit what was removed. The scheduleID scope stops a valid
// window id from being deleted through another schedule's URL.
func (s *Store) DeleteWindow(ctx context.Context, scheduleID, windowID int64) (domain.ScheduleDatedWindow, error) {
	if s == nil || s.db == nil {
		return domain.ScheduleDatedWindow{}, errors.New("schedule store has no database")
	}
	row := s.db.QueryRowContext(ctx, `
SELECT id, schedule_id, name, starts_at, ends_at, created_at
FROM schedule_dated_windows WHERE id = ? AND schedule_id = ?`, windowID, scheduleID)
	window, err := scanWindow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ScheduleDatedWindow{}, ErrWindowNotFound
	}
	if err != nil {
		return domain.ScheduleDatedWindow{}, fmt.Errorf("load schedule window: %w", err)
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM schedule_dated_windows WHERE id = ? AND schedule_id = ?`, windowID, scheduleID)
	if err != nil {
		return domain.ScheduleDatedWindow{}, fmt.Errorf("delete schedule window: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return domain.ScheduleDatedWindow{}, fmt.Errorf("deleted schedule window rows: %w", err)
	}
	if affected == 0 {
		return domain.ScheduleDatedWindow{}, ErrWindowNotFound
	}
	return window, nil
}

// WindowBounds resolves a window's wall clocks through the schedule's
// timezone into concrete instants, honoring DST transitions the same way
// weekly rules do: a nonexistent wall time shifts forward to the first valid
// instant, a repeated wall time starts at the first occurrence and ends at
// the second. Callers use it for past-window filtering, "Next:" lines, and
// already-started detection.
func WindowBounds(schedule domain.Schedule, window domain.ScheduleDatedWindow) (time.Time, time.Time, error) {
	start, end, err := resolveWindowBounds(schedule, window)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return start, end, nil
}

func resolveWindowBounds(schedule domain.Schedule, window domain.ScheduleDatedWindow) (time.Time, time.Time, error) {
	start, end, _, err := resolveWindowBoundsWithNotes(schedule, window)
	return start, end, err
}

func resolveWindowBoundsWithNotes(schedule domain.Schedule, window domain.ScheduleDatedWindow) (time.Time, time.Time, []DSTNote, error) {
	loc, err := time.LoadLocation(schedule.Timezone)
	if err != nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("load schedule %d timezone %q: %w", schedule.ID, schedule.Timezone, err)
	}
	notes := make([]DSTNote, 0, 2)
	start, startNote, err := resolveWindowBoundary(window.StartsAt, loc, "start", schedule.ID)
	if err != nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("schedule %d window %q start: %w", schedule.ID, window.Name, err)
	}
	if startNote != nil {
		notes = append(notes, *startNote)
	}
	end, endNote, err := resolveWindowBoundary(window.EndsAt, loc, "end", schedule.ID)
	if err != nil {
		return time.Time{}, time.Time{}, nil, fmt.Errorf("schedule %d window %q end: %w", schedule.ID, window.Name, err)
	}
	if endNote != nil {
		notes = append(notes, *endNote)
	}
	return start, end, notes, nil
}

// resolveWindowBoundary parses one stored wall clock and resolves it through
// resolveWall, sharing weekly expansion's DST semantics and note shape.
func resolveWindowBoundary(wall string, loc *time.Location, boundary string, scheduleID int64) (time.Time, *DSTNote, error) {
	year, month, day, minutes, ok := parseWallDateTime(wall)
	if !ok {
		return time.Time{}, nil, fmt.Errorf("invalid wall timestamp %q", wall)
	}
	resolved, note := resolveWall(year, month, day, minutes, loc, boundary, scheduleID)
	return resolved, note, nil
}

// parseWallDateTime parses a strict zero-padded "2006-01-02T15:04" local wall
// clock, rejecting calendar dates that don't exist (e.g. February 30).
func parseWallDateTime(value string) (int, time.Month, int, int, bool) {
	if len(value) != len(wallDateTimeFormat) || value[4] != '-' || value[7] != '-' || value[10] != 'T' {
		return 0, 0, 0, 0, false
	}
	for _, i := range []int{0, 1, 2, 3, 5, 6, 8, 9} {
		if value[i] < '0' || value[i] > '9' {
			return 0, 0, 0, 0, false
		}
	}
	minutes, ok := parseWallMinutes(value[11:])
	if !ok {
		return 0, 0, 0, 0, false
	}
	year := int(value[0]-'0')*1000 + int(value[1]-'0')*100 + int(value[2]-'0')*10 + int(value[3]-'0')
	month := time.Month(int(value[5]-'0')*10 + int(value[6]-'0'))
	day := int(value[8]-'0')*10 + int(value[9]-'0')
	if month < time.January || month > time.December {
		return 0, 0, 0, 0, false
	}
	normalized := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	if normalized.Year() != year || normalized.Month() != month || normalized.Day() != day {
		return 0, 0, 0, 0, false
	}
	return year, month, day, minutes, true
}

func normalizeAddWindowParams(params AddWindowParams) AddWindowParams {
	params.Name = strings.TrimSpace(params.Name)
	params.StartsAt = strings.TrimSpace(params.StartsAt)
	params.EndsAt = strings.TrimSpace(params.EndsAt)
	return params
}

func validateAddWindowParams(params AddWindowParams) error {
	if params.ScheduleID <= 0 {
		return ValidationError{Message: "missing required fields: schedule"}
	}
	missing := make([]string, 0, 3)
	if params.Name == "" {
		missing = append(missing, "name")
	}
	if params.StartsAt == "" {
		missing = append(missing, "start")
	}
	if params.EndsAt == "" {
		missing = append(missing, "end")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return ValidationError{Message: fmt.Sprintf("missing required fields: %s", strings.Join(missing, ", "))}
	}
	if utf8.RuneCountInString(params.Name) > nameMaxLength {
		return ValidationError{Message: "window name must be 100 characters or fewer"}
	}
	if containsControlCharacters(params.Name) {
		return ValidationError{Message: "window name contains unsupported control characters"}
	}
	if _, _, _, _, ok := parseWallDateTime(params.StartsAt); !ok {
		return ValidationError{Message: "start must be a valid date and time"}
	}
	if _, _, _, _, ok := parseWallDateTime(params.EndsAt); !ok {
		return ValidationError{Message: "end must be a valid date and time"}
	}
	// The fixed-width format makes string order chronological order.
	if params.EndsAt <= params.StartsAt {
		return ValidationError{Message: "a window's end must be after its start"}
	}
	return nil
}

func isDuplicateWindowError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: schedule_dated_windows.")
}

func scanWindow(row scanner) (domain.ScheduleDatedWindow, error) {
	var window domain.ScheduleDatedWindow
	var createdAt string
	if err := row.Scan(&window.ID, &window.ScheduleID, &window.Name, &window.StartsAt, &window.EndsAt, &createdAt); err != nil {
		return domain.ScheduleDatedWindow{}, err
	}
	var err error
	if window.CreatedAt, err = time.Parse(sqliteTimestampFormat, createdAt); err != nil {
		return domain.ScheduleDatedWindow{}, fmt.Errorf("parse schedule window created_at: %w", err)
	}
	return window, nil
}
