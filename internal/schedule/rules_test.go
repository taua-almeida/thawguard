package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestStoreAddRulesInsertsOneRulePerDayOrderedMondayFirst(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestWeeklySchedule(t, ctx, database)
	store := NewStore(database)

	added, err := store.AddRules(ctx, AddRulesParams{
		ScheduleID: created.ID,
		Weekdays:   []time.Weekday{time.Monday, time.Tuesday, time.Friday},
		StartTime:  "18:00",
		EndTime:    "08:00",
		EndDayMode: EndDayNext,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(added))
	}
	for i, want := range []struct{ start, end time.Weekday }{
		{time.Monday, time.Tuesday}, {time.Tuesday, time.Wednesday}, {time.Friday, time.Saturday},
	} {
		rule := added[i]
		if rule.ID == 0 || rule.ScheduleID != created.ID {
			t.Fatalf("rule %d not persisted for schedule: %+v", i, rule)
		}
		if rule.StartWeekday != want.start || rule.EndWeekday != want.end || rule.StartTime != "18:00" || rule.EndTime != "08:00" {
			t.Fatalf("unexpected rule %d: %+v", i, rule)
		}
	}

	// A Sunday rule sorts last: the list is Monday-first like the rules card.
	if _, err := store.AddRules(ctx, AddRulesParams{
		ScheduleID: created.ID,
		Weekdays:   []time.Weekday{time.Sunday},
		StartTime:  "09:00",
		EndTime:    "17:00",
		EndDayMode: EndDaySame,
	}); err != nil {
		t.Fatal(err)
	}
	rules, err := store.ListRules(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	gotOrder := []time.Weekday{rules[0].StartWeekday, rules[1].StartWeekday, rules[2].StartWeekday, rules[3].StartWeekday}
	wantOrder := []time.Weekday{time.Monday, time.Tuesday, time.Friday, time.Sunday}
	for i := range wantOrder {
		if gotOrder[i] != wantOrder[i] {
			t.Fatalf("expected Monday-first order %v, got %v", wantOrder, gotOrder)
		}
	}
}

func TestStoreAddRulesValidation(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestWeeklySchedule(t, ctx, database)
	store := NewStore(database)

	valid := AddRulesParams{
		ScheduleID: created.ID,
		Weekdays:   []time.Weekday{time.Monday},
		StartTime:  "18:00",
		EndTime:    "08:00",
		EndDayMode: EndDayNext,
	}
	cases := []struct {
		name   string
		mutate func(params AddRulesParams) AddRulesParams
	}{
		{"no days", func(p AddRulesParams) AddRulesParams { p.Weekdays = nil; return p }},
		{"duplicate day", func(p AddRulesParams) AddRulesParams {
			p.Weekdays = []time.Weekday{time.Monday, time.Monday}
			return p
		}},
		{"day out of range", func(p AddRulesParams) AddRulesParams { p.Weekdays = []time.Weekday{7}; return p }},
		{"unpadded start time", func(p AddRulesParams) AddRulesParams { p.StartTime = "8:00"; return p }},
		{"impossible end time", func(p AddRulesParams) AddRulesParams { p.EndTime = "24:00"; return p }},
		{"empty end time", func(p AddRulesParams) AddRulesParams { p.EndTime = ""; return p }},
		{"unknown end day mode", func(p AddRulesParams) AddRulesParams { p.EndDayMode = "eventually"; return p }},
		{"specific end day out of range", func(p AddRulesParams) AddRulesParams {
			p.EndDayMode = EndDaySpecific
			p.EndWeekday = -1
			return p
		}},
		{"zero-length rule", func(p AddRulesParams) AddRulesParams {
			p.EndDayMode = EndDaySame
			p.EndTime = p.StartTime
			return p
		}},
	}
	for _, tc := range cases {
		if _, err := store.AddRules(ctx, tc.mutate(valid)); !IsValidationError(err) {
			t.Fatalf("%s: expected validation error, got %v", tc.name, err)
		}
	}
	rules, err := store.ListRules(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected no rules after rejected submissions, got %+v", rules)
	}
}

func TestStoreAddRulesRejectsDuplicatesAtomically(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestWeeklySchedule(t, ctx, database)
	store := NewStore(database)

	params := AddRulesParams{
		ScheduleID: created.ID,
		Weekdays:   []time.Weekday{time.Monday},
		StartTime:  "18:00",
		EndTime:    "08:00",
		EndDayMode: EndDayNext,
	}
	if _, err := store.AddRules(ctx, params); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddRules(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected duplicate validation error, got %v", err)
	}

	// A submission that is only partially duplicated must not half-apply:
	// Tuesday shares the statement with the duplicate Monday and is rejected
	// with it.
	params.Weekdays = []time.Weekday{time.Tuesday, time.Monday}
	if _, err := store.AddRules(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected duplicate validation error, got %v", err)
	}
	rules, err := store.ListRules(ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].StartWeekday != time.Monday {
		t.Fatalf("expected only the original Monday rule, got %+v", rules)
	}
}

func TestStoreAddRulesRequiresExistingWeeklySchedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	dated, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Christmas shutdown", Kind: domain.ScheduleKindDated, Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	params := AddRulesParams{
		ScheduleID: dated.ID,
		Weekdays:   []time.Weekday{time.Monday},
		StartTime:  "18:00",
		EndTime:    "08:00",
		EndDayMode: EndDayNext,
	}
	if _, err := store.AddRules(ctx, params); !IsValidationError(err) {
		t.Fatalf("expected validation error for dated schedule, got %v", err)
	}
	params.ScheduleID = 12345
	if _, err := store.AddRules(ctx, params); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing schedule, got %v", err)
	}
}

func TestStoreDeleteRuleIsScopedToItsSchedule(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	repo := createTestRepository(t, ctx, database)
	store := NewStore(database)

	first, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Nightly release lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Create(ctx, CreateParams{RepositoryID: repo.ID, Branch: "main", Name: "Weekend lock", Kind: domain.ScheduleKindWeekly, Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	added, err := store.AddRules(ctx, AddRulesParams{ScheduleID: first.ID, Weekdays: []time.Weekday{time.Monday}, StartTime: "18:00", EndTime: "08:00", EndDayMode: EndDayNext})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.DeleteRule(ctx, second.ID, added[0].ID); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("expected ErrRuleNotFound through the wrong schedule, got %v", err)
	}
	removed, err := store.DeleteRule(ctx, first.ID, added[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if removed.ID != added[0].ID || removed.StartWeekday != time.Monday {
		t.Fatalf("expected the deleted Monday rule back, got %+v", removed)
	}
	if _, err := store.DeleteRule(ctx, first.ID, added[0].ID); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("expected ErrRuleNotFound on double delete, got %v", err)
	}
}

func TestScheduleDeleteCascadesRules(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestWeeklySchedule(t, ctx, database)
	store := NewStore(database)

	if _, err := store.AddRules(ctx, AddRulesParams{ScheduleID: created.ID, Weekdays: []time.Weekday{time.Monday, time.Friday}, StartTime: "18:00", EndTime: "08:00", EndDayMode: EndDayNext}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Delete(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	var remaining int64
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM schedule_weekly_rules`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("expected rules to cascade with their schedule, got %d rows", remaining)
	}
}

func TestServiceAddRulesRecordsOneAuditEventPerSubmission(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestWeeklySchedule(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	added, err := service.AddRules(ctx, AddRulesParams{
		ScheduleID: created.ID,
		Weekdays:   []time.Weekday{time.Monday, time.Tuesday, time.Wednesday},
		StartTime:  "18:00",
		EndTime:    "08:00",
		EndDayMode: EndDayNext,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(added))
	}
	details := assertSingleRuleAuditEvent(t, ctx, database, audit.ActionScheduleRulesAdded, created.ID)
	if details["days"] != "Mon, Tue, Wed" || details["start_time"] != "18:00" || details["end_time"] != "08:00" || details["end_day"] != "next day" {
		t.Fatalf("unexpected rules_added details: %+v", details)
	}

	if _, err := service.DeleteRule(ctx, created.ID, added[0].ID, actor); err != nil {
		t.Fatal(err)
	}
	details = assertSingleRuleAuditEvent(t, ctx, database, audit.ActionScheduleRuleRemoved, created.ID)
	if details["days"] != "Mon" || details["end_day"] != "next day" {
		t.Fatalf("unexpected rule_removed details: %+v", details)
	}
}

func TestServiceRejectedRuleSubmissionRecordsNoAudit(t *testing.T) {
	ctx := context.Background()
	database := newTestDB(t, ctx)
	created := createTestWeeklySchedule(t, ctx, database)
	service := NewService(database)
	actor := domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: "admin"}

	if _, err := service.AddRules(ctx, AddRulesParams{ScheduleID: created.ID, StartTime: "18:00", EndTime: "08:00", EndDayMode: EndDayNext}, actor); !IsValidationError(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	events, err := audit.NewStore(database).List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == audit.ActionScheduleRulesAdded {
			t.Fatalf("expected no rules_added audit event, got %+v", event)
		}
	}
}

func TestRuleWrapDays(t *testing.T) {
	cases := []struct {
		name string
		rule domain.ScheduleWeeklyRule
		want int
	}{
		{"same day", domain.ScheduleWeeklyRule{StartWeekday: time.Monday, StartTime: "09:00", EndWeekday: time.Monday, EndTime: "17:00"}, 0},
		{"next day", domain.ScheduleWeeklyRule{StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Tuesday, EndTime: "08:00"}, 1},
		{"weekend wrap", domain.ScheduleWeeklyRule{StartWeekday: time.Friday, StartTime: "16:00", EndWeekday: time.Monday, EndTime: "08:00"}, 3},
		{"saturday into sunday", domain.ScheduleWeeklyRule{StartWeekday: time.Saturday, StartTime: "18:00", EndWeekday: time.Sunday, EndTime: "08:00"}, 1},
		{"full week", domain.ScheduleWeeklyRule{StartWeekday: time.Monday, StartTime: "18:00", EndWeekday: time.Monday, EndTime: "08:00"}, 7},
	}
	for _, tc := range cases {
		if got := RuleWrapDays(tc.rule); got != tc.want {
			t.Fatalf("%s: expected %d wrap days, got %d", tc.name, tc.want, got)
		}
	}
}

func TestParseWallMinutes(t *testing.T) {
	valid := map[string]int{"00:00": 0, "09:30": 570, "23:59": 1439}
	for value, want := range valid {
		if got, ok := parseWallMinutes(value); !ok || got != want {
			t.Fatalf("expected %q to parse to %d, got %d ok=%v", value, want, got, ok)
		}
	}
	for _, value := range []string{"", "9:30", "24:00", "12:60", "12-30", "+1:30", "12:3a", "112:30"} {
		if _, ok := parseWallMinutes(value); ok {
			t.Fatalf("expected %q to be rejected", value)
		}
	}
}

func createTestWeeklySchedule(t *testing.T, ctx context.Context, database *sql.DB) domain.Schedule {
	t.Helper()
	repo := createTestRepository(t, ctx, database)
	created, err := NewStore(database).Create(ctx, CreateParams{
		RepositoryID: repo.ID,
		Branch:       "main",
		Name:         "Nightly release lock",
		Kind:         domain.ScheduleKindWeekly,
		Timezone:     "America/Sao_Paulo",
	})
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func assertSingleRuleAuditEvent(t *testing.T, ctx context.Context, database *sql.DB, action string, scheduleID int64) map[string]string {
	t.Helper()
	events, err := audit.NewStore(database).List(ctx, 20)
	if err != nil {
		t.Fatal(err)
	}
	matching := make([]audit.Event, 0, 1)
	for _, event := range events {
		if event.Action == action {
			matching = append(matching, event)
		}
	}
	if len(matching) != 1 {
		t.Fatalf("expected exactly one %s event, got %d", action, len(matching))
	}
	event := matching[0]
	if event.SubjectType != audit.SubjectTypeSchedule || event.SubjectID != strconv.FormatInt(scheduleID, 10) {
		t.Fatalf("unexpected audit subject: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	return details
}
