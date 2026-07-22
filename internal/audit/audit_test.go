package audit

import (
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/db"
	"github.com/taua-almeida/thawguard/internal/repositoryscope"
)

func TestStoreRecordsAndListsAuditEvents(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return createdAt }
	actorUserID := int64(42)
	createdAtText := createdAt.Format(time.RFC3339Nano)
	_, err := store.db.ExecContext(ctx, `
INSERT INTO users(id, email, display_name, password_hash, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)`, actorUserID, "admin@example.test", "Admin", "hash", "admin", createdAtText, createdAtText)
	if err != nil {
		t.Fatal(err)
	}

	err = store.Record(ctx, Event{
		ActorUserID: &actorUserID,
		Action:      ActionRepositoryCreated,
		SubjectType: SubjectTypeRepository,
		SubjectID:   "7",
		DetailsJSON: `{"forge":"forgejo","full_name":"taua-almeida/thawguard"}`,
		CreatedAt:   createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	event := events[0]
	if event.ID == 0 {
		t.Fatal("expected audit event id")
	}
	if event.ActorUserID == nil || *event.ActorUserID != actorUserID {
		t.Fatalf("unexpected actor user id: %+v", event.ActorUserID)
	}
	if event.Action != ActionRepositoryCreated {
		t.Fatalf("unexpected action: %q", event.Action)
	}
	if event.SubjectType != SubjectTypeRepository || event.SubjectID != "7" {
		t.Fatalf("unexpected subject: %s/%s", event.SubjectType, event.SubjectID)
	}
	if !event.CreatedAt.Equal(createdAt) {
		t.Fatalf("expected created_at %s, got %s", createdAt, event.CreatedAt)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["full_name"] != "taua-almeida/thawguard" {
		t.Fatalf("unexpected details JSON: %s", event.DetailsJSON)
	}
}

func TestStoreDefaultsDetailsAndCreatedAt(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return createdAt }

	err := store.Record(ctx, Event{
		Action:      "test.action",
		SubjectType: "test_subject",
		SubjectID:   "123",
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	if events[0].DetailsJSON != "{}" {
		t.Fatalf("expected default details JSON, got %q", events[0].DetailsJSON)
	}
	if !events[0].CreatedAt.Equal(createdAt) {
		t.Fatalf("expected authoritative created_at %s, got %s", createdAt, events[0].CreatedAt)
	}
	if events[0].ActorUserID != nil {
		t.Fatalf("expected nil actor user id, got %+v", events[0].ActorUserID)
	}
}

func TestStoreListsNewestFirstWithStableIDOrdering(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	older := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	newer := older.Add(time.Second)

	insertStoredEvent(t, ctx, store, "older", older)
	insertStoredEvent(t, ctx, store, "newer-first", newer)
	insertStoredEvent(t, ctx, store, "newer-second", newer)

	events, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"newer-second", "newer-first", "older"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i := range want {
		if events[i].SubjectID != want[i] {
			t.Fatalf("event %d: expected subject %q, got %q", i, want[i], events[i].SubjectID)
		}
	}
}

func TestStoreListHonorsBoundedLimit(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	createdAt := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		insertStoredEvent(t, ctx, store, strconv.Itoa(i+1), createdAt.Add(time.Duration(i)*time.Second))
	}

	events, err := store.List(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].SubjectID != "5" || events[1].SubjectID != "4" {
		t.Fatalf("expected newest two events, got %+v", events)
	}
}

func TestStoreListPageFiltersByExactActionNames(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

	insertStoredActionEvent(t, ctx, store, ActionRepositoryCreated, "repo-1", base)
	insertStoredActionEvent(t, ctx, store, ActionBranchFreezeCreated, "freeze-1", base.Add(time.Second))
	insertStoredActionEvent(t, ctx, store, ActionUserRolesUpdated, "user-1", base.Add(2*time.Second))
	insertStoredActionEvent(t, ctx, store, ActionBranchFreezeEnded, "freeze-2", base.Add(3*time.Second))
	// A prefix-sharing action must not match an exact IN-list filter.
	insertStoredActionEvent(t, ctx, store, ActionBranchFreezeCreated+".extra", "freeze-3", base.Add(4*time.Second))

	events, total, err := store.ListPage(ctx, []string{ActionBranchFreezeCreated, ActionBranchFreezeEnded}, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	want := []string{"freeze-2", "freeze-1"}
	if len(events) != len(want) {
		t.Fatalf("expected %d events, got %d", len(want), len(events))
	}
	for i := range want {
		if events[i].SubjectID != want[i] {
			t.Fatalf("event %d: expected subject %q, got %q", i, want[i], events[i].SubjectID)
		}
	}
}

func TestStoreListPageWithoutActionsReturnsAll(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)

	insertStoredActionEvent(t, ctx, store, ActionRepositoryCreated, "repo-1", base)
	insertStoredActionEvent(t, ctx, store, ActionUserDisabled, "user-1", base.Add(time.Second))

	events, total, err := store.ListPage(ctx, nil, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(events) != 2 {
		t.Fatalf("expected all 2 events, got %d of total %d", len(events), total)
	}
	if events[0].SubjectID != "user-1" || events[1].SubjectID != "repo-1" {
		t.Fatalf("expected newest-first ordering, got %+v", events)
	}
}

func TestStoreListPagePaginatesWithStableTotal(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i := range 5 {
		insertStoredEvent(t, ctx, store, strconv.Itoa(i+1), base.Add(time.Duration(i)*time.Second))
	}

	events, total, err := store.ListPage(ctx, nil, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 {
		t.Fatalf("expected total 5, got %d", total)
	}
	if len(events) != 2 || events[0].SubjectID != "3" || events[1].SubjectID != "2" {
		t.Fatalf("expected middle page (3, 2), got %+v", events)
	}
}

func TestStoreListPageClampsOffsetAndLimit(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC)
	for i := range 3 {
		insertStoredEvent(t, ctx, store, strconv.Itoa(i+1), base.Add(time.Duration(i)*time.Second))
	}

	events, total, err := store.ListPage(ctx, nil, -5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(events) != 3 {
		t.Fatalf("expected clamped query to return all 3 events, got %d of total %d", len(events), total)
	}
	if events[0].SubjectID != "3" {
		t.Fatalf("expected newest event first, got %+v", events)
	}
}

func TestStoreListPageReturnsSafeScanFailure(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO audit_events(action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?)`, ActionRepositoryCreated, SubjectTypeRepository, "1", `{}`, "not-a-time"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.ListPage(ctx, nil, 0, 10); err == nil {
		t.Fatal("expected invalid stored timestamp to fail safely")
	}
}

func TestStoreListReturnsSafeScanFailure(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO audit_events(action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?)`, ActionRepositoryCreated, SubjectTypeRepository, "1", `{}`, "not-a-time"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.List(ctx, 10); err == nil {
		t.Fatal("expected invalid stored timestamp to fail safely")
	}
}

func TestStoreRejectsInvalidAuditEvents(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)

	cases := []struct {
		name  string
		event Event
	}{
		{name: "missing action", event: Event{SubjectType: "repository", SubjectID: "1"}},
		{name: "missing subject type", event: Event{Action: "repository.created", SubjectID: "1"}},
		{name: "missing subject id", event: Event{Action: "repository.created", SubjectType: "repository"}},
		{name: "invalid JSON", event: Event{Action: "repository.created", SubjectType: "repository", SubjectID: "1", DetailsJSON: "not-json"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Record(ctx, tc.event); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestScopedActionClassificationCoversEveryKnownAction(t *testing.T) {
	const adminOnly = "admin-only"
	// Independent literal matrix: every known action and the subject family a
	// bounded scope must classify it under. Spelled as string literals, not
	// the production constants or slices, so a renamed action or a new
	// unclassified action fails here and has to be classified deliberately.
	expected := map[string]string{
		"repository.created":                         "repository",
		"repository.webhook_secret_configured":       "repository",
		"repository.status_token_configured":         "repository",
		"repository.open_pull_requests_synced":       "repository",
		"repository.branch_added":                    "repository",
		"repository.branch_removed":                  "repository",
		"repository.setup_check_run":                 "repository",
		"repository.setup_drift_detected":            "repository",
		"repository.status_post_verified":            "repository",
		"repository.status_post_verification_failed": "repository",
		"repository.enforcement_activated":           "repository",
		"repository.enforcement_deactivated":         "repository",
		"repository.enforcement_activation_failed":   "repository",
		"repository.enforcement_reconcile_succeeded": "repository",
		"repository.enforcement_reconcile_failed":    "repository",
		"repository.enforcement_recovery_succeeded":  "repository",
		"repository.enforcement_recovery_failed":     "repository",
		"repository.runtime_convergence_failed":      "repository",
		"repository_grant.added":                     "repository",
		"repository_grant.revoked":                   "repository",
		"branch_freeze.created":                      "branch_freeze",
		"branch_freeze.ended":                        "branch_freeze",
		"branch_freeze.cancelled":                    "branch_freeze",
		"branch_freeze.planned_unfreeze":             "branch_freeze",
		"freeze_schedule.created":                    "branch_freeze",
		"freeze_schedule.updated":                    "branch_freeze",
		"freeze_schedule.cancelled":                  "branch_freeze",
		"freeze_schedule.activated":                  "branch_freeze",
		"freeze_schedule.started_now":                "branch_freeze",
		"freeze_schedule.planned_unfreeze_executed":  "branch_freeze",
		"schedule.created":                           "schedule",
		"schedule.deleted":                           "schedule",
		"schedule.rules_added":                       "schedule",
		"schedule.rule_removed":                      "schedule",
		"schedule.window_added":                      "schedule",
		"schedule.window_removed":                    "schedule",
		"schedule.activated":                         "schedule",
		"schedule.paused":                            "schedule",
		"schedule.suppressed":                        "schedule",
		"thaw_exception.approved":                    "thaw_exception",
		"thaw_exception.shared_head_approved":        "thaw_exception",
		"user.roles_updated":                         adminOnly,
		"user.disabled":                              adminOnly,
		"user.enabled":                               adminOnly,
		"user.password_changed":                      adminOnly,
		"user.password_reset":                        adminOnly,
	}

	classified := map[string]string{}
	for subjectType, actions := range map[string][]string{
		SubjectTypeRepository:    repositorySubjectActions,
		SubjectTypeBranchFreeze:  branchFreezeSubjectActions,
		SubjectTypeSchedule:      scheduleSubjectActions,
		SubjectTypeThawException: thawExceptionSubjectActions,
	} {
		for _, action := range actions {
			if previous, ok := classified[action]; ok {
				t.Errorf("action %q classified under both %q and %q", action, previous, subjectType)
			}
			classified[action] = subjectType
		}
	}

	known := map[string]bool{}
	for _, action := range KnownActions() {
		known[action] = true
		want, ok := expected[action]
		if !ok {
			t.Errorf("action %q missing from the expected matrix; classify it explicitly before bounded scopes may see it", action)
			continue
		}
		got, ok := classified[action]
		if !ok {
			got = adminOnly
		}
		if got != want {
			t.Errorf("action %q: production classifies it as %q, matrix expects %q", action, got, want)
		}
	}
	for action := range classified {
		if !known[action] {
			t.Errorf("classified action %q is not in KnownActions", action)
		}
	}
	for action := range expected {
		if !known[action] {
			t.Errorf("matrix action %q is not in KnownActions", action)
		}
	}
}

func TestListForScopeAssociationPrecedence(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 20, 10, 0, 0, 0, time.UTC)

	// Every event uses a distinct action so scope results can be asserted as
	// an exact ordered action list.
	seed := []struct {
		action      string
		subjectType string
		subjectID   string
		detailsJSON string
	}{
		{ActionRepositoryCreated, SubjectTypeRepository, "7", `{}`},                                                   // no detail: subject fallback
		{ActionRepositoryBranchAdded, SubjectTypeRepository, "7", `{"repository_id":"9"}`},                            // valid detail wins over subject
		{ActionRepositoryBranchRemoved, SubjectTypeRepository, "7", `{"repository_id":"0"}`},                          // unusable detail: subject fallback
		{ActionRepositorySetupCheckRun, SubjectTypeRepository, "7", `not-json`},                                       // malformed details: subject fallback
		{ActionRepositoryStatusTokenConfigured, SubjectTypeRepository, "7", `"9"`},                                    // non-object root: subject fallback
		{ActionRepositoryOpenPullRequestsSynced, SubjectTypeRepository, "7", ``},                                      // empty details: subject fallback
		{ActionRepositorySetupDriftDetected, SubjectTypeRepository, "7", `{"repository_id":"8","repository_id":"7"}`}, // duplicate detail is ambiguous: no subject fallback
		{ActionRepositoryEnforcementActivated, SubjectTypeRepository, "not-a-number", `{}`},                           // unusable subject: admin-only
		{ActionBranchFreezeCreated, SubjectTypeBranchFreeze, "55", `{"repository_id":"7"}`},                           // details-only family associates
		{ActionBranchFreezeEnded, SubjectTypeBranchFreeze, "56", `not-json`},                                          // no subject fallback here: admin-only
		{ActionBranchFreezeCancelled, SubjectTypeBranchFreeze, "58", `{}`},                                            // no detail, no fallback: admin-only
		{ActionFreezeScheduleCreated, SubjectTypeBranchFreeze, "57", `{"repository_id":7}`},                           // JSON integer detail associates
		{ActionScheduleCreated, SubjectTypeSchedule, "9", `{"repository_id":"7"}`},                                    // schedule subject id is not a repository
		{ActionThawExceptionApproved, SubjectTypeThawException, "3", `{"repository_id":"7"}`},                         // details-only family associates
		{ActionThawExceptionSharedHeadApproved, SubjectTypeThawException, "9", `{"repository_id":"7"}`},               // shared-head subject id is not a repository
		{ActionUserRolesUpdated, SubjectTypeUser, "7", `{"repository_id":"7"}`},                                       // user actions stay admin-only
		{"repository.future_action", SubjectTypeRepository, "7", `{"repository_id":"7"}`},                             // unknown action stays admin-only
		{ActionRepositoryWebhookSecretConfigured, SubjectTypeSchedule, "7", `{"repository_id":"7"}`},                  // subject mismatch stays admin-only
	}
	for i, event := range seed {
		insertRawEvent(t, ctx, store, event.action, event.subjectType, event.subjectID, event.detailsJSON, base.Add(time.Duration(i)*time.Second))
	}

	assertScopeActions := func(name string, scope repositoryscope.ReadScope, want []string) {
		t.Helper()
		events, err := store.ListForScope(ctx, scope, 50)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := make([]string, 0, len(events))
		for _, event := range events {
			got = append(got, event.Action)
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}

	assertScopeActions("repository 7", repositoryscope.IDs(7), []string{
		ActionThawExceptionSharedHeadApproved,
		ActionThawExceptionApproved,
		ActionScheduleCreated,
		ActionFreezeScheduleCreated,
		ActionBranchFreezeCreated,
		ActionRepositoryOpenPullRequestsSynced,
		ActionRepositoryStatusTokenConfigured,
		ActionRepositorySetupCheckRun,
		ActionRepositoryBranchRemoved,
		ActionRepositoryCreated,
	})
	assertScopeActions("repository 9 sees only the redirected detail", repositoryscope.IDs(9), []string{ActionRepositoryBranchAdded})
	assertScopeActions("repository 8 does not see an ambiguous duplicate detail", repositoryscope.IDs(8), []string{})
	assertScopeActions("freeze subject id 55 is not a repository", repositoryscope.IDs(55), []string{})
	assertScopeActions("zero scope denies all", repositoryscope.IDs(), []string{})

	all, err := store.List(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(seed) {
		t.Errorf("unrestricted List returned %d events, want the complete trail of %d", len(all), len(seed))
	}
}

func TestScopedRepositoryDetailParsingSafety(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	// Each case is one branch_freeze.created event — the strictest,
	// details-only family — whose subject_id is the case marker. wantRepo is
	// the only repository whose bounded scope may see the marker; 0 means no
	// bounded scope may ever see it.
	cases := []struct {
		marker      string
		detailsJSON string
		wantRepo    int64
	}{
		{"json-integer", `{"repository_id":7}`, 7},
		{"json-integer-max", `{"repository_id":9223372036854775807}`, math.MaxInt64},
		{"canonical-string", `{"repository_id":"7"}`, 7},
		{"whitespace-string", `{"repository_id":" \t7\n "}`, 7},
		{"max-int64-string", `{"repository_id":"9223372036854775807"}`, math.MaxInt64},
		{"zero-integer", `{"repository_id":0}`, 0},
		{"zero-string", `{"repository_id":"0"}`, 0},
		{"negative-integer", `{"repository_id":-7}`, 0},
		{"negative-string", `{"repository_id":"-7"}`, 0},
		{"float", `{"repository_id":7.0}`, 0},
		{"float-string", `{"repository_id":"7.5"}`, 0},
		{"exponent", `{"repository_id":7e0}`, 0},
		{"exponent-string", `{"repository_id":"7e0"}`, 0},
		{"trailing-junk-string", `{"repository_id":"7junk"}`, 0},
		{"empty-string", `{"repository_id":""}`, 0},
		{"plus-sign-string", `{"repository_id":"+7"}`, 0},
		{"leading-zero-string", `{"repository_id":"007"}`, 0},
		{"overflow-integer", `{"repository_id":9223372036854775808}`, 0},
		{"overflow-string", `{"repository_id":"9223372036854775808"}`, 0},
		{"boolean-true", `{"repository_id":true}`, 0},
		{"json-null-detail", `{"repository_id":null}`, 0},
		{"missing-key", `{"other":"7"}`, 0},
		{"malformed", `not-json`, 0},
		{"empty-details", ``, 0},
		{"array-root", `[7]`, 0},
		{"integer-root", `7`, 0},
		{"string-root", `"7"`, 0},
		{"null-root", `null`, 0},
		{"duplicate-keys", `{"repository_id":"8","repository_id":"7"}`, 0},
		{"duplicate-keys-agreeing", `{"repository_id":"7","repository_id":"7"}`, 0},
	}
	for i, testCase := range cases {
		insertRawEvent(t, ctx, store, ActionBranchFreezeCreated, SubjectTypeBranchFreeze, testCase.marker, testCase.detailsJSON, base.Add(time.Duration(i)*time.Second))
	}

	assertScopeMarkers := func(name string, scope repositoryscope.ReadScope, want []string) {
		t.Helper()
		events, err := store.ListForScope(ctx, scope, 100)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := make([]string, 0, len(events))
		for _, event := range events {
			got = append(got, event.SubjectID)
		}
		slices.Sort(got)
		want = slices.Clone(want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", name, got, want)
		}
	}

	markersFor := func(repo int64) []string {
		markers := make([]string, 0)
		for _, testCase := range cases {
			if testCase.wantRepo == repo && repo != 0 {
				markers = append(markers, testCase.marker)
			}
		}
		return markers
	}

	assertScopeMarkers("repository 7 sees only safe forms", repositoryscope.IDs(7), markersFor(7))
	assertScopeMarkers("max int64 round-trips without saturation", repositoryscope.IDs(math.MaxInt64), markersFor(math.MaxInt64))
	assertScopeMarkers("boolean true never coerces to repository 1", repositoryscope.IDs(1), []string{})
	assertScopeMarkers("duplicate keys are ambiguous, not first-value", repositoryscope.IDs(8), []string{})

	all, err := store.List(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(cases) {
		t.Errorf("unrestricted List returned %d events, want all %d regardless of malformed details", len(all), len(cases))
	}
}

func TestListPageForScopeFiltersBeforePagination(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t, ctx)
	base := time.Date(2026, 7, 20, 14, 0, 0, 0, time.UTC)

	// Five older events visible to repository 7, markers acc-1 (oldest)
	// through acc-5 (newest of the accessible rows).
	accessible := []struct{ action, marker string }{
		{ActionBranchFreezeCreated, "acc-1"},
		{ActionBranchFreezeCreated, "acc-2"},
		{ActionBranchFreezeCreated, "acc-3"},
		{ActionFreezeScheduleCreated, "acc-4"},
		{ActionFreezeScheduleCreated, "acc-5"},
	}
	for i, event := range accessible {
		insertRawEvent(t, ctx, store, event.action, SubjectTypeBranchFreeze, event.marker, `{"repository_id":"7"}`, base.Add(time.Duration(i)*time.Second))
	}
	// Four newer events a bounded scope for repository 7 must never see, in
	// front of every accessible row in the unrestricted ordering.
	insertRawEvent(t, ctx, store, ActionBranchFreezeCreated, SubjectTypeBranchFreeze, "foreign", `{"repository_id":"8"}`, base.Add(10*time.Second))
	insertRawEvent(t, ctx, store, ActionUserRolesUpdated, SubjectTypeUser, "42", `{"repository_id":"7"}`, base.Add(11*time.Second))
	insertRawEvent(t, ctx, store, "repository.future_action", SubjectTypeRepository, "7", `{}`, base.Add(12*time.Second))
	insertRawEvent(t, ctx, store, ActionBranchFreezeEnded, SubjectTypeBranchFreeze, "unassociated", `not-json`, base.Add(13*time.Second))

	scope := repositoryscope.IDs(7)
	markers := func(events []Event) []string {
		got := make([]string, 0, len(events))
		for _, event := range events {
			got = append(got, event.SubjectID)
		}
		return got
	}

	limited, err := store.ListForScope(ctx, scope, 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"acc-5", "acc-4"}; !slices.Equal(markers(limited), want) {
		t.Errorf("scoped limit should fill with accessible rows: got %v, want %v", markers(limited), want)
	}

	assertPage := func(name string, actions []string, offset, limit int, wantMarkers []string, wantTotal int) {
		t.Helper()
		events, total, err := store.ListPageForScope(ctx, scope, actions, offset, limit)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.Equal(markers(events), wantMarkers) {
			t.Errorf("%s: got %v, want %v", name, markers(events), wantMarkers)
		}
		if total != wantTotal {
			t.Errorf("%s: got total %d, want %d", name, total, wantTotal)
		}
	}

	assertPage("first page", nil, 0, 2, []string{"acc-5", "acc-4"}, 5)
	assertPage("second page", nil, 2, 2, []string{"acc-3", "acc-2"}, 5)
	assertPage("last page", nil, 4, 10, []string{"acc-1"}, 5)
	assertPage("action filter intersects scope", []string{ActionBranchFreezeCreated}, 0, 10, []string{"acc-3", "acc-2", "acc-1"}, 3)
	assertPage("admin-only action filter stays empty", []string{ActionUserRolesUpdated}, 0, 10, []string{}, 0)

	unrestricted, total, err := store.ListPageForScope(ctx, repositoryscope.All(), nil, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(unrestricted) != 9 || total != 9 {
		t.Errorf("unrestricted page returned %d rows, total %d; want the complete trail of 9", len(unrestricted), total)
	}
}

func newTestStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()
	database, err := db.Open(ctx, db.DefaultConfig(filepath.Join(t.TempDir(), "thawguard-test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	migrations, err := db.LoadMigrations(projectMigrationsDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ApplyMigrations(ctx, database, migrations); err != nil {
		t.Fatal(err)
	}
	return NewStore(database)
}

func insertStoredEvent(t *testing.T, ctx context.Context, store *Store, subjectID string, createdAt time.Time) {
	t.Helper()
	insertStoredActionEvent(t, ctx, store, ActionRepositoryCreated, subjectID, createdAt)
}

func insertStoredActionEvent(t *testing.T, ctx context.Context, store *Store, action, subjectID string, createdAt time.Time) {
	t.Helper()
	insertRawEvent(t, ctx, store, action, SubjectTypeRepository, subjectID, `{}`, createdAt)
}

// insertRawEvent writes a row directly so tests can seed malformed or
// historical shapes that Record correctly rejects.
func insertRawEvent(t *testing.T, ctx context.Context, store *Store, action, subjectType, subjectID, detailsJSON string, createdAt time.Time) {
	t.Helper()
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO audit_events(action, subject_type, subject_id, details_json, created_at)
VALUES (?, ?, ?, ?, ?)`, action, subjectType, subjectID, detailsJSON, createdAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func projectMigrationsDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "migrations")
}
