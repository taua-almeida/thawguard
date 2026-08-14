package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

type fakeRoleEvidenceAuthService struct {
	AuthService
	session     auth.Session
	holders     []auth.RepositoryRoleHolder
	holderErr   error
	holderCalls []int64
}

func (f *fakeRoleEvidenceAuthService) HasUsers(context.Context) (bool, error) {
	return true, nil
}

func (f *fakeRoleEvidenceAuthService) SessionByID(_ context.Context, id string) (auth.Session, bool, error) {
	if id != f.session.ID {
		return auth.Session{}, false, nil
	}
	return f.session, true, nil
}

func (f *fakeRoleEvidenceAuthService) ListRepositoryRoleHolders(
	_ context.Context,
	repositoryID int64,
) ([]auth.RepositoryRoleHolder, error) {
	f.holderCalls = append(f.holderCalls, repositoryID)
	return f.holders, f.holderErr
}

func roleEvidenceSession(admin bool) auth.Session {
	return auth.Session{
		ID:        "role-evidence-session",
		CSRFToken: "role-evidence-csrf",
		User: auth.User{
			ID:          99,
			Email:       "admin@example.test",
			DisplayName: "Administrator",
			IsAdmin:     admin,
		},
		Grants:    auth.NewGrants(admin, nil),
		CreatedAt: time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC),
	}
}

func roleEvidenceHolders() []auth.RepositoryRoleHolder {
	return []auth.RepositoryRoleHolder{
		{
			UserID:      1,
			Email:       "admin-holder@example.test",
			DisplayName: "Admin holder",
			IsAdmin:     true,
			Roles:       auth.RoleSet{auth.RoleViewer, auth.RoleFreezer},
		},
		{
			UserID:      2,
			Email:       "approver@example.test",
			DisplayName: "Approver",
			Roles:       auth.RoleSet{auth.RoleThawApprover},
		},
		{
			UserID:      3,
			Email:       "unlinked@example.test",
			DisplayName: "Unlinked",
			Roles:       auth.RoleSet{auth.RoleViewer},
		},
		{
			UserID:      4,
			Email:       "disabled@example.test",
			DisplayName: "Disabled holder",
			Disabled:    true,
			Roles:       auth.RoleSet{auth.RoleFreezer},
		},
	}
}

func qualifyingRoleEvidenceView() forgeconnection.AccessShadowView {
	completedAt := time.Date(2026, 8, 14, 9, 58, 0, 0, time.UTC)
	failedAt := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	dueAt := time.Date(2026, 8, 14, 9, 55, 0, 0, time.UTC)
	return forgeconnection.AccessShadowView{
		HasConnection:          true,
		ConnectionID:           5,
		ConfigRevision:         3,
		CheckGeneration:        4,
		BindingRevision:        6,
		AccessIdentityRevision: 8,
		SetupEvidenceCurrent:   true,
		EncryptionAvailable:    false,
		IdentityCount:          3,
		BindingCount:           1,
		WithinLimits:           true,
		NewestRunID:            8,
		LatestAttempt: &forgeconnection.AccessShadowAttempt{
			Status:     forgeconnection.AccessAttemptFailed,
			Trigger:    forgeconnection.AccessShadowRunPeriodic,
			ResultCode: forgeconnection.AccessSyncUnavailable,
			StartedAt:  failedAt.Add(-time.Minute),
			FinishedAt: &failedAt,
		},
		LatestSnapshot: &forgeconnection.AccessShadowSnapshot{
			RunID:        7,
			PresentCount: 2,
			AbsentCount:  1,
			UnknownCount: 0,
			PairCount:    3,
			ScopeCurrent: true,
			Age:          2 * time.Minute,
			ObservedAt:   completedAt,
		},
		PeriodicRevision:  2,
		PeriodicNextDueAt: &dueAt,
		PeriodicDueStatus: forgeconnection.AccessPeriodicOverdue,
		PeriodicBlockers: []forgeconnection.AccessShadowPeriodicBlocker{
			forgeconnection.AccessPeriodicEncryptionUnavailable,
		},
		BoundRepositories: []forgeconnection.AccessShadowBoundRepository{
			{RepositoryID: 11, RepositoryFullName: "fixture-org/alpha"},
		},
		Pairs: []forgeconnection.AccessShadowPairRow{
			{
				IdentityID:         21,
				UserID:             1,
				RepositoryID:       11,
				UsernameAtLink:     "admin-user",
				RepositoryFullName: "fixture-org/alpha",
				Observed:           true,
				LatestReason:       forgeconnection.AccessReasonDirectCollaborator,
				LatestRunID:        7,
				LatestObservedAt:   completedAt,
			},
			{
				IdentityID:         22,
				UserID:             2,
				RepositoryID:       11,
				UsernameAtLink:     "approver-user",
				RepositoryFullName: "fixture-org/alpha",
				Observed:           true,
				LatestReason:       forgeconnection.AccessReasonNoExplicitAccessNone,
				LatestRunID:        7,
				LatestObservedAt:   completedAt,
			},
			{
				IdentityID:         24,
				UserID:             4,
				RepositoryID:       11,
				UsernameAtLink:     "disabled-user",
				RepositoryFullName: "fixture-org/alpha",
				Observed:           true,
				LatestReason:       forgeconnection.AccessReasonTeamAccess,
				LatestRunID:        7,
				LatestObservedAt:   completedAt,
			},
		},
	}
}

func newRoleEvidenceServer(
	view forgeconnection.AccessShadowView,
	holders []auth.RepositoryRoleHolder,
) (*Server, *fakeRoleEvidenceAuthService, *fakeForgeAccessShadowService, auth.Session) {
	session := roleEvidenceSession(true)
	authService := &fakeRoleEvidenceAuthService{session: session, holders: holders}
	shadow := &fakeForgeAccessShadowService{view: view}
	server := NewServer(Config{
		AppName:                  "Thawguard",
		AuthService:              authService,
		ForgeAccessShadowService: shadow,
	})
	return server, authService, shadow, session
}

func roleEvidenceGET(
	server *Server,
	session auth.Session,
	rawQuery string,
	forceQuery bool,
) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/settings/forge-access/role-evidence", nil)
	request.URL.RawQuery = rawQuery
	request.URL.ForceQuery = forceQuery
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func TestClassifyForgeRoleEvidencePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name          string
		gateQualified bool
		pairExists    bool
		observed      bool
		snapshotRunID int64
		pairRunID     int64
		reason        forgeconnection.AccessObservationReason
		want          string
	}{
		{name: "failed gate", pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "missing pair", gateQualified: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "unobserved pair", gateQualified: true, pairExists: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "nonpositive snapshot run", gateQualified: true, pairExists: true, observed: true, pairRunID: 7, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "nonpositive pair run", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "mismatched run", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 8, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "direct collaborator", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonDirectCollaborator, want: forgeRoleEvidenceSupportingOutcome},
		{name: "team access", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonTeamAccess, want: forgeRoleEvidenceSupportingOutcome},
		{name: "confirmed absent", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonNoExplicitAccessNone, want: forgeRoleEvidenceAbsentOutcome},
		{name: "unknown latest reason", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessReasonPermissionUnavailable, want: forgeRoleEvidenceIndeterminateOutcome},
		{name: "unrecognized latest reason", gateQualified: true, pairExists: true, observed: true, snapshotRunID: 7, pairRunID: 7, reason: forgeconnection.AccessObservationReason("unexpected"), want: forgeRoleEvidenceIndeterminateOutcome},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyForgeRoleEvidence(
				tc.gateQualified,
				tc.pairExists,
				tc.observed,
				tc.snapshotRunID,
				tc.pairRunID,
				tc.reason,
			)
			if string(got) != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestForgeRoleEvidenceGateUsesOnlyComparisonPrerequisites(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*forgeconnection.AccessShadowView)
		want   bool
	}{
		{name: "qualifying despite unavailable encryption periodic blocker and newer failure", want: true},
		{name: "no connection", mutate: func(view *forgeconnection.AccessShadowView) { view.HasConnection = false }},
		{name: "repository not bound", mutate: func(view *forgeconnection.AccessShadowView) { view.BoundRepositories = nil }},
		{name: "setup evidence stale", mutate: func(view *forgeconnection.AccessShadowView) { view.SetupEvidenceCurrent = false }},
		{name: "over limits", mutate: func(view *forgeconnection.AccessShadowView) { view.WithinLimits = false }},
		{name: "no completed snapshot", mutate: func(view *forgeconnection.AccessShadowView) { view.LatestSnapshot = nil }},
		{name: "snapshot scope changed", mutate: func(view *forgeconnection.AccessShadowView) { view.LatestSnapshot.ScopeCurrent = false }},
		{name: "exact ten minute boundary", mutate: func(view *forgeconnection.AccessShadowView) { view.LatestSnapshot.Age = 10 * time.Minute }},
		{name: "unknown pair", mutate: func(view *forgeconnection.AccessShadowView) { view.LatestSnapshot.UnknownCount = 1 }},
		{name: "pair count mismatch", mutate: func(view *forgeconnection.AccessShadowView) { view.LatestSnapshot.PairCount = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := qualifyingRoleEvidenceView()
			if tc.mutate != nil {
				tc.mutate(&view)
			}
			got, _, _, _ := forgeRoleEvidenceGate(view, 11)
			if got != tc.want {
				t.Fatalf("qualified = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestForgeRoleEvidenceGateReportsAllApplicableBlockersInOrder(t *testing.T) {
	view := qualifyingRoleEvidenceView()
	view.WithinLimits = false
	view.SetupEvidenceCurrent = false
	view.IdentityCount = -1
	view.BindingCount = -2
	view.LatestSnapshot.ScopeCurrent = false
	view.LatestSnapshot.Age = 10 * time.Minute
	view.LatestSnapshot.UnknownCount = 1
	view.LatestSnapshot.PairCount = 99

	qualified, label, tone, detail := forgeRoleEvidenceGate(view, 11)
	if qualified || label != forgeRoleEvidenceIndeterminateOutcome || tone != "warning" {
		t.Fatalf("gate = (%v, %q, %q), want indeterminate warning", qualified, label, tone)
	}
	want := forgeRoleEvidenceOverLimitDetail +
		" Forge connection setup evidence is not current." +
		" The current identity and repository counts are invalid." +
		" The completed snapshot does not describe the current identity and repository scope." +
		" The completed snapshot is at least ten minutes old." +
		" The completed snapshot contains unknown pair evidence." +
		" The completed snapshot pair count does not match the current identity and repository scope."
	if detail != want {
		t.Fatalf("detail = %q, want %q", detail, want)
	}
}

func TestForgeRoleEvidenceRowsUseLatestMatchingSnapshotOnly(t *testing.T) {
	view := qualifyingRoleEvidenceView()
	qualified, _, _, _ := forgeRoleEvidenceGate(view, 11)
	rows, counts := forgeRoleEvidenceRows(view, 11, qualified, roleEvidenceHolders())
	if counts != (forgeRoleEvidenceCounts{
		SupportingActive:    1,
		AbsentActive:        1,
		IndeterminateActive: 1,
		Disabled:            1,
	}) {
		t.Fatalf("counts = %+v", counts)
	}
	wantOutcomes := []string{
		forgeRoleEvidenceSupportingOutcome,
		forgeRoleEvidenceAbsentOutcome,
		forgeRoleEvidenceIndeterminateOutcome,
		forgeRoleEvidenceSupportingOutcome,
	}
	for i, want := range wantOutcomes {
		if rows[i].Outcome != want {
			t.Fatalf("row outcomes = %+v", rows)
		}
	}
	if rows[2].IdentityDetail != forgeRoleEvidenceMissingIdentity {
		t.Fatalf("missing identity detail = %q", rows[2].IdentityDetail)
	}
	if !strings.Contains(rows[1].OutcomeDetail, forgeRoleEvidenceAbsentOutcome) ||
		!strings.Contains(rows[1].OutcomeDetail, forgeRoleEvidenceAbsenceCaveat) {
		t.Fatalf("absence explanation = %q", rows[1].OutcomeDetail)
	}
	if rows[1].OutcomeBadgeLabel != forgeRoleEvidenceAbsentOutcome {
		t.Fatalf("absence badge label = %q", rows[1].OutcomeBadgeLabel)
	}
	if !strings.Contains(rows[0].OutcomeDetail, forgeShadowReasonText(view.Pairs[0].LatestReason)) ||
		!strings.Contains(rows[0].OutcomeDetail, "This evidence does not preserve or predict authority and changes nothing.") {
		t.Fatalf("supporting explanation = %q", rows[0].OutcomeDetail)
	}

	view.Pairs[0].LatestReason = forgeconnection.AccessReasonPermissionUnavailable
	view.Pairs[0].PriorConfirmedReason = forgeconnection.AccessReasonDirectCollaborator
	rows, _ = forgeRoleEvidenceRows(view, 11, qualified, roleEvidenceHolders())
	if rows[0].Outcome != forgeRoleEvidenceIndeterminateOutcome {
		t.Fatalf("prior confirmation affected latest classification: %+v", rows[0])
	}
}

func TestForgeRoleEvidenceRowsUsePairObservationUTCAndSnapshotAge(t *testing.T) {
	view := qualifyingRoleEvidenceView()
	view.Pairs[0].LatestObservedAt = time.Date(2026, 8, 14, 11, 58, 0, 0, time.FixedZone("fixture", 2*60*60))
	rows, _ := forgeRoleEvidenceRows(view, 11, true, roleEvidenceHolders())
	if rows[0].ObservedAt != "2026-08-14 09:58:00 UTC" || rows[0].ObservedAge != "2 min ago" {
		t.Fatalf("matching observation = (%q, %q)", rows[0].ObservedAt, rows[0].ObservedAge)
	}

	view.Pairs[0].LatestRunID++
	rows, _ = forgeRoleEvidenceRows(view, 11, true, roleEvidenceHolders())
	if rows[0].ObservedAt != "2026-08-14 09:58:00 UTC" || rows[0].ObservedAge != "" {
		t.Fatalf("nonmatching observation = (%q, %q)", rows[0].ObservedAt, rows[0].ObservedAge)
	}
}

func TestForgeRoleEvidenceQueryBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rawQuery   string
		forceQuery bool
	}{
		{name: "no query"},
		{name: "bare question mark", forceQuery: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, authService, shadow, session := newRoleEvidenceServer(qualifyingRoleEvidenceView(), roleEvidenceHolders())
			response := roleEvidenceGET(server, session, tc.rawQuery, tc.forceQuery)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d body=%q", response.Code, response.Body.String())
			}
			body := response.Body.String()
			if !strings.Contains(body, "Choose a repository to compare") ||
				!strings.Contains(body, `<option value="" selected>Choose a bound repository</option>`) ||
				strings.Contains(body, "Current holder counts") {
				t.Fatalf("selector-only body = %q", body)
			}
			if len(authService.holderCalls) != 0 || shadow.viewCalls != 1 {
				t.Fatalf("calls: holders=%v shadow=%d", authService.holderCalls, shadow.viewCalls)
			}
		})
	}

	badQueries := []string{
		"repository_id=%",
		"repository_id=1;other=2",
		"repository_id=1&repository_id=1",
		"repository_id=1&other=2",
		"other=1",
		"repository_id=",
		"repository_id",
		"repository_id=0",
		"repository_id=-1",
		"repository_id=%2B1",
		"repository_id=+1",
		"repository_id=%201",
		"repository_id=01",
		"repository_id=9223372036854775808",
	}
	for _, rawQuery := range badQueries {
		t.Run(rawQuery, func(t *testing.T) {
			server, authService, shadow, session := newRoleEvidenceServer(qualifyingRoleEvidenceView(), roleEvidenceHolders())
			response := roleEvidenceGET(server, session, rawQuery, false)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%q", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "<!doctype html>") ||
				!strings.Contains(response.Body.String(), "Bad request") {
				t.Fatalf("malformed query did not render the full-page error: %q", response.Body.String())
			}
			if len(authService.holderCalls) != 0 || shadow.viewCalls != 0 {
				t.Fatalf("malformed query reached services: holders=%v shadow=%d", authService.holderCalls, shadow.viewCalls)
			}
		})
	}

}

func TestForgeRoleEvidencePageRendersReadOnlyComparison(t *testing.T) {
	server, authService, _, session := newRoleEvidenceServer(qualifyingRoleEvidenceView(), roleEvidenceHolders())
	response := roleEvidenceGET(server, session, "repository_id=11", false)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", response.Code, response.Body.String())
	}
	assertForgeAccessSecurityHeaders(t, response.Header())
	if len(authService.holderCalls) != 1 || authService.holderCalls[0] != 11 {
		t.Fatalf("holder calls = %v", authService.holderCalls)
	}
	body := response.Body.String()
	for _, fragment := range []string{
		"Current role and Forge evidence",
		"This page configures nothing. This page makes no Thawguard or Forgejo authority changes.",
		"This page makes no Thawguard or Forgejo authority changes.",
		"It combines local role state and retained evidence loaded for this request and is not an atomic authorization proof, saved policy, cutover plan, or hard security boundary.",
		"Administrator read-all authority is installation-wide and independent of repository-scoped Freeze/Thaw roles.",
		"This evidence does not preserve or predict authority and changes nothing.",
		forgeRoleEvidenceAbsentOutcome + " " + forgeRoleEvidenceAbsenceCaveat,
		"fixture-org/alpha",
		"Qualifying completed evidence",
		"Newer non-completed attempt",
		"Latest attempt: Failed (Periodic).",
		"It has not replaced or invalidated the completed snapshot.",
		"Enabled · blocked",
		"Service PAT encryption is unavailable.",
		forgeRoleEvidenceSupportingOutcome,
		forgeRoleEvidenceAbsentOutcome,
		forgeRoleEvidenceIndeterminateOutcome,
		forgeRoleEvidenceAbsenceCaveat,
		forgeRoleEvidenceMissingIdentity,
		"Non-exercisable while disabled",
		"Repository-scoped",
		"Admin",
		"Viewer",
		"Freezer",
		"Thaw approver",
		`href="/settings/forge-access/shadow-access"`,
		`href="/settings/forge-access"`,
		`href="/users"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("page is missing %q", fragment)
		}
	}
	if strings.Count(body, forgeRoleEvidenceAbsentOutcome) != 4 ||
		!strings.Contains(body, ">"+forgeRoleEvidenceAbsentOutcome+"</span>") {
		t.Fatalf("absence wording is not aligned across the summary, badge, row detail, and footer: %q", body)
	}
	for _, control := range []string{">Save<", ">Apply<", ">Allow<", ">Deny<", ">Refresh<", ">Export<"} {
		if strings.Contains(body, control) {
			t.Fatalf("page contains forbidden control %q", control)
		}
	}
}

func TestForgeRoleEvidencePageRendersPairObservationTimeAndSnapshotAge(t *testing.T) {
	view := qualifyingRoleEvidenceView()
	view.Pairs[0].LatestObservedAt = time.Date(2026, 8, 14, 10, 58, 0, 0, time.FixedZone("fixture", 60*60))
	server, _, _, session := newRoleEvidenceServer(view, roleEvidenceHolders())
	response := roleEvidenceGET(server, session, "repository_id=11", false)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%q", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Observed 2026-08-14 09:58:00 UTC · 2 min ago") {
		t.Fatalf("pair observation timestamp and retained age are missing: %q", response.Body.String())
	}
}

func TestForgeRoleEvidencePageOverLimitCopyPrecedesMissingIdentity(t *testing.T) {
	view := qualifyingRoleEvidenceView()
	view.WithinLimits = false
	view.SetupEvidenceCurrent = false
	view.Pairs = nil
	server, _, _, session := newRoleEvidenceServer(view, roleEvidenceHolders())
	response := roleEvidenceGET(server, session, "repository_id=11", false)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if strings.Count(body, forgeRoleEvidenceOverLimitDetail) != len(roleEvidenceHolders())+1 {
		t.Fatalf("over-limit gate and row copy missing: %q", body)
	}
	if !strings.Contains(body, "How to read an absence outcome") ||
		!strings.Contains(body, forgeRoleEvidenceAbsentOutcome+" "+forgeRoleEvidenceAbsenceCaveat) {
		t.Fatalf("absence legend is not framed conditionally: %q", body)
	}
	if strings.Count(body, forgeRoleEvidenceAbsentOutcome) != 2 {
		t.Fatalf("over-limit rows render absence outcome copy beyond the required summary and footer: %q", body)
	}
	if strings.Contains(body, forgeRoleEvidenceMissingIdentity) {
		t.Fatalf("missing-identity copy rendered over limits: %q", body)
	}
}

func TestForgeRoleEvidenceRowsUseExactOverLimitIdentityDetail(t *testing.T) {
	view := qualifyingRoleEvidenceView()
	view.WithinLimits = false
	view.Pairs = nil
	rows, _ := forgeRoleEvidenceRows(view, 11, false, roleEvidenceHolders())
	for _, row := range rows {
		if row.IdentityDetail != forgeRoleEvidenceOverLimitDetail {
			t.Fatalf("identity detail = %q, want %q", row.IdentityDetail, forgeRoleEvidenceOverLimitDetail)
		}
	}
}

func TestForgeRoleEvidencePageHandlesEmptyAndStaleSelections(t *testing.T) {
	for _, tc := range []struct {
		name      string
		view      forgeconnection.AccessShadowView
		emptyText string
	}{
		{name: "no connection without selection", emptyText: "No Forge connection configured"},
		{
			name:      "no bindings without selection",
			view:      forgeconnection.AccessShadowView{HasConnection: true},
			emptyText: "No bound repositories",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, authService, _, session := newRoleEvidenceServer(tc.view, roleEvidenceHolders())
			response := roleEvidenceGET(server, session, "", false)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), tc.emptyText) {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if len(authService.holderCalls) != 0 {
				t.Fatalf("empty selector reached auth: %v", authService.holderCalls)
			}
		})
	}

	t.Run("empty holder population", func(t *testing.T) {
		server, authService, _, session := newRoleEvidenceServer(qualifyingRoleEvidenceView(), nil)
		response := roleEvidenceGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "No current repository role holders") {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
		if len(authService.holderCalls) != 1 {
			t.Fatalf("holder calls = %v", authService.holderCalls)
		}
	})

	for _, tc := range []struct {
		name string
		view forgeconnection.AccessShadowView
	}{
		{name: "after reset", view: forgeconnection.AccessShadowView{}},
		{name: "no bindings", view: forgeconnection.AccessShadowView{HasConnection: true}},
		{name: "different binding", view: forgeconnection.AccessShadowView{
			HasConnection: true,
			BoundRepositories: []forgeconnection.AccessShadowBoundRepository{
				{RepositoryID: 12, RepositoryFullName: "fixture-org/beta"},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, authService, _, session := newRoleEvidenceServer(tc.view, roleEvidenceHolders())
			response := roleEvidenceGET(server, session, "repository_id=11", false)
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "Page not found") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if len(authService.holderCalls) != 0 {
				t.Fatalf("stale selection reached auth: %v", authService.holderCalls)
			}
		})
	}
}

func TestForgeRoleEvidencePageFailureOrderingAndAuthorization(t *testing.T) {
	t.Run("shadow failure precedes holder query", func(t *testing.T) {
		server, authService, shadow, session := newRoleEvidenceServer(qualifyingRoleEvidenceView(), roleEvidenceHolders())
		shadow.viewErr = errors.New("shadow failed")
		response := roleEvidenceGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "Current holder counts") {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
		if len(authService.holderCalls) != 0 {
			t.Fatalf("shadow failure reached auth: %v", authService.holderCalls)
		}
	})

	t.Run("holder failure renders no partial comparison", func(t *testing.T) {
		server, authService, _, session := newRoleEvidenceServer(qualifyingRoleEvidenceView(), roleEvidenceHolders())
		authService.holderErr = errors.New("holders failed")
		response := roleEvidenceGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "Current holder counts") {
			t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
		}
	})

	t.Run("missing shadow service", func(t *testing.T) {
		session := roleEvidenceSession(true)
		authService := &fakeRoleEvidenceAuthService{session: session}
		server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
		if response := roleEvidenceGET(server, session, "", false); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", response.Code)
		}
	})

	t.Run("missing auth service", func(t *testing.T) {
		server := NewServer(Config{
			AppName:                  "Thawguard",
			ForgeAccessShadowService: &fakeForgeAccessShadowService{view: qualifyingRoleEvidenceView()},
		})
		session := forgeAccessAdminSession(t, server)
		if response := forgeAccessGET(server, session, "/settings/forge-access/role-evidence"); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", response.Code)
		}
	})

	t.Run("administrator required", func(t *testing.T) {
		session := roleEvidenceSession(false)
		authService := &fakeRoleEvidenceAuthService{session: session}
		server := NewServer(Config{
			AppName:                  "Thawguard",
			AuthService:              authService,
			ForgeAccessShadowService: &fakeForgeAccessShadowService{view: qualifyingRoleEvidenceView()},
		})
		if response := roleEvidenceGET(server, session, "", false); response.Code != http.StatusForbidden {
			t.Fatalf("status = %d", response.Code)
		}
	})
}
