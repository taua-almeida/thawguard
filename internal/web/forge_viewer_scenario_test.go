package web

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

type viewerScenarioAccessCall struct {
	repositoryID int64
	linkedIDs    []int64
}

type fakeViewerScenarioAuthService struct {
	AuthService
	session auth.Session
	users   []auth.RepositoryAccessUser
	userErr error
	calls   []viewerScenarioAccessCall
}

func (f *fakeViewerScenarioAuthService) HasUsers(context.Context) (bool, error) {
	return true, nil
}

func (f *fakeViewerScenarioAuthService) SessionByID(_ context.Context, id string) (auth.Session, bool, error) {
	if id != f.session.ID {
		return auth.Session{}, false, nil
	}
	return f.session, true, nil
}

func (f *fakeViewerScenarioAuthService) ListRepositoryAccessUsers(
	_ context.Context,
	repositoryID int64,
	linkedUserIDs []int64,
) ([]auth.RepositoryAccessUser, error) {
	f.calls = append(f.calls, viewerScenarioAccessCall{
		repositoryID: repositoryID,
		linkedIDs:    append([]int64(nil), linkedUserIDs...),
	})
	return f.users, f.userErr
}

func qualifyingViewerScenarioView() forgeconnection.AccessShadowView {
	view := qualifyingRoleEvidenceView()
	view.IdentityCount = 4
	view.LatestSnapshot.PresentCount = 3
	view.LatestSnapshot.PairCount = 4
	view.LinkedUsers = append(view.LinkedUsers, forgeconnection.AccessShadowLinkedUser{
		UserID:          5,
		UserDisplayName: "Candidate",
		UserEmail:       "candidate@example.test",
		UsernameAtLink:  "candidate-user",
	})
	view.Pairs = append(view.Pairs, forgeconnection.AccessShadowPairRow{
		IdentityID:         25,
		UserID:             5,
		RepositoryID:       11,
		UserDisplayName:    "Candidate",
		UserEmail:          "candidate@example.test",
		UsernameAtLink:     "candidate-user",
		RepositoryFullName: "fixture-org/alpha",
		Observed:           true,
		LatestReason:       forgeconnection.AccessReasonDirectCollaborator,
		LatestRunID:        7,
		LatestObservedAt:   view.LatestSnapshot.ObservedAt,
	})
	return view
}

func viewerScenarioAccessUsers() []auth.RepositoryAccessUser {
	users := append([]auth.RepositoryAccessUser(nil), roleEvidenceHolders()...)
	users = append(users, auth.RepositoryAccessUser{
		UserID:      5,
		Email:       "candidate@example.test",
		DisplayName: "Candidate",
	})
	slices.SortFunc(users, func(a, b auth.RepositoryAccessUser) int {
		return strings.Compare(a.DisplayName, b.DisplayName)
	})
	return users
}

func newViewerScenarioServer(
	view forgeconnection.AccessShadowView,
	users []auth.RepositoryAccessUser,
) (*Server, *fakeViewerScenarioAuthService, *fakeForgeAccessShadowService, auth.Session) {
	session := roleEvidenceSession(true)
	authService := &fakeViewerScenarioAuthService{session: session, users: users}
	shadow := &fakeForgeAccessShadowService{view: view}
	server := NewServer(Config{
		AppName:                  "Thawguard",
		AuthService:              authService,
		ForgeAccessShadowService: shadow,
	})
	return server, authService, shadow, session
}

func viewerScenarioGET(
	server *Server,
	session auth.Session,
	rawQuery string,
	forceQuery bool,
) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/settings/forge-access/viewer-scenario", nil)
	request.URL.RawQuery = rawQuery
	request.URL.ForceQuery = forceQuery
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func TestClassifyForgeViewerScenarioPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name            string
		baselineOn      bool
		disabled        bool
		isAdmin         bool
		roles           auth.RoleSet
		gateQualified   bool
		evidenceOutcome string
		want            forgeViewerScenarioReason
		wantError       bool
	}{
		{
			name: "current Viewer wins every later condition", roles: auth.RoleSet{auth.RoleViewer},
			disabled: true, isAdmin: true, evidenceOutcome: "unexpected", want: forgeViewerReasonCurrentViewer,
		},
		{
			name: "baseline off precedes account and authority", disabled: true, isAdmin: true,
			roles: auth.RoleSet{auth.RoleFreezer}, evidenceOutcome: "unexpected", want: forgeViewerReasonBaselineOff,
		},
		{
			name: "disabled precedes Administrator", baselineOn: true, disabled: true, isAdmin: true,
			evidenceOutcome: "unexpected", want: forgeViewerReasonAccountDisabled,
		},
		{
			name: "Administrator precedes scoped read", baselineOn: true, isAdmin: true,
			roles: auth.RoleSet{auth.RoleFreezer}, evidenceOutcome: "unexpected", want: forgeViewerReasonAdminReadAll,
		},
		{
			name: "Freezer already reads", baselineOn: true, roles: auth.RoleSet{auth.RoleFreezer},
			evidenceOutcome: "unexpected", want: forgeViewerReasonScopedReadPresent,
		},
		{
			name: "Thaw approver already reads", baselineOn: true, roles: auth.RoleSet{auth.RoleThawApprover},
			evidenceOutcome: "unexpected", want: forgeViewerReasonScopedReadPresent,
		},
		{
			name: "failed gate", baselineOn: true, evidenceOutcome: "unexpected",
			want: forgeViewerReasonEvidenceGateFailed,
		},
		{
			name: "supporting evidence", baselineOn: true, gateQualified: true,
			evidenceOutcome: forgeRoleEvidenceSupportingOutcome, want: forgeViewerReasonSupportingEvidence,
		},
		{
			name: "confirmed absence", baselineOn: true, gateQualified: true,
			evidenceOutcome: forgeRoleEvidenceAbsentOutcome, want: forgeViewerReasonConfirmedAbsent,
		},
		{
			name: "pair indeterminate", baselineOn: true, gateQualified: true,
			evidenceOutcome: forgeRoleEvidenceIndeterminateOutcome, want: forgeViewerReasonPairIndeterminate,
		},
		{
			name: "unrecognized evidence", baselineOn: true, gateQualified: true,
			evidenceOutcome: "unexpected", wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyForgeViewerScenario(
				tc.baselineOn,
				tc.disabled,
				tc.isAdmin,
				tc.roles,
				tc.gateQualified,
				tc.evidenceOutcome,
			)
			if tc.wantError {
				if err == nil {
					t.Fatalf("reason = %q, want error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("reason = %q error = %v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestForgeViewerScenarioPresentationDetails(t *testing.T) {
	for _, tc := range []struct {
		reason  forgeViewerScenarioReason
		outcome string
		detail  string
	}{
		{
			reason: forgeViewerReasonCurrentViewer, outcome: forgeViewerCurrentOutcome,
			detail: "The current Viewer role is retained. No role is removed by this scenario.",
		},
		{
			reason: forgeViewerReasonBaselineOff, outcome: forgeViewerNoChangeOutcome,
			detail: "The Viewer baseline is off, so the scenario adds nothing. Every current role is retained.",
		},
		{
			reason: forgeViewerReasonAccountDisabled, outcome: forgeViewerNoChangeOutcome,
			detail: "Viewer is withheld while this account is disabled. Recalculate after the account is enabled.",
		},
		{
			reason: forgeViewerReasonAdminReadAll, outcome: forgeViewerNoChangeOutcome,
			detail: "Administrator read-all makes Viewer redundant. No fallback role is proposed; recalculate after Administrator authority changes.",
		},
		{
			reason: forgeViewerReasonScopedReadPresent, outcome: forgeViewerNoChangeOutcome,
			detail: "The current Freezer or Thaw approver action role is retained and already includes repository read. Recalculate after that action role is removed.",
		},
		{
			reason: forgeViewerReasonEvidenceGateFailed, outcome: forgeViewerIndeterminateOutcome,
			detail: "Viewer eligibility remains indeterminate. See the global evidence gate above for the blocking facts.",
		},
		{
			reason: forgeViewerReasonPairIndeterminate, outcome: forgeViewerIndeterminateOutcome,
			detail: "Viewer eligibility remains indeterminate. See this row's Evidence column.",
		},
		{
			reason: forgeViewerReasonSupportingEvidence, outcome: forgeViewerAddedOutcome,
			detail: "Qualifying explicit-access evidence supports adding Viewer. Every current role is retained and no role is removed.",
		},
		{
			reason: forgeViewerReasonConfirmedAbsent, outcome: forgeViewerNoChangeOutcome,
			detail: forgeRoleEvidenceAbsentOutcome + " " + forgeRoleEvidenceAbsenceCaveat,
		},
	} {
		outcome, _, detail, err := forgeViewerScenarioPresentation(tc.reason)
		if err != nil || outcome != tc.outcome || detail != tc.detail {
			t.Fatalf("reason %q presentation = (%q, %q, %v), want (%q, %q)", tc.reason, outcome, detail, err, tc.outcome, tc.detail)
		}
	}
}

func TestForgeViewerScenarioPresentationRejectsUnknownReason(t *testing.T) {
	if _, _, _, err := forgeViewerScenarioPresentation("unexpected"); err == nil {
		t.Fatal("unrecognized reason was accepted")
	}
}

func TestForgeViewerScenarioRowsComposeOrderedPopulation(t *testing.T) {
	view := qualifyingViewerScenarioView()
	qualified, _, _, _ := forgeRoleEvidenceGate(view, 11)
	rows, counts, err := forgeViewerScenarioRows(view, 11, true, qualified, viewerScenarioAccessUsers())
	if err != nil {
		t.Fatal(err)
	}
	if counts != (forgeViewerScenarioCounts{
		CurrentViewer: 2,
		AddedViewer:   1,
		NoChange:      2,
	}) {
		t.Fatalf("counts = %+v", counts)
	}
	wantNames := []string{"Admin holder", "Approver", "Candidate", "Disabled holder", "Unlinked"}
	for i, wantName := range wantNames {
		if rows[i].DisplayName != wantName {
			t.Fatalf("row order = %+v, want %v", rows, wantNames)
		}
	}
	if rows[2].ScenarioOutcome != forgeViewerAddedOutcome ||
		rows[2].ScenarioDetail != "Qualifying explicit-access evidence supports adding Viewer. Every current role is retained and no role is removed." ||
		!rows[2].Linked ||
		rows[2].UsernameAtLink != "candidate-user" || rows[2].EvidenceObservedAt == "" ||
		rows[2].EvidenceAge != "2 min ago" {
		t.Fatalf("candidate row = %+v", rows[2])
	}
	if rows[4].ScenarioOutcome != forgeViewerCurrentOutcome ||
		rows[4].ScenarioDetail != "The current Viewer role is retained. No role is removed by this scenario." || rows[4].Linked ||
		rows[4].EvidenceLabel != forgeRoleEvidenceIndeterminateOutcome || rows[4].EvidenceObservedAt != "" {
		t.Fatalf("unlinked current Viewer row = %+v", rows[4])
	}
	if rows[1].ScenarioDetail != "The current Freezer or Thaw approver action role is retained and already includes repository read. Recalculate after that action role is removed." {
		t.Fatalf("scoped-read row = %+v", rows[1])
	}
	if rows[3].ScenarioDetail != "Viewer is withheld while this account is disabled. Recalculate after the account is enabled." {
		t.Fatalf("disabled row = %+v", rows[3])
	}
	if len(rows[3].ScopedRoles) == 0 || !rows[3].Disabled || rows[3].IsAdmin {
		t.Fatalf("independent row axes = %+v", rows[3])
	}
}

func TestForgeViewerScenarioRowsUseBaselineAndExactCurrentPairEvidence(t *testing.T) {
	view := qualifyingViewerScenarioView()
	qualified, _, _, _ := forgeRoleEvidenceGate(view, 11)
	rows, counts, err := forgeViewerScenarioRows(view, 11, false, qualified, viewerScenarioAccessUsers())
	if err != nil {
		t.Fatal(err)
	}
	if rows[2].ScenarioOutcome != forgeViewerNoChangeOutcome ||
		rows[2].ScenarioDetail != "The Viewer baseline is off, so the scenario adds nothing. Every current role is retained." ||
		counts.AddedViewer != 0 || counts.NoChange != 3 {
		t.Fatalf("baseline-off rows=%+v counts=%+v", rows, counts)
	}

	view = qualifyingViewerScenarioView()
	view.Pairs[len(view.Pairs)-1].LatestRunID = view.LatestSnapshot.RunID - 1
	rows, _, err = forgeViewerScenarioRows(view, 11, true, true, viewerScenarioAccessUsers())
	if err != nil {
		t.Fatal(err)
	}
	if rows[2].ScenarioOutcome != forgeViewerIndeterminateOutcome ||
		rows[2].ScenarioDetail != "Viewer eligibility remains indeterminate. The Evidence column reports: The pair observation does not belong to the qualifying completed snapshot." ||
		rows[2].EvidenceObservedAt != "" || rows[2].EvidenceAge != "" {
		t.Fatalf("non-current pair row = %+v", rows[2])
	}

	view = qualifyingViewerScenarioView()
	users := viewerScenarioAccessUsers()
	users[3].Roles = auth.RoleSet{auth.RoleViewer}
	rows, _, err = forgeViewerScenarioRows(view, 11, true, true, users)
	if err != nil {
		t.Fatal(err)
	}
	if rows[3].ScenarioOutcome != forgeViewerCurrentOutcome ||
		rows[3].ScenarioDetail != "The current Viewer role is retained. No role is removed by this scenario." ||
		!rows[3].Disabled {
		t.Fatalf("disabled Viewer row = %+v", rows[3])
	}

	view = qualifyingViewerScenarioView()
	view.Pairs[len(view.Pairs)-1].LatestReason = forgeconnection.AccessReasonNoExplicitAccessNone
	rows, _, err = forgeViewerScenarioRows(view, 11, true, true, viewerScenarioAccessUsers())
	if err != nil {
		t.Fatal(err)
	}
	wantAbsentDetail := forgeRoleEvidenceAbsentOutcome + " " + forgeRoleEvidenceAbsenceCaveat
	if rows[2].ScenarioOutcome != forgeViewerNoChangeOutcome || rows[2].ScenarioDetail != wantAbsentDetail {
		t.Fatalf("confirmed-absence row = %+v", rows[2])
	}
}

func TestForgeViewerScenarioRowsKeepLinkedPopulationOutsidePairLimits(t *testing.T) {
	view := qualifyingViewerScenarioView()
	view.WithinLimits = false
	view.Pairs = nil
	qualified, _, _, _ := forgeRoleEvidenceGate(view, 11)
	rows, counts, err := forgeViewerScenarioRows(view, 11, true, qualified, viewerScenarioAccessUsers())
	if err != nil {
		t.Fatal(err)
	}
	if qualified || rows[2].ScenarioOutcome != forgeViewerIndeterminateOutcome ||
		rows[2].ScenarioDetail != "Viewer eligibility remains indeterminate. See the global evidence gate above for the blocking facts." || !rows[2].Linked ||
		rows[2].UsernameAtLink != "candidate-user" || counts.IndeterminateViewer != 1 {
		t.Fatalf("outside-limit rows=%+v counts=%+v", rows, counts)
	}
}

func TestForgeViewerScenarioRowsRejectMalformedComposition(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*forgeconnection.AccessShadowView, *[]auth.RepositoryAccessUser)
	}{
		{
			name: "nonpositive linked id",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.LinkedUsers[0].UserID = 0
			},
		},
		{
			name: "duplicate linked id",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.LinkedUsers[1].UserID = view.LinkedUsers[0].UserID
			},
		},
		{
			name: "identity count mismatch",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.IdentityCount--
			},
		},
		{
			name: "duplicate pair key",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.Pairs = append(view.Pairs, view.Pairs[0])
			},
		},
		{
			name: "missing selected pair",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.Pairs = view.Pairs[:len(view.Pairs)-1]
			},
		},
		{
			name: "extra selected pair",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.Pairs = append(view.Pairs, forgeconnection.AccessShadowPairRow{
					IdentityID: 99, UserID: 99, RepositoryID: 11,
				})
			},
		},
		{
			name: "pair rows outside limits",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.WithinLimits = false
			},
		},
		{
			name: "pair label contradiction",
			mutate: func(view *forgeconnection.AccessShadowView, _ *[]auth.RepositoryAccessUser) {
				view.Pairs[0].UserEmail = "different@example.test"
			},
		},
		{
			name: "nonpositive auth id",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				(*users)[0].UserID = 0
			},
		},
		{
			name: "duplicate auth id",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				*users = append(*users, (*users)[0])
			},
		},
		{
			name: "linked user absent from auth",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				*users = slices.Delete(*users, 2, 3)
			},
		},
		{
			name: "unlinked zero-role auth user",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				*users = append(*users, auth.RepositoryAccessUser{UserID: 99, Email: "extra@example.test", DisplayName: "Extra"})
			},
		},
		{
			name: "display-name contradiction",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				(*users)[0].DisplayName = "Different"
			},
		},
		{
			name: "email contradiction",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				(*users)[0].Email = "different@example.test"
			},
		},
		{
			name: "disabled contradiction",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				(*users)[0].Disabled = true
			},
		},
		{
			name: "noncanonical roles",
			mutate: func(_ *forgeconnection.AccessShadowView, users *[]auth.RepositoryAccessUser) {
				(*users)[0].Roles = auth.RoleSet{auth.RoleFreezer, auth.RoleViewer}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := qualifyingViewerScenarioView()
			users := viewerScenarioAccessUsers()
			tc.mutate(&view, &users)
			if _, _, err := forgeViewerScenarioRows(view, 11, true, true, users); err == nil {
				t.Fatal("malformed composition was accepted")
			}
		})
	}
}

func TestForgeViewerScenarioQueryBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		rawQuery   string
		forceQuery bool
	}{
		{name: "no query"},
		{name: "bare question mark", forceQuery: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, authService, shadow, session := newViewerScenarioServer(
				qualifyingViewerScenarioView(),
				viewerScenarioAccessUsers(),
			)
			response := viewerScenarioGET(server, session, tc.rawQuery, tc.forceQuery)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Choose a repository") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if len(authService.calls) != 0 || shadow.viewCalls != 1 {
				t.Fatalf("calls: auth=%+v shadow=%d", authService.calls, shadow.viewCalls)
			}
			tag := renderedControlTag(t, response.Body.String(), "viewer-scenario-baseline")
			if strings.Contains(tag, "checked") || strings.Contains(tag, "disabled") {
				t.Fatalf("unselected baseline checkbox = %q", tag)
			}
		})
	}
	for _, rawQuery := range []string{
		"repository_id=11&viewer_baseline=qualifying_explicit_access",
		"viewer_baseline=qualifying_explicit_access&repository_id=11",
	} {
		t.Run("canonical "+rawQuery, func(t *testing.T) {
			server, authService, shadow, session := newViewerScenarioServer(
				qualifyingViewerScenarioView(),
				viewerScenarioAccessUsers(),
			)
			response := viewerScenarioGET(server, session, rawQuery, false)
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if len(authService.calls) != 1 || shadow.viewCalls != 1 {
				t.Fatalf("calls: auth=%+v shadow=%d", authService.calls, shadow.viewCalls)
			}
			tag := renderedControlTag(t, response.Body.String(), "viewer-scenario-baseline")
			if !strings.Contains(tag, "checked") {
				t.Fatalf("canonical baseline checkbox = %q", tag)
			}
		})
	}

	for _, rawQuery := range []string{
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
		"viewer_baseline=qualifying_explicit_access",
		"repository_id=1&viewer_baseline=",
		"repository_id=1&viewer_baseline=other",
		"repository_id=1&viewer_baseline=qualifying_explicit_access&viewer_baseline=qualifying_explicit_access",
		"repository_id=1&",
		"&repository_id=1",
		"repository_id=1&&viewer_baseline=qualifying_explicit_access",
		"%72epository_id=11",
		"repository_id=%31%31",
		"repository_id=11&%76iewer_baseline=qualifying_explicit_access",
		"repository_id=11&viewer%5Fbaseline=qualifying_explicit_access",
		"repository_id=11&viewer_baseline=%71ualifying_explicit_access",
		"repository_id=11&viewer_baseline=qualifying%5Fexplicit_access",
		"repository_id=11&viewer_baseline=qualifying+explicit+access",
	} {
		t.Run(rawQuery, func(t *testing.T) {
			server, authService, shadow, session := newViewerScenarioServer(
				qualifyingViewerScenarioView(),
				viewerScenarioAccessUsers(),
			)
			response := viewerScenarioGET(server, session, rawQuery, false)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "Bad request") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if len(authService.calls) != 0 || shadow.viewCalls != 0 {
				t.Fatalf("malformed query reached services: auth=%+v shadow=%d", authService.calls, shadow.viewCalls)
			}
		})
	}
}

func TestForgeViewerScenarioPageRendersUnsavedScenario(t *testing.T) {
	server, authService, shadow, session := newViewerScenarioServer(
		qualifyingViewerScenarioView(),
		viewerScenarioAccessUsers(),
	)
	response := viewerScenarioGET(
		server,
		session,
		"viewer_baseline=qualifying_explicit_access&repository_id=11",
		false,
	)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	assertForgeAccessSecurityHeaders(t, response.Header())
	if shadow.viewCalls != 1 || len(authService.calls) != 1 || authService.calls[0].repositoryID != 11 ||
		!slices.Equal(authService.calls[0].linkedIDs, []int64{1, 2, 4, 5}) {
		t.Fatalf("service calls: shadow=%d auth=%+v", shadow.viewCalls, authService.calls)
	}
	body := response.Body.String()
	for _, fragment := range []string{
		"Viewer access scenario",
		"This is an unsaved request-time scenario. It preserves every current role and changes no Thawguard or Forgejo authority. It is not a saved policy, exact preflight, Apply plan, or reusable authorization proof.",
		"Forge linkage and evidence are loaded separately from local account and role state. They may change between those reads, so this is not an atomic authorization snapshot.",
		"Thawguard stores no scenario or Activity event. The repository and baseline values in this URL may still appear in browser history or deployment access logs.",
		"fixture-org/alpha",
		"Baseline on",
		"Qualifying completed evidence",
		"Newer non-completed attempt",
		"Current Viewer retained",
		"Scenario adds Viewer",
		"Viewer eligibility indeterminate",
		"Scenario adds nothing",
		"Account state",
		"Admin",
		"Current roles",
		"Linkage",
		"Evidence",
		"Scenario outcome",
		"Non-exercisable while disabled",
		"Forgejo username at link (historical): candidate-user",
		"Observed 2026-08-14 09:58:00 UTC · 2 min ago",
		`href="/settings/forge-access/role-evidence"`,
		`href="/settings/forge-access/shadow-access"`,
		`href="/settings/forge-access"`,
		`href="/users"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("page is missing %q", fragment)
		}
	}
	if tag := renderedControlTag(t, body, "viewer-scenario-baseline"); !strings.Contains(tag, `value="qualifying_explicit_access"`) || !strings.Contains(tag, "checked") ||
		strings.Contains(tag, "disabled") {
		t.Fatalf("baseline-on checkbox = %q", tag)
	}
	for _, control := range []string{
		">Save<", ">Apply<", ">Allow<", ">Deny<", ">Remove<", ">Reconcile<",
	} {
		if strings.Contains(body, control) {
			t.Fatalf("page contains forbidden control %q", control)
		}
	}
}

func TestForgeViewerScenarioLogsInternalFailureStage(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stage     string
		configure func(*fakeViewerScenarioAuthService, *fakeForgeAccessShadowService)
		users     []auth.RepositoryAccessUser
	}{
		{
			name:  "shadow read",
			stage: "shadow_read",
			configure: func(_ *fakeViewerScenarioAuthService, shadow *fakeForgeAccessShadowService) {
				shadow.viewErr = errors.New("shadow failed")
			},
			users: viewerScenarioAccessUsers(),
		},
		{
			name:  "auth union read",
			stage: "auth_union_read",
			configure: func(authService *fakeViewerScenarioAuthService, _ *fakeForgeAccessShadowService) {
				authService.userErr = errors.New("auth failed")
			},
			users: viewerScenarioAccessUsers(),
		},
		{
			name:  "composition",
			stage: "composition",
			configure: func(_ *fakeViewerScenarioAuthService, _ *fakeForgeAccessShadowService) {
			},
			users: func() []auth.RepositoryAccessUser {
				users := viewerScenarioAccessUsers()
				users[0].Roles = auth.RoleSet{auth.RoleFreezer, auth.RoleViewer}
				return users
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, authService, shadow, session := newViewerScenarioServer(
				qualifyingViewerScenarioView(),
				tc.users,
			)
			var logs bytes.Buffer
			server.cfg.Logger = slog.New(slog.NewJSONHandler(&logs, nil))
			tc.configure(authService, shadow)
			response := viewerScenarioGET(server, session, "repository_id=11", false)
			if response.Code != http.StatusInternalServerError {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			logText := logs.String()
			for _, fragment := range []string{
				`"level":"ERROR"`,
				`"msg":"forge Viewer scenario failed"`,
				`"route":"/settings/forge-access/viewer-scenario"`,
				`"status":500`,
				`"stage":"` + tc.stage + `"`,
			} {
				if !strings.Contains(logText, fragment) {
					t.Fatalf("diagnostic is missing %q: %s", fragment, logText)
				}
			}
			if strings.Contains(logText, "repository_id=11") {
				t.Fatalf("diagnostic contains request query: %s", logText)
			}
		})
	}
}

func TestForgeViewerScenarioRepositoryOnlyLeavesBaselineUnchecked(t *testing.T) {
	server, _, _, session := newViewerScenarioServer(qualifyingViewerScenarioView(), viewerScenarioAccessUsers())
	response := viewerScenarioGET(server, session, "repository_id=11", false)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "Baseline off") {
		t.Fatalf("baseline-off badge missing: %q", body)
	}
	if tag := renderedControlTag(t, body, "viewer-scenario-baseline"); strings.Contains(tag, "checked") || strings.Contains(tag, "disabled") {
		t.Fatalf("repository-only checkbox = %q", tag)
	}
}

func TestForgeViewerScenarioDisablesBaselineOnlyWithoutBoundRepositories(t *testing.T) {
	view := forgeconnection.AccessShadowView{HasConnection: true}
	server, _, _, session := newViewerScenarioServer(view, nil)
	response := viewerScenarioGET(server, session, "", false)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if tag := renderedControlTag(t, response.Body.String(), "viewer-scenario-baseline"); !strings.Contains(tag, "disabled") {
		t.Fatalf("no-binding checkbox = %q", tag)
	}
}

func TestForgeViewerScenarioFailureOrderingAndAuthorization(t *testing.T) {
	t.Run("stale repository stops before auth", func(t *testing.T) {
		view := qualifyingViewerScenarioView()
		view.BoundRepositories[0].RepositoryID = 12
		server, authService, shadow, session := newViewerScenarioServer(view, viewerScenarioAccessUsers())
		response := viewerScenarioGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusNotFound || len(authService.calls) != 0 || shadow.viewCalls != 1 {
			t.Fatalf("status=%d auth=%+v shadow=%d", response.Code, authService.calls, shadow.viewCalls)
		}
	})

	t.Run("shadow failure stops before auth", func(t *testing.T) {
		server, authService, shadow, session := newViewerScenarioServer(
			qualifyingViewerScenarioView(),
			viewerScenarioAccessUsers(),
		)
		shadow.viewErr = errors.New("shadow failed")
		response := viewerScenarioGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusInternalServerError || len(authService.calls) != 0 {
			t.Fatalf("status=%d auth=%+v", response.Code, authService.calls)
		}
	})

	t.Run("auth failure renders no partial rows", func(t *testing.T) {
		server, authService, _, session := newViewerScenarioServer(
			qualifyingViewerScenarioView(),
			viewerScenarioAccessUsers(),
		)
		authService.userErr = errors.New("auth failed")
		response := viewerScenarioGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "Scenario outcome counts") ||
			len(authService.calls) != 1 {
			t.Fatalf("status=%d calls=%+v body=%q", response.Code, authService.calls, response.Body.String())
		}
	})

	t.Run("composition failure renders no partial rows", func(t *testing.T) {
		users := viewerScenarioAccessUsers()
		users[0].Roles = auth.RoleSet{auth.RoleFreezer, auth.RoleViewer}
		server, authService, _, session := newViewerScenarioServer(qualifyingViewerScenarioView(), users)
		response := viewerScenarioGET(server, session, "repository_id=11", false)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "Scenario outcome counts") ||
			len(authService.calls) != 1 {
			t.Fatalf("status=%d calls=%+v body=%q", response.Code, authService.calls, response.Body.String())
		}
	})

	t.Run("missing service", func(t *testing.T) {
		session := roleEvidenceSession(true)
		authService := &fakeViewerScenarioAuthService{session: session}
		server := NewServer(Config{AppName: "Thawguard", AuthService: authService})
		response := viewerScenarioGET(server, session, "", false)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("status=%d", response.Code)
		}
	})

	t.Run("Administrator required", func(t *testing.T) {
		session := roleEvidenceSession(false)
		authService := &fakeViewerScenarioAuthService{session: session}
		server := NewServer(Config{
			AppName:                  "Thawguard",
			AuthService:              authService,
			ForgeAccessShadowService: &fakeForgeAccessShadowService{view: qualifyingViewerScenarioView()},
		})
		response := viewerScenarioGET(server, session, "", false)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status=%d", response.Code)
		}
	})
}
