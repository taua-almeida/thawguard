package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

type fakeForgeAccessShadowService struct {
	view    forgeconnection.AccessShadowView
	viewErr error

	runResult forgeconnection.AccessSyncResultCode
	runErr    error
	runCalls  []forgeconnection.RunAccessShadowInput
	runActors []int64

	enableNoOp    bool
	enableErr     error
	enableCalls   []forgeconnection.EnableAccessShadowPeriodicInput
	enableActors  []int64
	disableErr    error
	disableCalls  []forgeconnection.DisableAccessShadowPeriodicInput
	disableActors []int64
}

func (f *fakeForgeAccessShadowService) EnablePeriodic(
	_ context.Context,
	actorUserID int64,
	input forgeconnection.EnableAccessShadowPeriodicInput,
) (bool, error) {
	f.enableCalls = append(f.enableCalls, input)
	f.enableActors = append(f.enableActors, actorUserID)
	return !f.enableNoOp, f.enableErr
}

func (f *fakeForgeAccessShadowService) DisablePeriodic(
	_ context.Context,
	actorUserID int64,
	input forgeconnection.DisableAccessShadowPeriodicInput,
) error {
	f.disableCalls = append(f.disableCalls, input)
	f.disableActors = append(f.disableActors, actorUserID)
	return f.disableErr
}

func (f *fakeForgeAccessShadowService) View(context.Context) (forgeconnection.AccessShadowView, error) {
	return f.view, f.viewErr
}

func (f *fakeForgeAccessShadowService) Run(
	_ context.Context,
	actorUserID int64,
	input forgeconnection.RunAccessShadowInput,
) (forgeconnection.AccessSyncResultCode, error) {
	f.runCalls = append(f.runCalls, input)
	f.runActors = append(f.runActors, actorUserID)
	return f.runResult, f.runErr
}

func readyShadowView() forgeconnection.AccessShadowView {
	finished := time.Date(2026, 8, 10, 12, 1, 0, 0, time.UTC)
	return forgeconnection.AccessShadowView{
		HasConnection:          true,
		ConnectionID:           3,
		ConfigRevision:         1,
		CheckGeneration:        1,
		BindingRevision:        2,
		AccessIdentityRevision: 4,
		SetupEvidenceCurrent:   true,
		EncryptionAvailable:    true,
		IdentityCount:          2,
		BindingCount:           2,
		WithinLimits:           true,
		NewestRunID:            9,
		LatestAttempt: &forgeconnection.AccessShadowAttempt{
			Status:     forgeconnection.AccessAttemptCompleted,
			Trigger:    forgeconnection.AccessShadowRunManual,
			ResultCode: forgeconnection.AccessSyncComplete,
			StartedAt:  time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
			FinishedAt: &finished,
		},
		LatestSnapshot: &forgeconnection.AccessShadowSnapshot{
			PresentCount: 1,
			AbsentCount:  2,
			UnknownCount: 1,
			PairCount:    4,
			ScopeCurrent: true,
			Fresh:        true,
			ObservedAt:   finished,
		},
		Pairs: []forgeconnection.AccessShadowPairRow{
			{
				IdentityID:         21,
				RepositoryID:       11,
				UserDisplayName:    "Administrator",
				UserEmail:          "admin@example.test",
				UsernameAtLink:     "admin-user",
				RepositoryFullName: "fixture-org/alpha",
				Observed:           true,
				LatestReason:       forgeconnection.AccessReasonDirectCollaborator,
				LatestObservedAt:   finished,
			},
			{
				IdentityID:           21,
				RepositoryID:         12,
				UserDisplayName:      "Administrator",
				UserEmail:            "admin@example.test",
				UsernameAtLink:       "admin-user",
				RepositoryFullName:   "fixture-org/beta",
				Observed:             true,
				LatestReason:         forgeconnection.AccessReasonPermissionUnavailable,
				LatestObservedAt:     finished,
				PriorConfirmedReason: forgeconnection.AccessReasonNoExplicitAccessNone,
				PriorConfirmedAt:     time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC),
			},
			{
				IdentityID:         22,
				RepositoryID:       11,
				UserDisplayName:    "Developer",
				UserEmail:          "dev@example.test",
				UserDisabled:       true,
				UsernameAtLink:     "dev-user",
				RepositoryFullName: "fixture-org/alpha",
			},
		},
	}
}

func newForgeShadowServer(shadow *fakeForgeAccessShadowService, encryption bool) (*Server, *fakeForgeConnectionService) {
	connectionService := &fakeForgeConnectionService{
		connection: checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved),
		found:      true,
	}
	server := NewServer(Config{
		AppName:                "Thawguard",
		PublicURL:              forgeAccessTestPublicURL,
		ForgeConnectionService: connectionService,
		ForgeConnectionSecretEncryptionConfigured: encryption,
		ForgeAccessShadowService:                  shadow,
	})
	return server, connectionService
}

func validForgeShadowRunForm(session sessionState) url.Values {
	return url.Values{
		csrfFormField:                       {session.CSRFToken},
		"expected_connection_id":            {"3"},
		"expected_config_revision":          {"1"},
		"expected_check_generation":         {"1"},
		"expected_binding_revision":         {"2"},
		"expected_access_identity_revision": {"4"},
		"expected_newest_run_id":            {"9"},
		"confirm_shadow_only":               {forgeShadowConfirmValue},
	}
}

func validForgeShadowPeriodicEnableForm(session sessionState) url.Values {
	return url.Values{
		csrfFormField:                       {session.CSRFToken},
		"expected_connection_id":            {"3"},
		"expected_config_revision":          {"1"},
		"expected_check_generation":         {"1"},
		"expected_binding_revision":         {"2"},
		"expected_access_identity_revision": {"4"},
		"expected_newest_run_id":            {"9"},
		"expected_periodic_revision":        {"0"},
		"confirm_periodic_enable":           {forgePeriodicEnableConfirmValue},
	}
}

func validForgeShadowPeriodicDisableForm(session sessionState) url.Values {
	return url.Values{
		csrfFormField:                {session.CSRFToken},
		"expected_connection_id":     {"3"},
		"expected_periodic_revision": {"2"},
		"confirm_periodic_disable":   {forgePeriodicDisableConfirmValue},
	}
}

func TestForgeAccessPageRendersShadowSummaryAndRunForm(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView()}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	response := forgeAccessGET(server, session, "/settings/forge-access")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, fragment := range []string{
		"Shadow access snapshot",
		"credential-visible snapshot",
		"Run shadow snapshot",
		"Latest attempt",
		"Completed evidence",
		"Current · incomplete",
		"Periodic configuration",
		"Disabled",
		"Trigger: Manual",
		`name="expected_access_identity_revision" value="4"`,
		`name="expected_newest_run_id" value="9"`,
		`name="confirm_shadow_only" value="shadow-only"`,
		"Enable periodic refresh",
		"five minutes",
		"89-request constructive maximum",
		"96-request hard cap",
		"288 automatic attempts",
		"25,632 periodic requests per day",
		"27,648 attempted requests per day",
		"576 automatic Activity rows",
		"Manual snapshots add traffic",
		"one Thawguard process per SQLite database",
		`name="expected_periodic_revision" value="0"`,
		`name="confirm_periodic_enable" value="periodic-shadow-enable"`,
		"/settings/forge-access/shadow-access",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("page is missing %q", fragment)
		}
	}
}

func TestForgeAccessPageShadowStatesWithoutRunForm(t *testing.T) {
	view := readyShadowView()
	view.SetupEvidenceCurrent = false
	view.LatestAttempt.Status = forgeconnection.AccessAttemptInterrupted
	shadow := &fakeForgeAccessShadowService{view: view}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	body := forgeAccessGET(server, session, "/settings/forge-access").Body.String()
	if strings.Contains(body, "/settings/forge-access/shadow-access/run") {
		t.Fatal("run form rendered while prerequisites are unmet")
	}
	if !strings.Contains(body, "Interrupted") || !strings.Contains(body, "Not met") {
		t.Fatal("interrupted attempt and unmet prerequisite are not visible")
	}
}

func TestForgeAccessPageRendersIndependentPeriodicAttemptAndSnapshotAxes(t *testing.T) {
	view := readyShadowView()
	view.PeriodicRevision = 2
	due := time.Date(2026, 8, 10, 11, 50, 0, 0, time.UTC)
	view.PeriodicNextDueAt = &due
	view.PeriodicDueStatus = forgeconnection.AccessPeriodicOverdue
	view.PeriodicBlockers = []forgeconnection.AccessShadowPeriodicBlocker{
		forgeconnection.AccessPeriodicEncryptionUnavailable,
		forgeconnection.AccessPeriodicNoBindings,
	}
	view.LatestAttempt.Status = forgeconnection.AccessAttemptFailed
	view.LatestAttempt.Trigger = forgeconnection.AccessShadowRunPeriodic
	view.LatestAttempt.ResultCode = forgeconnection.AccessSyncUnavailable
	shadow := &fakeForgeAccessShadowService{view: view}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	body := forgeAccessGET(server, session, "/settings/forge-access").Body.String()
	for _, fragment := range []string{
		"Enabled · blocked",
		"No provider call occurs",
		"Service PAT encryption is unavailable.",
		"No repositories are bound.",
		"Overdue",
		"Trigger: Periodic",
		"Failed",
		"Current · incomplete",
		"Disable periodic refresh",
		"existing run may finish",
		"manual snapshots remain available",
		`name="confirm_periodic_disable" value="periodic-shadow-disable"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("independent axes page is missing %q", fragment)
		}
	}
}

func TestForgeShadowPresentationFreshnessAndRunningPrecedence(t *testing.T) {
	base := &forgeconnection.AccessShadowSnapshot{ScopeCurrent: true}
	for _, tc := range []struct {
		name    string
		fresh   bool
		unknown int64
		label   string
	}{
		{name: "current complete", fresh: true, label: "Current · complete"},
		{name: "current incomplete", fresh: true, unknown: 1, label: "Current · incomplete"},
		{name: "stale complete", label: "Stale · complete"},
		{name: "stale incomplete", unknown: 1, label: "Stale · incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := *base
			snapshot.Fresh = tc.fresh
			snapshot.UnknownCount = tc.unknown
			label, _, _ := forgeShadowSnapshotPresentation(&snapshot)
			if label != tc.label {
				t.Fatalf("label = %q want %q", label, tc.label)
			}
		})
	}
	changed := *base
	changed.ScopeCurrent = false
	if label, _, _ := forgeShadowSnapshotPresentation(&changed); label != "Scope changed" {
		t.Fatalf("scope-changed label = %q", label)
	}

	view := readyShadowView()
	view.PeriodicDueStatus = forgeconnection.AccessPeriodicRunning
	view.LatestAttempt.Trigger = forgeconnection.AccessShadowRunPeriodic
	view.LatestAttempt.Status = forgeconnection.AccessAttemptRunning
	section := forgeShadowSection(view)
	if section.PeriodicConfigLabel != "Disabled" || section.PeriodicDueLabel != "Running" {
		t.Fatalf("disabled in-flight axes = %+v", section)
	}
}

func TestForgeShadowDetailsPageRendersPairEvidence(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView()}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	response := forgeAccessGET(server, session, "/settings/forge-access/shadow-access")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	header := response.Header()
	if header.Get("Cache-Control") != "no-store" ||
		header.Get("Referrer-Policy") != "same-origin" ||
		header.Get("X-Frame-Options") != "DENY" ||
		header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.Contains(header.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("sensitive headers missing: %v", header)
	}
	body := response.Body.String()
	for _, fragment := range []string{
		"Pair evidence",
		"Administrator",
		"admin-user",
		"historical",
		"fixture-org/alpha",
		"Explicit access observed",
		"Unknown",
		"Never observed",
		"Previously confirmed",
		"No explicit access observed",
		"Disabled",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("details page is missing %q", fragment)
		}
	}
}

func TestForgeShadowDetailsPageRequiresAdminAndService(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView()}
	server, _ := newForgeShadowServer(shadow, true)
	session, err := server.sessions.create()
	if err != nil {
		t.Fatal(err)
	}
	userID := int64(8)
	session.UserID = &userID
	session.Grants = auth.NewGrants(false, nil)
	server.sessions.mu.Lock()
	server.sessions.sessions[session.ID] = session
	server.sessions.mu.Unlock()
	if response := forgeAccessGET(server, session, "/settings/forge-access/shadow-access"); response.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", response.Code)
	}

	unavailable, _ := newForgeShadowServer(nil, true)
	unavailable.cfg.ForgeAccessShadowService = nil
	adminSession := forgeAccessAdminSession(t, unavailable)
	if response := forgeAccessGET(unavailable, adminSession, "/settings/forge-access/shadow-access"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d", response.Code)
	}
}

func TestForgeShadowRunPostRunsAndRedirects(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView(), runResult: forgeconnection.AccessSyncComplete}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", validForgeShadowRunForm(session), forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/settings/forge-access?notice="+forgeShadowCompleteNotice {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(shadow.runCalls) != 1 {
		t.Fatalf("run calls = %d", len(shadow.runCalls))
	}
	call := shadow.runCalls[0]
	if call.ExpectedConnectionID != 3 || call.ExpectedConfigRevision != 1 ||
		call.ExpectedCheckGeneration != 1 || call.ExpectedBindingRevision != 2 ||
		call.ExpectedAccessIdentityRevision != 4 || call.ExpectedNewestRunID != 9 ||
		!call.ConfirmShadowOnly {
		t.Fatalf("run input = %+v", call)
	}
	if shadow.runActors[0] != 7 {
		t.Fatalf("run actor = %d", shadow.runActors[0])
	}

	// A zero newest-run token is a valid first-run CAS value.
	first := validForgeShadowRunForm(session)
	first.Set("expected_newest_run_id", "0")
	if response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", first, forgeAccessTestPublicURL); response.Code != http.StatusSeeOther {
		t.Fatalf("zero newest-run status = %d", response.Code)
	}
	// A zero binding revision is canonical for bindings that predate the
	// revision column and must pass the form boundary.
	zeroBinding := validForgeShadowRunForm(session)
	zeroBinding.Set("expected_binding_revision", "0")
	if response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", zeroBinding, forgeAccessTestPublicURL); response.Code != http.StatusSeeOther {
		t.Fatalf("zero binding-revision status = %d", response.Code)
	}
	if last := shadow.runCalls[len(shadow.runCalls)-1]; last.ExpectedBindingRevision != 0 {
		t.Fatalf("zero binding revision reached the service as %d", last.ExpectedBindingRevision)
	}
}

func TestForgeShadowRunPostNoticeMapping(t *testing.T) {
	cases := []struct {
		name   string
		result forgeconnection.AccessSyncResultCode
		err    error
		notice string
	}{
		{name: "failure result", result: forgeconnection.AccessSyncUnavailable, notice: forgeShadowIncompleteNotice},
		{name: "superseded result", result: forgeconnection.AccessSyncScopeChanged, notice: forgeShadowSupersededNotice},
		{name: "stale", err: forgeconnection.ErrConflict, notice: forgeShadowStaleNotice},
		{name: "running", err: forgeconnection.ErrAccessSyncRunning, notice: forgeShadowRunningNotice},
		{name: "interrupted", err: forgeconnection.ErrAccessSyncInterrupted, notice: forgeShadowInterruptedNotice},
		{name: "authority", err: forgeconnection.ErrAuthorization, notice: forgeShadowAuthorityNotice},
		{name: "configuration", err: forgeconnection.ErrConfiguration, notice: forgeShadowUnavailableNotice},
		{name: "validation", err: forgeconnection.ValidationError{Message: "limits"}, notice: forgeShadowInvalidNotice},
		{name: "unknown", err: errors.New("boom"), notice: forgeShadowUnknownNotice},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shadow := &fakeForgeAccessShadowService{view: readyShadowView(), runResult: tc.result, runErr: tc.err}
			server, _ := newForgeShadowServer(shadow, true)
			session := forgeAccessAdminSession(t, server)
			response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", validForgeShadowRunForm(session), forgeAccessTestPublicURL)
			if response.Code != http.StatusSeeOther ||
				response.Header().Get("Location") != "/settings/forge-access?notice="+tc.notice {
				t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
		})
	}
}

func TestForgeShadowPeriodicEnableDisablePostsUseExactFencedInputs(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView()}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	enable := forgeAccessPOST(
		server,
		session,
		"/settings/forge-access/shadow-access/periodic/enable",
		validForgeShadowPeriodicEnableForm(session),
		forgeAccessTestPublicURL,
	)
	if enable.Code != http.StatusSeeOther ||
		enable.Header().Get("Location") != "/settings/forge-access?notice="+forgePeriodicEnabledNotice {
		t.Fatalf("enable status=%d location=%q", enable.Code, enable.Header().Get("Location"))
	}
	assertForgeAccessSecurityHeaders(t, enable.Header())
	if len(shadow.enableCalls) != 1 || shadow.enableActors[0] != 7 ||
		shadow.enableCalls[0] != (forgeconnection.EnableAccessShadowPeriodicInput{
			ExpectedConnectionID:           3,
			ExpectedConfigRevision:         1,
			ExpectedCheckGeneration:        1,
			ExpectedBindingRevision:        2,
			ExpectedAccessIdentityRevision: 4,
			ExpectedNewestRunID:            9,
			ExpectedPeriodicRevision:       0,
			ConfirmPeriodicEnable:          true,
		}) {
		t.Fatalf("enable calls=%+v actors=%v", shadow.enableCalls, shadow.enableActors)
	}

	disable := forgeAccessPOST(
		server,
		session,
		"/settings/forge-access/shadow-access/periodic/disable",
		validForgeShadowPeriodicDisableForm(session),
		forgeAccessTestPublicURL,
	)
	if disable.Code != http.StatusSeeOther ||
		disable.Header().Get("Location") != "/settings/forge-access?notice="+forgePeriodicDisabledNotice {
		t.Fatalf("disable status=%d location=%q", disable.Code, disable.Header().Get("Location"))
	}
	assertForgeAccessSecurityHeaders(t, disable.Header())
	if len(shadow.disableCalls) != 1 || shadow.disableActors[0] != 7 ||
		shadow.disableCalls[0] != (forgeconnection.DisableAccessShadowPeriodicInput{
			ExpectedConnectionID:     3,
			ExpectedPeriodicRevision: 2,
			ConfirmPeriodicDisable:   true,
		}) {
		t.Fatalf("disable calls=%+v actors=%v", shadow.disableCalls, shadow.disableActors)
	}
}

func TestForgeShadowPeriodicAlreadyEnabledNoOpHasTruthfulNotice(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView(), enableNoOp: true}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	response := forgeAccessPOST(
		server,
		session,
		"/settings/forge-access/shadow-access/periodic/enable",
		validForgeShadowPeriodicEnableForm(session),
		forgeAccessTestPublicURL,
	)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/settings/forge-access?notice="+forgePeriodicAlreadyEnabledNotice {
		t.Fatalf("no-op enable status=%d location=%q", response.Code, response.Header().Get("Location"))
	}

	body := forgeAccessGET(
		server,
		session,
		"/settings/forge-access?notice="+forgePeriodicAlreadyEnabledNotice,
	).Body.String()
	if !strings.Contains(body, "Its existing due time was not changed.") {
		t.Fatalf("no-op enable notice is not truthful: %q", body)
	}
}

func TestForgeShadowPeriodicPostsRejectMalformedOriginCSRFAndOversizedBodies(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView()}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)
	routes := []struct {
		name string
		path string
		form func(sessionState) url.Values
	}{
		{name: "enable", path: "/settings/forge-access/shadow-access/periodic/enable", form: validForgeShadowPeriodicEnableForm},
		{name: "disable", path: "/settings/forge-access/shadow-access/periodic/disable", form: validForgeShadowPeriodicDisableForm},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				mutate func(url.Values)
			}{
				{name: "missing field", mutate: func(form url.Values) { form.Del("expected_connection_id") }},
				{name: "duplicate field", mutate: func(form url.Values) { form.Add("expected_periodic_revision", "0") }},
				{name: "unknown field", mutate: func(form url.Values) { form.Set("extra", "1") }},
				{name: "noncanonical integer", mutate: func(form url.Values) { form.Set("expected_connection_id", "03") }},
				{name: "bad confirmation", mutate: func(form url.Values) {
					if route.name == "enable" {
						form.Set("confirm_periodic_enable", "yes")
					} else {
						form.Set("confirm_periodic_disable", "yes")
					}
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					form := route.form(session)
					tc.mutate(form)
					response := forgeAccessPOST(server, session, route.path, form, forgeAccessTestPublicURL)
					if response.Code != http.StatusBadRequest {
						t.Fatalf("status = %d", response.Code)
					}
				})
			}
			wrongCSRF := route.form(session)
			wrongCSRF.Set(csrfFormField, "wrong")
			if response := forgeAccessPOST(server, session, route.path, wrongCSRF, forgeAccessTestPublicURL); response.Code != http.StatusForbidden {
				t.Fatalf("wrong CSRF status = %d", response.Code)
			}
			if response := forgeAccessPOST(server, session, route.path, route.form(session), "https://evil.example.test"); response.Code != http.StatusForbidden {
				t.Fatalf("cross-origin status = %d", response.Code)
			}
			if response := forgeAccessPOST(server, session, route.path, route.form(session)); response.Code != http.StatusForbidden {
				t.Fatalf("missing-origin status = %d", response.Code)
			}
			oversized := route.form(session)
			if route.name == "enable" {
				oversized.Set("confirm_periodic_enable", strings.Repeat("x", int(forgeAccessActionMaxBodyBytes)))
			} else {
				oversized.Set("confirm_periodic_disable", strings.Repeat("x", int(forgeAccessActionMaxBodyBytes)))
			}
			if response := forgeAccessPOST(server, session, route.path, oversized, forgeAccessTestPublicURL); response.Code != http.StatusBadRequest {
				t.Fatalf("oversized status = %d", response.Code)
			}
		})
	}
	if len(shadow.enableCalls) != 0 || len(shadow.disableCalls) != 0 {
		t.Fatalf("rejected posts reached service: enable=%d disable=%d", len(shadow.enableCalls), len(shadow.disableCalls))
	}
}

func TestForgeShadowPeriodicPostsRequireEnabledUnforcedAdministrator(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView()}
	server, _ := newForgeShadowServer(shadow, true)
	nonAdmin, err := server.sessions.create()
	if err != nil {
		t.Fatal(err)
	}
	nonAdminID := int64(8)
	nonAdmin.UserID = &nonAdminID
	nonAdmin.Grants = auth.NewGrants(false, nil)
	server.sessions.mu.Lock()
	server.sessions.sessions[nonAdmin.ID] = nonAdmin
	server.sessions.mu.Unlock()

	admin := forgeAccessAdminSession(t, server)
	forced := admin
	forced.MustChangePassword = true
	server.sessions.mu.Lock()
	server.sessions.sessions[forced.ID] = forced
	server.sessions.mu.Unlock()

	for _, route := range []struct {
		path string
		form func(sessionState) url.Values
	}{
		{path: "/settings/forge-access/shadow-access/periodic/enable", form: validForgeShadowPeriodicEnableForm},
		{path: "/settings/forge-access/shadow-access/periodic/disable", form: validForgeShadowPeriodicDisableForm},
	} {
		response := forgeAccessPOST(server, nonAdmin, route.path, route.form(nonAdmin), forgeAccessTestPublicURL)
		if response.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s status = %d", route.path, response.Code)
		}
		response = forgeAccessPOST(server, forced, route.path, route.form(forced), forgeAccessTestPublicURL)
		if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/account/password" {
			t.Fatalf("forced-password %s status=%d location=%q", route.path, response.Code, response.Header().Get("Location"))
		}
	}
	if len(shadow.enableCalls) != 0 || len(shadow.disableCalls) != 0 {
		t.Fatalf("authorization gate reached service: enable=%d disable=%d", len(shadow.enableCalls), len(shadow.disableCalls))
	}
}

func TestForgeShadowPeriodicConfigurationKeepsHandlerEncryptionGate(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{
		view:      readyShadowView(),
		enableErr: forgeconnection.ErrConfiguration,
	}
	server, _ := newForgeShadowServer(shadow, false)
	session := forgeAccessAdminSession(t, server)

	enable := forgeAccessPOST(server, session,
		"/settings/forge-access/shadow-access/periodic/enable",
		validForgeShadowPeriodicEnableForm(session), forgeAccessTestPublicURL)
	if enable.Header().Get("Location") != "/settings/forge-access?notice="+forgePeriodicUnavailableNotice ||
		len(shadow.enableCalls) != 0 {
		t.Fatalf("no-encryption enable location=%q calls=%d", enable.Header().Get("Location"), len(shadow.enableCalls))
	}
	disable := forgeAccessPOST(server, session,
		"/settings/forge-access/shadow-access/periodic/disable",
		validForgeShadowPeriodicDisableForm(session), forgeAccessTestPublicURL)
	if disable.Header().Get("Location") != "/settings/forge-access?notice="+forgePeriodicDisabledNotice ||
		len(shadow.disableCalls) != 1 {
		t.Fatalf("no-encryption disable location=%q calls=%d", disable.Header().Get("Location"), len(shadow.disableCalls))
	}
}

func TestForgeShadowRunPostRejectsMalformedForms(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView(), runResult: forgeconnection.AccessSyncComplete}
	server, _ := newForgeShadowServer(shadow, true)
	session := forgeAccessAdminSession(t, server)

	cases := []struct {
		name   string
		mutate func(url.Values)
	}{
		{name: "missing fence", mutate: func(form url.Values) { form.Del("expected_access_identity_revision") }},
		{name: "duplicate fence", mutate: func(form url.Values) { form.Add("expected_newest_run_id", "9") }},
		{name: "unknown field", mutate: func(form url.Values) { form.Set("extra", "1") }},
		{name: "non-canonical fence", mutate: func(form url.Values) { form.Set("expected_connection_id", "03") }},
		{name: "negative newest run id", mutate: func(form url.Values) { form.Set("expected_newest_run_id", "-1") }},
		{name: "wrong confirmation", mutate: func(form url.Values) { form.Set("confirm_shadow_only", "yes") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := validForgeShadowRunForm(session)
			tc.mutate(form)
			response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", form, forgeAccessTestPublicURL)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
	if len(shadow.runCalls) != 0 {
		t.Fatalf("malformed forms reached the service %d times", len(shadow.runCalls))
	}

	if response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", validForgeShadowRunForm(session), "https://evil.example.test"); response.Code != http.StatusForbidden {
		t.Fatalf("cross-origin status = %d", response.Code)
	}
	if response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", validForgeShadowRunForm(session)); response.Code != http.StatusForbidden {
		t.Fatalf("missing origin status = %d", response.Code)
	}
	if len(shadow.runCalls) != 0 {
		t.Fatalf("rejected origins reached the service %d times", len(shadow.runCalls))
	}
}

func TestActivityForgeAccessSyncPresentation(t *testing.T) {
	actorID := int64(7)
	event := func(action, details string) audit.Event {
		return audit.Event{
			ActorUserID: &actorID,
			Action:      action,
			SubjectType: audit.SubjectTypeForgeConnection,
			SubjectID:   "1",
			DetailsJSON: details,
			CreatedAt:   time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		}
	}

	started := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncStarted,
		`{"run_id":4,"identity_count":2,"repository_count":3,"run_trigger":"manual"}`))
	if started.ActionLabel != "Shadow access snapshot" || started.Outcome != "Started" ||
		!strings.Contains(started.Detail, "Manual run 4") || !strings.Contains(started.Detail, "no roles or authority change") {
		t.Fatalf("started view = %+v", started)
	}

	complete := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"complete","run_trigger":"manual","present_count":2,"unknown_count":1,"request_count":40}`))
	if complete.Outcome != "Completed" || complete.OutcomeClass != "ok" ||
		!strings.Contains(complete.Detail, "2 explicit-access and 1 unknown pairs") ||
		!strings.Contains(complete.Detail, "40 provider request attempts") {
		t.Fatalf("complete view = %+v", complete)
	}

	interrupted := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"interrupted","run_trigger":"manual"}`))
	if interrupted.Outcome != "Interrupted" || interrupted.OutcomeClass != "warning" ||
		strings.Contains(interrupted.Detail, "provider request attempts") {
		t.Fatalf("interrupted view = %+v", interrupted)
	}

	// The durable scope_changed result renders as Superseded, matching the
	// attempt axis, never as a failure.
	superseded := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"scope_changed","run_trigger":"manual","request_count":12}`))
	if superseded.Outcome != "Superseded" || superseded.OutcomeClass != "warning" ||
		!strings.Contains(superseded.Detail, "identity/binding scope changed") {
		t.Fatalf("superseded view = %+v", superseded)
	}

	failed := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"authentication_failed","run_trigger":"manual","request_count":2}`))
	if failed.Outcome != "Failed" || failed.OutcomeClass != "failed" ||
		!strings.Contains(failed.Detail, "was not accepted") {
		t.Fatalf("failed view = %+v", failed)
	}

	periodicEvent := func(action, details string) audit.Event {
		return audit.Event{
			Action:      action,
			SubjectType: audit.SubjectTypeForgeConnection,
			SubjectID:   "1",
			DetailsJSON: details,
			CreatedAt:   time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		}
	}
	periodicStarted := activityEventViewForEvent(nil, nil, periodicEvent(
		audit.ActionForgeAccessSyncStarted,
		`{"run_id":5,"identity_count":2,"repository_count":3,"run_trigger":"periodic","actor_kind":"system","actor_role":"shadow_refresh_runner"}`,
	))
	if periodicStarted.Actor != "Shadow refresh runner" ||
		!strings.Contains(periodicStarted.Detail, "Periodic run 5") {
		t.Fatalf("periodic started view = %+v", periodicStarted)
	}
	periodicFinished := activityEventViewForEvent(nil, nil, periodicEvent(
		audit.ActionForgeAccessSyncFinished,
		`{"run_id":5,"result_code":"interrupted","run_trigger":"periodic","actor_kind":"system","actor_role":"shadow_refresh_runner"}`,
	))
	if periodicFinished.Actor != "Shadow refresh runner" || periodicFinished.Outcome != "Interrupted" {
		t.Fatalf("periodic finished view = %+v", periodicFinished)
	}
	deletedManual := periodicEvent(
		audit.ActionForgeAccessSyncFinished,
		`{"run_id":6,"result_code":"interrupted","run_trigger":"manual"}`,
	)
	deletedManualView := activityEventViewForEvent(nil, nil, deletedManual)
	if deletedManualView.Actor != "Deleted user" || !strings.Contains(deletedManualView.Detail, "Manual run 6") {
		t.Fatalf("deleted manual requester view = %+v", deletedManualView)
	}
	legacyManual := periodicEvent(
		audit.ActionForgeAccessSyncFinished,
		`{"run_id":3,"result_code":"interrupted"}`,
	)
	legacyManualView := activityEventViewForEvent(nil, nil, legacyManual)
	if legacyManualView.Actor != "Deleted user" || !strings.Contains(legacyManualView.Detail, "Manual run 3") {
		t.Fatalf("legacy manual event view = %+v", legacyManualView)
	}
	periodicConfig := event(audit.ActionForgeAccessPeriodicEnabled, `{"revision":3}`)
	periodicConfigView := activityEventViewForEvent(nil, nil, periodicConfig)
	if periodicConfigView.ActionLabel != "Periodic shadow refresh" || periodicConfigView.Outcome != "Enabled" ||
		!strings.Contains(periodicConfigView.Detail, "revision 3") {
		t.Fatalf("periodic config view = %+v", periodicConfigView)
	}
	deletedConfig := periodicConfig
	deletedConfig.ActorUserID = nil
	if got := activityEventViewForEvent(nil, nil, deletedConfig); got.Actor != "Deleted user" {
		t.Fatalf("deleted periodic configuration actor view = %+v", got)
	}

	// Malformed shapes fall back instead of rendering partial evidence.
	for name, details := range map[string]string{
		"failure with pair counts":  `{"run_id":4,"result_code":"unavailable","run_trigger":"manual","present_count":1,"unknown_count":0}`,
		"complete without counts":   `{"run_id":4,"result_code":"complete","run_trigger":"manual"}`,
		"unknown result code":       `{"run_id":4,"result_code":"observed","run_trigger":"manual"}`,
		"unexpected detail key":     `{"run_id":4,"result_code":"interrupted","run_trigger":"manual","provider_error":"leak"}`,
		"duplicated guarded key":    `{"run_id":4,"run_id":5,"result_code":"interrupted","run_trigger":"manual"}`,
		"periodic with human actor": `{"run_id":4,"result_code":"interrupted","run_trigger":"periodic","actor_kind":"system","actor_role":"shadow_refresh_runner"}`,
		"periodic wrong role":       `{"run_id":4,"result_code":"interrupted","run_trigger":"periodic","actor_kind":"system","actor_role":"scheduler"}`,
		"manual system metadata":    `{"run_id":4,"result_code":"interrupted","run_trigger":"manual","actor_kind":"system","actor_role":"shadow_refresh_runner"}`,
	} {
		view := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished, details))
		if view.ActionLabel != "Unrecognized activity" {
			t.Fatalf("%s rendered as %+v", name, view)
		}
	}
}

func TestForgeShadowRunPostKeepsHandlerEncryptionGate(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView(), runErr: forgeconnection.ErrConfiguration}
	server, _ := newForgeShadowServer(shadow, false)
	session := forgeAccessAdminSession(t, server)
	response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", validForgeShadowRunForm(session), forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/settings/forge-access?notice="+forgeShadowUnavailableNotice {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(shadow.runCalls) != 0 {
		t.Fatalf("run service calls = %d, want 0", len(shadow.runCalls))
	}
}
