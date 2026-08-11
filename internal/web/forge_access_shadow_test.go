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
		IdentityCount:          2,
		BindingCount:           2,
		WithinLimits:           true,
		NewestRunID:            9,
		LatestAttempt: &forgeconnection.AccessShadowAttempt{
			Status:     forgeconnection.AccessAttemptCompleted,
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
		"Latest completed snapshot",
		"Scope unchanged · incomplete",
		`name="expected_access_identity_revision" value="4"`,
		`name="expected_newest_run_id" value="9"`,
		`name="confirm_shadow_only" value="shadow-only"`,
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
		`{"run_id":4,"identity_count":2,"repository_count":3}`))
	if started.ActionLabel != "Shadow access snapshot" || started.Outcome != "Started" ||
		!strings.Contains(started.Detail, "Run 4") || !strings.Contains(started.Detail, "no roles or authority change") {
		t.Fatalf("started view = %+v", started)
	}

	complete := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"complete","present_count":2,"unknown_count":1,"request_count":40}`))
	if complete.Outcome != "Completed" || complete.OutcomeClass != "ok" ||
		!strings.Contains(complete.Detail, "2 explicit-access and 1 unknown pairs") ||
		!strings.Contains(complete.Detail, "40 provider request attempts") {
		t.Fatalf("complete view = %+v", complete)
	}

	interrupted := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"interrupted"}`))
	if interrupted.Outcome != "Interrupted" || interrupted.OutcomeClass != "warning" ||
		strings.Contains(interrupted.Detail, "provider request attempts") {
		t.Fatalf("interrupted view = %+v", interrupted)
	}

	// The durable scope_changed result renders as Superseded, matching the
	// attempt axis, never as a failure.
	superseded := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"scope_changed","request_count":12}`))
	if superseded.Outcome != "Superseded" || superseded.OutcomeClass != "warning" ||
		!strings.Contains(superseded.Detail, "identity/binding scope changed") {
		t.Fatalf("superseded view = %+v", superseded)
	}

	failed := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished,
		`{"run_id":4,"result_code":"authentication_failed","request_count":2}`))
	if failed.Outcome != "Failed" || failed.OutcomeClass != "failed" ||
		!strings.Contains(failed.Detail, "was not accepted") {
		t.Fatalf("failed view = %+v", failed)
	}

	// Malformed shapes fall back instead of rendering partial evidence.
	for name, details := range map[string]string{
		"failure with pair counts": `{"run_id":4,"result_code":"unavailable","present_count":1,"unknown_count":0}`,
		"complete without counts":  `{"run_id":4,"result_code":"complete"}`,
		"unknown result code":      `{"run_id":4,"result_code":"observed"}`,
		"unexpected detail key":    `{"run_id":4,"result_code":"interrupted","provider_error":"leak"}`,
		"duplicated guarded key":   `{"run_id":4,"run_id":5,"result_code":"interrupted"}`,
	} {
		view := activityEventViewForEvent(nil, nil, event(audit.ActionForgeAccessSyncFinished, details))
		if view.ActionLabel != "Unrecognized activity" {
			t.Fatalf("%s rendered as %+v", name, view)
		}
	}
}

func TestForgeShadowRunPostUnavailableWithoutEncryption(t *testing.T) {
	shadow := &fakeForgeAccessShadowService{view: readyShadowView(), runResult: forgeconnection.AccessSyncComplete}
	server, _ := newForgeShadowServer(shadow, false)
	session := forgeAccessAdminSession(t, server)
	response := forgeAccessPOST(server, session, "/settings/forge-access/shadow-access/run", validForgeShadowRunForm(session), forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "/settings/forge-access?notice="+forgeShadowUnavailableNotice {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(shadow.runCalls) != 0 {
		t.Fatal("run reached the service without encryption")
	}
}
