package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

const (
	forgeAccessTestPublicURL = "http://localhost:8080"
	forgeAccessTestPAT       = "fictional-forge-access-pat"
)

type fakeForgeConnectionService struct {
	connection forgeconnection.Connection
	found      bool
	currentErr error

	bindingModel forgeconnection.RepositoryBindingReadModel
	listErr      error

	createErr, editErr, resetErr, checkErr, bindErr, unbindErr error

	createCalls []forgeconnection.CreateInput
	editCalls   []forgeconnection.EditInput
	resetCalls  []forgeconnection.ResetInput
	checkCalls  []forgeAccessCheckCall
	bindCalls   []forgeconnection.BindRepositoryInput
	unbindCalls []forgeconnection.UnbindRepositoryInput
}

type forgeAccessCheckCall struct {
	ConnectionID int64
	Revision     int64
}

func (f *fakeForgeConnectionService) Current(context.Context) (forgeconnection.Connection, bool, error) {
	return f.connection, f.found, f.currentErr
}

func (f *fakeForgeConnectionService) RepositoryBindings(context.Context, int64) (forgeconnection.RepositoryBindingReadModel, error) {
	if f.listErr != nil {
		return forgeconnection.RepositoryBindingReadModel{}, f.listErr
	}
	return f.bindingModel, nil
}

func (f *fakeForgeConnectionService) Create(_ context.Context, _ int64, input forgeconnection.CreateInput) error {
	f.createCalls = append(f.createCalls, input)
	return f.createErr
}

func (f *fakeForgeConnectionService) Edit(_ context.Context, _ int64, input forgeconnection.EditInput) error {
	f.editCalls = append(f.editCalls, input)
	return f.editErr
}

func (f *fakeForgeConnectionService) Reset(_ context.Context, _ int64, input forgeconnection.ResetInput) error {
	f.resetCalls = append(f.resetCalls, input)
	return f.resetErr
}

func (f *fakeForgeConnectionService) Check(_ context.Context, _ int64, connectionID, revision int64) (forgeconnection.SetupCheck, error) {
	f.checkCalls = append(f.checkCalls, forgeAccessCheckCall{ConnectionID: connectionID, Revision: revision})
	return forgeconnection.SetupCheck{}, f.checkErr
}

func (f *fakeForgeConnectionService) BindRepository(_ context.Context, _ int64, input forgeconnection.BindRepositoryInput) error {
	f.bindCalls = append(f.bindCalls, input)
	return f.bindErr
}

func (f *fakeForgeConnectionService) UnbindRepository(_ context.Context, _ int64, input forgeconnection.UnbindRepositoryInput) error {
	f.unbindCalls = append(f.unbindCalls, input)
	return f.unbindErr
}

func newForgeAccessServer(service *fakeForgeConnectionService, encryption bool) *Server {
	return NewServer(Config{
		AppName:                "Thawguard",
		PublicURL:              forgeAccessTestPublicURL,
		ForgeConnectionService: service,
		ForgeConnectionSecretEncryptionConfigured: encryption,
	})
}

func forgeAccessAdminSession(t *testing.T, server *Server) sessionState {
	t.Helper()
	session, err := server.sessions.create()
	if err != nil {
		t.Fatal(err)
	}
	userID := int64(7)
	session.UserID = &userID
	session.Grants = auth.NewGrants(true, nil)
	server.sessions.mu.Lock()
	server.sessions.sessions[session.ID] = session
	server.sessions.mu.Unlock()
	return session
}

func forgeAccessGET(server *Server, session sessionState, path string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func forgeAccessPOST(server *Server, session sessionState, path string, form url.Values, origins ...string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, origin := range origins {
		request.Header.Add("Origin", origin)
	}
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
	server.Routes().ServeHTTP(recorder, request)
	return recorder
}

func forgeAccessSaveForm(session sessionState, connectionID, revision string) url.Values {
	return url.Values{
		csrfFormField:            {session.CSRFToken},
		"display_name":           {"Fixture Forge"},
		"base_url":               {"https://forge.example.test"},
		"organization_slug":      {"fixture-org"},
		"service_pat":            {forgeAccessTestPAT},
		"pat_attested":           {forgeAccessPATAttestedValue},
		"expected_connection_id": {connectionID},
		"expected_revision":      {revision},
	}
}

func savedForgeConnection() forgeconnection.Connection {
	return forgeconnection.Connection{
		ID:               3,
		Provider:         forgeconnection.ProviderForgejo,
		DisplayName:      "Fixture Forge",
		BaseURL:          "https://forge.example.test",
		OrganizationSlug: "fixture-org",
		Revision:         1,
		CheckGeneration:  0,
		PATAttestedAt:    time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		CreatedAt:        time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		UpdatedAt:        time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
	}
}

func checkedForgeConnection(code forgeconnection.CheckResultCode) forgeconnection.Connection {
	connection := savedForgeConnection()
	connection.CheckGeneration = 1
	connection.ServiceUserRemoteID = "42"
	connection.Organization = &forgeconnection.Organization{
		RemoteID:    "7",
		Slug:        "fixture-org",
		DisplayName: "Fixture Organization",
		ObservedAt:  connection.CreatedAt,
	}
	check := &forgeconnection.SetupCheck{
		ConfigRevision:  1,
		CheckGeneration: 1,
		ResultCode:      code,
		ObservedVersion: "15.0.6",
		CheckedAt:       time.Date(2026, 8, 1, 11, 0, 0, 0, time.UTC),
	}
	if code.Observed() {
		visible := int64(2)
		private := int64(1)
		if code == forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven {
			private = 0
		}
		check.VisibleRepositoryCount = &visible
		check.VisiblePrivateRepositoryCount = &private
	}
	connection.SetupCheck = check
	return connection
}

// forgePreviewRow is one unbound remote-only preview row as the service
// derives it: RemoteFullNames always carries the row's retained locators.
func forgePreviewRow(name string, private bool, state forgeconnection.RepositoryBindingState) forgeconnection.RepositoryBindingRow {
	fullName := "fixture-org/" + name
	return forgeconnection.RepositoryBindingRow{
		State:               state,
		RemoteFullName:      fullName,
		RemoteFullNames:     []string{fullName},
		RemoteDefaultBranch: "main",
		RemotePrivate:       &private,
		ObservedAt:          time.Date(2026, 8, 1, 11, 0, 0, 0, time.UTC),
	}
}

// forgePreviewModel mirrors what the service derives for two retained
// unbound rows: unmatched while the preview is current, preview-not-current
// otherwise.
func forgePreviewModel(current bool) forgeconnection.RepositoryBindingReadModel {
	state := forgeconnection.RepositoryBindingUnmatched
	if !current {
		state = forgeconnection.RepositoryBindingPreviewNotCurrent
	}
	return forgeconnection.RepositoryBindingReadModel{
		Current: current,
		Rows: []forgeconnection.RepositoryBindingRow{
			forgePreviewRow("alpha", false, state),
			forgePreviewRow("beta", true, state),
		},
	}
}

func assertForgeAccessSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	if header.Get("Cache-Control") != "no-store" ||
		header.Get("X-Frame-Options") != "DENY" ||
		header.Get("X-Content-Type-Options") != "nosniff" ||
		header.Get("Referrer-Policy") != "same-origin" ||
		header.Get("Content-Security-Policy") != sensitiveFormCSP {
		t.Fatalf("missing sensitive-page headers: %+v", header)
	}
}

func TestForgeAccessRequiresAdministratorView(t *testing.T) {
	service := &fakeForgeConnectionService{}
	server := newForgeAccessServer(service, true)

	session, err := server.sessions.create()
	if err != nil {
		t.Fatal(err)
	}
	server.sessions.mu.Lock()
	server.sessions.sessions[session.ID] = session
	server.sessions.mu.Unlock()
	nonAdmin := forgeAccessGET(server, session, "/settings/forge-access")
	if nonAdmin.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", nonAdmin.Code)
	}
	assertForgeAccessSecurityHeaders(t, nonAdmin.Header())

	nonAdminPost := forgeAccessPOST(server, session, "/settings/forge-access", forgeAccessSaveForm(session, "0", "0"), forgeAccessTestPublicURL)
	if nonAdminPost.Code != http.StatusForbidden || len(service.createCalls) != 0 {
		t.Fatalf("non-admin post status=%d creates=%d", nonAdminPost.Code, len(service.createCalls))
	}
}

func TestForgeAccessRendersEmptyAndEncryptionStates(t *testing.T) {
	service := &fakeForgeConnectionService{}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)
	response := forgeAccessGET(server, session, "/settings/forge-access")
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	assertForgeAccessSecurityHeaders(t, response.Header())
	body := response.Body.String()
	for _, want := range []string{
		"Forge access",
		"Identity metadata only",
		"Configure Forgejo connection",
		"Administrator attestation",
		"read:user, read:organization, and read:repository",
		"All-resources mode",
		"never a provider-verified fact",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("empty-config body missing %q", want)
		}
	}

	noEncryption := newForgeAccessServer(&fakeForgeConnectionService{}, false)
	session = forgeAccessAdminSession(t, noEncryption)
	response = forgeAccessGET(noEncryption, session, "/settings/forge-access")
	body = response.Body.String()
	if !strings.Contains(body, "Service PAT encryption unavailable") {
		t.Fatalf("encryption warning missing: %q", body)
	}
	if strings.Contains(body, "Configure Forgejo connection") {
		t.Fatal("form offered without encryption")
	}

	unavailable := NewServer(Config{AppName: "Thawguard", PublicURL: forgeAccessTestPublicURL})
	session = forgeAccessAdminSession(t, unavailable)
	response = forgeAccessGET(unavailable, session, "/settings/forge-access")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "not configured") {
		t.Fatalf("unavailable state: status=%d", response.Code)
	}
}

func TestForgeAccessRendersEvidenceStates(t *testing.T) {
	cases := []struct {
		name       string
		connection forgeconnection.Connection
		model      forgeconnection.RepositoryBindingReadModel
		want       []string
		reject     []string
	}{
		{
			name:       "saved never checked",
			connection: savedForgeConnection(),
			want:       []string{"Never checked", "No preview recorded yet", "Administrator-attested PAT stored", "Run connection check"},
			reject:     []string{"Preview not current", "Repository bindings and last observed preview"},
		},
		{
			name: "check incomplete",
			connection: func() forgeconnection.Connection {
				connection := savedForgeConnection()
				connection.CheckGeneration = 1
				return connection
			}(),
			want: []string{"Check incomplete; run again."},
		},
		{
			name:       "current visible inventory",
			connection: checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved),
			model:      forgePreviewModel(true),
			want: []string{
				"Visible inventory observed",
				"Repository bindings and current preview",
				"fixture-org/alpha",
				"fixture-org/beta",
				"private-read capability was observed",
				"Forge identities bound",
				"Forgejo version 15.0.6",
			},
			reject: []string{"Last observed preview"},
		},
		{
			name:       "private read unproven",
			connection: checkedForgeConnection(forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven),
			model:      forgePreviewModel(true),
			want:       []string{"private read unproven", "private-read capability is unproven"},
		},
		{
			name: "failed with retained preview",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckUnavailable)
				connection.CheckGeneration = 2
				connection.SetupCheck.CheckGeneration = 2
				return connection
			}(),
			model: forgePreviewModel(false),
			want:  []string{"Check failed", "could not be reached", "Repository bindings and last observed preview"},
		},
		{
			name: "stale after edit",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved)
				connection.Revision = 2
				return connection
			}(),
			model: forgePreviewModel(false),
			want:  []string{"Evidence predates the current revision", "Repository bindings and last observed preview"},
		},
		{
			name: "empty visible inventory",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven)
				zero := int64(0)
				connection.SetupCheck.VisibleRepositoryCount = &zero
				connection.SetupCheck.VisiblePrivateRepositoryCount = &zero
				return connection
			}(),
			model:  forgeconnection.RepositoryBindingReadModel{Current: true},
			want:   []string{"Empty visible inventory", "not what the organization contains"},
			reject: []string{"Last observed preview", "(last observed)"},
		},
		{
			// A bound connection with zero preview rows recorded an empty
			// snapshot; after an edit that state is stale, never "no preview".
			name: "stale empty preview after edit",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven)
				zero := int64(0)
				connection.SetupCheck.VisibleRepositoryCount = &zero
				connection.SetupCheck.VisiblePrivateRepositoryCount = &zero
				connection.Revision = 2
				return connection
			}(),
			want:   []string{"Repository bindings and last observed preview", "Empty visible inventory (last observed)"},
			reject: []string{"No preview recorded yet"},
		},
		{
			// A failed check replaces the evidence row, but the retained
			// empty observation is still labeled as the last one.
			name: "stale empty preview after failed check",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckUnavailable)
				connection.CheckGeneration = 2
				connection.SetupCheck.CheckGeneration = 2
				return connection
			}(),
			want:   []string{"Repository bindings and last observed preview", "Empty visible inventory (last observed)"},
			reject: []string{"No preview recorded yet"},
		},
		{
			// An interrupted newer check leaves observed evidence one
			// generation behind; an empty preview stays labeled stale.
			name: "stale empty preview after interrupted check",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven)
				zero := int64(0)
				connection.SetupCheck.VisibleRepositoryCount = &zero
				connection.SetupCheck.VisiblePrivateRepositoryCount = &zero
				connection.CheckGeneration = 2
				return connection
			}(),
			want:   []string{"Repository bindings and last observed preview", "Empty visible inventory (last observed)"},
			reject: []string{"No preview recorded yet"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeForgeConnectionService{connection: tc.connection, found: true, bindingModel: tc.model}
			server := newForgeAccessServer(service, true)
			session := forgeAccessAdminSession(t, server)
			response := forgeAccessGET(server, session, "/settings/forge-access")
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			body := response.Body.String()
			for _, want := range tc.want {
				if !strings.Contains(body, want) {
					t.Fatalf("body missing %q", want)
				}
			}
			for _, reject := range tc.reject {
				if strings.Contains(body, reject) {
					t.Fatalf("body unexpectedly contains %q", reject)
				}
			}
		})
	}
}

func TestForgeAccessPreviewSearchFilterAndPagination(t *testing.T) {
	rows := make([]forgeconnection.RepositoryBindingRow, 0, 45)
	for i := range 45 {
		name := "repo-" + string(rune('a'+i%26)) + strings.Repeat("x", i/26+1)
		rows = append(rows, forgePreviewRow(name, i%3 == 0, forgeconnection.RepositoryBindingUnmatched))
	}
	connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved)
	service := &fakeForgeConnectionService{
		connection:   connection,
		found:        true,
		bindingModel: forgeconnection.RepositoryBindingReadModel{Current: true, Rows: rows},
	}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	page1 := forgeAccessGET(server, session, "/settings/forge-access").Body.String()
	if !strings.Contains(page1, "Showing 1–20 of 45 repositories") {
		t.Fatalf("page 1 pager missing: %q", page1)
	}
	if !strings.Contains(page1, "page=2") {
		t.Fatal("page 1 next link missing")
	}

	page3 := forgeAccessGET(server, session, "/settings/forge-access?page=3").Body.String()
	if !strings.Contains(page3, "Showing 41–45 of 45 repositories") {
		t.Fatalf("page 3 pager missing")
	}

	// 15 of 45 repositories are private; they fit one page, so no pager.
	private := forgeAccessGET(server, session, "/settings/forge-access?status=private").Body.String()
	if got := strings.Count(private, "fixture-org/repo-"); got != 15 {
		t.Fatalf("private filter rendered %d rows, want 15", got)
	}
	if strings.Contains(private, "Showing") {
		t.Fatal("single-page private filter rendered a pager")
	}

	search := forgeAccessGET(server, session, "/settings/forge-access?q=repo-a").Body.String()
	if !strings.Contains(search, "repo-a") || strings.Contains(search, "repo-b") {
		t.Fatalf("search filter failed")
	}

	noMatch := forgeAccessGET(server, session, "/settings/forge-access?q=zzz-none").Body.String()
	if !strings.Contains(noMatch, "No repositories match") {
		t.Fatalf("no-match state missing")
	}
}

func TestForgeAccessPaginatesSeparateStaleIdentitiesAtOneLocator(t *testing.T) {
	rows := make([]forgeconnection.RepositoryBindingRow, 0, 21)
	for range 21 {
		rows = append(rows, forgePreviewRow("same-locator", false, forgeconnection.RepositoryBindingPreviewNotCurrent))
	}
	service := &fakeForgeConnectionService{
		connection: checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved),
		found:      true,
		bindingModel: forgeconnection.RepositoryBindingReadModel{
			Current: false,
			Rows:    rows,
		},
	}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	page1 := forgeAccessGET(server, session, "/settings/forge-access").Body.String()
	if !strings.Contains(page1, "Showing 1–20 of 21 repositories") ||
		strings.Count(page1, "fixture-org/same-locator") != 20 {
		t.Fatalf("first stale identity page collapsed rows")
	}
	page2 := forgeAccessGET(server, session, "/settings/forge-access?page=2").Body.String()
	if !strings.Contains(page2, "Showing 21–21 of 21 repositories") ||
		strings.Count(page2, "fixture-org/same-locator") != 1 {
		t.Fatalf("second stale identity page did not retain the final row")
	}
}

func TestForgeAccessSaveEnforcesOriginCSRFAndStrictForm(t *testing.T) {
	service := &fakeForgeConnectionService{}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)
	valid := forgeAccessSaveForm(session, "0", "0")

	for _, tc := range []struct {
		name    string
		origins []string
	}{
		{name: "missing"},
		{name: "null", origins: []string{"null"}},
		{name: "mismatch", origins: []string{"https://attacker.example"}},
		{name: "duplicate", origins: []string{forgeAccessTestPublicURL, forgeAccessTestPublicURL}},
	} {
		t.Run("origin "+tc.name, func(t *testing.T) {
			response := forgeAccessPOST(server, session, "/settings/forge-access", valid, tc.origins...)
			if response.Code != http.StatusForbidden || len(service.createCalls) != 0 {
				t.Fatalf("status=%d creates=%d", response.Code, len(service.createCalls))
			}
			assertForgeAccessSecurityHeaders(t, response.Header())
		})
	}

	badCSRF := cloneValues(valid)
	badCSRF.Set(csrfFormField, "invalid")
	if response := forgeAccessPOST(server, session, "/settings/forge-access", badCSRF, forgeAccessTestPublicURL); response.Code != http.StatusForbidden || len(service.createCalls) != 0 {
		t.Fatalf("bad CSRF status=%d", response.Code)
	}

	rejected := []struct {
		name string
		path string
		form url.Values
	}{
		{name: "query", path: "/settings/forge-access?x=1", form: cloneValues(valid)},
		{name: "unknown field", path: "/settings/forge-access", form: withFormValue(valid, "unexpected", "1")},
		{name: "duplicate field", path: "/settings/forge-access", form: withDuplicateFormValue(valid, "service_pat", "second")},
		{name: "missing revision", path: "/settings/forge-access", form: withoutFormValue(valid, "expected_revision")},
		{name: "missing connection id", path: "/settings/forge-access", form: withoutFormValue(valid, "expected_connection_id")},
		{name: "inconsistent id and revision", path: "/settings/forge-access", form: forgeAccessSaveForm(session, "3", "0")},
		{name: "bad attested value", path: "/settings/forge-access", form: withFormValue(withoutFormValue(valid, "pat_attested"), "pat_attested", "yes")},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", forgeAccessTestPublicURL)
			request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: session.ID})
			server.Routes().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest || len(service.createCalls) != 0 {
				t.Fatalf("status=%d creates=%d", recorder.Code, len(service.createCalls))
			}
		})
	}

	// The attestation checkbox may be absent; the service rejects it there.
	unattested := withoutFormValue(valid, "pat_attested")
	service.createErr = forgeconnection.ValidationError{Message: "confirm the read-only service PAT attestation before saving"}
	response := forgeAccessPOST(server, session, "/settings/forge-access", unattested, forgeAccessTestPublicURL)
	if response.Code != http.StatusBadRequest || len(service.createCalls) != 1 || service.createCalls[0].PATAttested {
		t.Fatalf("unattested create: status=%d calls=%+v", response.Code, service.createCalls)
	}
	if strings.Contains(response.Body.String(), forgeAccessTestPAT) {
		t.Fatal("validation re-render leaked the submitted PAT")
	}

	service.createErr = nil
	service.createCalls = nil
	success := forgeAccessPOST(server, session, "/settings/forge-access", valid, forgeAccessTestPublicURL)
	if success.Code != http.StatusSeeOther || success.Header().Get("Location") != "/settings/forge-access?notice=forge-saved" {
		t.Fatalf("create status=%d location=%q", success.Code, success.Header().Get("Location"))
	}
	if len(service.createCalls) != 1 {
		t.Fatalf("create calls = %d", len(service.createCalls))
	}
	created := service.createCalls[0]
	if created.DisplayName != "Fixture Forge" ||
		created.BaseURL != "https://forge.example.test" ||
		created.OrganizationSlug != "fixture-org" ||
		created.ServicePAT != forgeAccessTestPAT ||
		!created.PATAttested {
		t.Fatalf("create input = %+v", created)
	}

	// A non-zero revision routes to Edit with the PAT as replacement, pinned
	// to the never-reused connection id from the form.
	editForm := forgeAccessSaveForm(session, "3", "2")
	response = forgeAccessPOST(server, session, "/settings/forge-access", editForm, forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther || len(service.editCalls) != 1 {
		t.Fatalf("edit status=%d calls=%d", response.Code, len(service.editCalls))
	}
	edited := service.editCalls[0]
	if edited.ExpectedConnectionID != 3 || edited.ExpectedRevision != 2 || edited.ReplacementPAT != forgeAccessTestPAT || !edited.ReplacementPATAttested {
		t.Fatalf("edit input = %+v", edited)
	}
}

// TestForgeAccessDestinationChangeRequiresReplacementPAT covers the web
// side of the destination-attestation rule: the edit form spells out the
// requirement, a blank-PAT destination change is re-rendered with the
// service's validation message, and no secret ever appears in the render.
func TestForgeAccessDestinationChangeRequiresReplacementPAT(t *testing.T) {
	service := &fakeForgeConnectionService{connection: savedForgeConnection(), found: true}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	editBody := forgeAccessGET(server, session, "/settings/forge-access?edit=1").Body.String()
	if !strings.Contains(editBody, "Changing the URL of a saved connection always requires a replacement PAT") {
		t.Fatalf("edit form does not state the destination-attestation requirement")
	}

	message := "changing the installation URL requires a replacement service PAT attested for the new destination"
	service.editErr = forgeconnection.ValidationError{Message: message}
	form := forgeAccessSaveForm(session, "3", "1")
	form.Set("base_url", "https://moved.example.test")
	form.Set("service_pat", "")
	form.Del("pat_attested")
	response := forgeAccessPOST(server, session, "/settings/forge-access", form, forgeAccessTestPublicURL)
	if response.Code != http.StatusBadRequest || len(service.editCalls) != 1 {
		t.Fatalf("blank-PAT destination change: status=%d edits=%d", response.Code, len(service.editCalls))
	}
	if edited := service.editCalls[0]; edited.ReplacementPAT != "" || edited.BaseURL != "https://moved.example.test" {
		t.Fatalf("edit input = %+v", edited)
	}
	body := response.Body.String()
	if !strings.Contains(body, message) {
		t.Fatalf("validation message missing from re-render")
	}
	if strings.Contains(body, forgeAccessTestPAT) {
		t.Fatal("re-render leaked a PAT value")
	}
}

func TestForgeAccessCheckAndResetPostContracts(t *testing.T) {
	service := &fakeForgeConnectionService{connection: savedForgeConnection(), found: true}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	// A check form without the connection id is refused outright.
	missingID := url.Values{csrfFormField: {session.CSRFToken}, "expected_revision": {"1"}}
	if response := forgeAccessPOST(server, session, "/settings/forge-access/check", missingID, forgeAccessTestPublicURL); response.Code != http.StatusBadRequest || len(service.checkCalls) != 0 {
		t.Fatalf("missing connection id status=%d checks=%d", response.Code, len(service.checkCalls))
	}

	checkForm := url.Values{csrfFormField: {session.CSRFToken}, "expected_connection_id": {"3"}, "expected_revision": {"1"}}
	response := forgeAccessPOST(server, session, "/settings/forge-access/check", checkForm, forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings/forge-access?notice=forge-checked" {
		t.Fatalf("check status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(service.checkCalls) != 1 || service.checkCalls[0] != (forgeAccessCheckCall{ConnectionID: 3, Revision: 1}) {
		t.Fatalf("check calls = %v", service.checkCalls)
	}

	for _, tc := range []struct {
		name   string
		err    error
		notice string
	}{
		{name: "stale", err: forgeconnection.ErrCheckStale, notice: forgeAccessCheckStaleNotice},
		{name: "conflict", err: forgeconnection.ErrConflict, notice: forgeAccessCheckStaleNotice},
		{name: "incomplete", err: forgeconnection.ErrCheckIncomplete, notice: forgeAccessCheckIncompleteNotice},
		{name: "configuration", err: forgeconnection.ErrConfiguration, notice: forgeAccessCheckUnavailableNotice},
		{name: "authority", err: forgeconnection.ErrAuthorization, notice: forgeAccessCheckAuthorityNotice},
		{name: "unknown", err: errors.New("boom"), notice: forgeAccessCheckUnknownNotice},
	} {
		t.Run("check "+tc.name, func(t *testing.T) {
			service.checkErr = tc.err
			response := forgeAccessPOST(server, session, "/settings/forge-access/check", checkForm, forgeAccessTestPublicURL)
			want := "/settings/forge-access?notice=" + tc.notice
			if response.Code != http.StatusSeeOther || response.Header().Get("Location") != want {
				t.Fatalf("status=%d location=%q want %q", response.Code, response.Header().Get("Location"), want)
			}
		})
	}
	service.checkErr = nil

	// Reset requires the exact confirmation field.
	missingConfirm := url.Values{csrfFormField: {session.CSRFToken}, "expected_connection_id": {"3"}, "expected_revision": {"1"}}
	if response := forgeAccessPOST(server, session, "/settings/forge-access/reset", missingConfirm, forgeAccessTestPublicURL); response.Code != http.StatusBadRequest || len(service.resetCalls) != 0 {
		t.Fatalf("missing confirm status=%d resets=%d", response.Code, len(service.resetCalls))
	}
	wrongConfirm := url.Values{csrfFormField: {session.CSRFToken}, "expected_connection_id": {"3"}, "expected_revision": {"1"}, "confirm_reset": {"yes"}}
	if response := forgeAccessPOST(server, session, "/settings/forge-access/reset", wrongConfirm, forgeAccessTestPublicURL); response.Code != http.StatusBadRequest || len(service.resetCalls) != 0 {
		t.Fatalf("wrong confirm status=%d resets=%d", response.Code, len(service.resetCalls))
	}
	confirmed := url.Values{
		csrfFormField:               {session.CSRFToken},
		"expected_connection_id":    {"3"},
		"expected_revision":         {"1"},
		"expected_binding_revision": {"0"},
		"confirm_reset":             {forgeAccessConfirmResetValue},
	}
	response = forgeAccessPOST(server, session, "/settings/forge-access/reset", confirmed, forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings/forge-access?notice=forge-reset" {
		t.Fatalf("reset status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(service.resetCalls) != 1 || service.resetCalls[0].ExpectedConnectionID != 3 ||
		service.resetCalls[0].ExpectedRevision != 1 || service.resetCalls[0].ExpectedBindingRevision != 0 ||
		!service.resetCalls[0].ConfirmReset {
		t.Fatalf("reset calls = %+v", service.resetCalls)
	}
}

func TestForgeAccessResetConfirmationDialog(t *testing.T) {
	service := &fakeForgeConnectionService{connection: savedForgeConnection(), found: true}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)
	body := forgeAccessGET(server, session, "/settings/forge-access?reset=confirm").Body.String()
	if !strings.Contains(body, "<dialog id=\"forge-reset-confirm\" open") {
		t.Fatalf("reset confirmation dialog not open: %q", body)
	}
	for _, want := range []string{"Reset Forge connection?", "No local repositories, roles, or grants are affected", "never reused"} {
		if !strings.Contains(body, want) {
			t.Fatalf("reset dialog missing %q", want)
		}
	}
	// The reset dialog and the check form both pin their commands to the
	// never-reused connection id.
	if got := strings.Count(body, `name="expected_connection_id" value="3"`); got < 2 {
		t.Fatalf("expected connection-id fields missing: %d occurrences", got)
	}

	// The edit form carries the connection id and revision as hidden fields.
	editBody := forgeAccessGET(server, session, "/settings/forge-access?edit=1").Body.String()
	for _, want := range []string{
		`name="expected_connection_id" value="3"`,
		`name="expected_revision" value="1"`,
	} {
		if !strings.Contains(editBody, want) {
			t.Fatalf("edit form missing %q", want)
		}
	}
}

func TestForgeAccessBindingLoadFailuresDegradeByCause(t *testing.T) {
	service := &fakeForgeConnectionService{
		connection: checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved),
		found:      true,
		listErr:    errors.New("boom"),
	}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)
	response := forgeAccessGET(server, session, "/settings/forge-access")
	if response.Code != http.StatusInternalServerError ||
		!strings.Contains(response.Body.String(), "could not load repository binding states") {
		t.Fatalf("unknown load failure: status=%d", response.Code)
	}

	// A concurrent reset between Current and RepositoryBindings surfaces as
	// ErrNoConnection; the page renders the empty model instead of failing.
	service.listErr = forgeconnection.ErrNoConnection
	response = forgeAccessGET(server, session, "/settings/forge-access")
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "Empty visible inventory (last observed)") {
		t.Fatalf("concurrent reset render: status=%d", response.Code)
	}
}

func forgeAccessBindingModel() forgeconnection.RepositoryBindingReadModel {
	public := false
	private := true
	createdAt := func(nanosecond int) string {
		return time.Date(2026, 8, 2, 10, 0, 0, nanosecond, time.UTC).Format(time.RFC3339Nano)
	}
	observedAt := time.Date(2026, 8, 2, 11, 0, 0, 0, time.UTC)
	return forgeconnection.RepositoryBindingReadModel{
		Current: true,
		Rows: []forgeconnection.RepositoryBindingRow{
			{
				State:               forgeconnection.RepositoryBindingReady,
				RepositoryID:        11,
				RepositoryCreatedAt: createdAt(11),
				LocalFullName:       "fixture-org/alpha-local",
				LocalDefaultBranch:  "release",
				LocalActive:         false,
				RemoteFullName:      "fixture-org/alpha-remote",
				RemoteFullNames:     []string{"fixture-org/alpha-remote"},
				RemoteDefaultBranch: "main",
				RemotePrivate:       &public,
				ObservedAt:          observedAt,
			},
			{
				State:               forgeconnection.RepositoryBindingCurrent,
				RepositoryID:        12,
				RepositoryCreatedAt: createdAt(12),
				LocalFullName:       "fixture-org/beta-local",
				LocalDefaultBranch:  "main",
				LocalActive:         true,
				RemoteFullName:      "fixture-org/beta-remote",
				RemoteFullNames:     []string{"fixture-org/beta-remote"},
				RemoteDefaultBranch: "trunk",
				RemotePrivate:       &private,
				ObservedAt:          observedAt,
			},
			{
				State:               forgeconnection.RepositoryBindingIdentityConflict,
				RepositoryID:        13,
				RepositoryCreatedAt: createdAt(13),
				LocalFullName:       "fixture-org/gamma-local",
				LocalDefaultBranch:  "main",
				LocalActive:         true,
				RemoteFullName:      "fixture-org/gamma-local",
				RemoteFullNames:     []string{"fixture-org/gamma-local", "fixture-org/gamma-replacement"},
				RemoteDefaultBranch: "release",
				RemotePrivate:       &public,
				ObservedAt:          observedAt,
			},
			{
				State:               forgeconnection.RepositoryBindingUnmatched,
				RemoteFullName:      "fixture-org/delta-remote",
				RemoteFullNames:     []string{"fixture-org/delta-remote"},
				RemoteDefaultBranch: "main",
				RemotePrivate:       &public,
				ObservedAt:          observedAt,
			},
			{
				State:               forgeconnection.RepositoryBindingDuplicateRemoteLocator,
				RemoteFullName:      "fixture-org/epsilon-remote",
				RemoteFullNames:     []string{"fixture-org/epsilon-remote"},
				RemoteDefaultBranch: "",
				RemotePrivate:       nil,
				ObservedAt:          observedAt,
			},
		},
	}
}

func forgeAccessBindingConnection() forgeconnection.Connection {
	connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved)
	connection.BindingRevision = 4
	return connection
}

func forgeAccessBindForm(session sessionState) url.Values {
	return url.Values{
		csrfFormField:               {session.CSRFToken},
		"expected_connection_id":    {"3"},
		"expected_config_revision":  {"1"},
		"expected_check_generation": {"1"},
		"expected_binding_revision": {"4"},
		"repository_id":             {"11"},
		"repository_created_at":     {"2026-08-02T10:00:00.000000011Z"},
		"confirm_bind":              {forgeAccessConfirmBindValue},
	}
}

func forgeAccessUnbindForm(session sessionState) url.Values {
	return url.Values{
		csrfFormField:               {session.CSRFToken},
		"expected_connection_id":    {"3"},
		"expected_config_revision":  {"1"},
		"expected_binding_revision": {"4"},
		"repository_id":             {"12"},
		"confirm_unbind":            {forgeAccessConfirmUnbindValue},
	}
}

func TestForgeAccessBindingStatesFiltersAndNoJavaScriptConfirmations(t *testing.T) {
	service := &fakeForgeConnectionService{
		connection:   forgeAccessBindingConnection(),
		found:        true,
		bindingModel: forgeAccessBindingModel(),
	}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	body := forgeAccessGET(server, session, "/settings/forge-access").Body.String()
	for _, want := range []string{
		"Repository bindings and current preview",
		"Ready to bind",
		"Bound and current",
		"Identity conflict",
		"Unmatched",
		"Duplicate remote locator",
		"fixture-org/alpha-local",
		"fixture-org/alpha-remote",
		"Inactive",
		"Default branch:",
		"unknown",
		"Reset is blocked until every repository binding below is removed",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("binding page missing %q", want)
		}
	}
	for _, forbidden := range []string{"remote_repository_id", "Remote ID", ">100<", ">101<"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("binding page exposed %q", forbidden)
		}
	}

	filters := []struct {
		query  string
		want   string
		reject []string
	}{
		{query: "ready", want: "fixture-org/alpha-remote", reject: []string{"fixture-org/beta-remote", "fixture-org/delta-remote"}},
		{query: "bound", want: "fixture-org/beta-remote", reject: []string{"fixture-org/alpha-remote", "fixture-org/gamma-local", "fixture-org/delta-remote"}},
		{query: "attention", want: "fixture-org/gamma-local", reject: []string{"fixture-org/alpha-remote", "fixture-org/delta-remote"}},
		{query: "unmatched", want: "fixture-org/delta-remote", reject: []string{"fixture-org/alpha-remote", "fixture-org/beta-remote"}},
	}
	for _, filter := range filters {
		filtered := forgeAccessGET(server, session, "/settings/forge-access?binding="+filter.query).Body.String()
		if !strings.Contains(filtered, filter.want) {
			t.Fatalf("binding filter %s missing %q", filter.query, filter.want)
		}
		for _, reject := range filter.reject {
			if strings.Contains(filtered, reject) {
				t.Fatalf("binding filter %s unexpectedly rendered %q", filter.query, reject)
			}
		}
	}
	privateOnly := forgeAccessGET(server, session, "/settings/forge-access?status=private").Body.String()
	if !strings.Contains(privateOnly, "fixture-org/beta-remote") || strings.Contains(privateOnly, "fixture-org/alpha-remote") ||
		strings.Contains(privateOnly, "fixture-org/gamma-local") {
		t.Fatalf("private visibility filter included public or unknown rows")
	}
	publicOnly := forgeAccessGET(server, session, "/settings/forge-access?status=public").Body.String()
	if !strings.Contains(publicOnly, "fixture-org/gamma-local") || strings.Contains(publicOnly, "fixture-org/beta-remote") ||
		strings.Contains(publicOnly, "fixture-org/epsilon-remote") {
		t.Fatalf("public visibility filter omitted the agreed conflict group or included private/unknown rows")
	}

	// A conflict row keeps its remote display cleared but is still found by
	// searching any of its retained remote locators.
	conflictSearch := forgeAccessGET(server, session, "/settings/forge-access?q=gamma-replacement").Body.String()
	if !strings.Contains(conflictSearch, "fixture-org/gamma-local") ||
		!strings.Contains(conflictSearch, "Identity conflict") {
		t.Fatalf("conflict row not searchable by retained remote locator")
	}
	if strings.Contains(conflictSearch, "fixture-org/alpha-local") {
		t.Fatalf("conflict search rendered unrelated rows")
	}

	bindBody := forgeAccessGET(server, session, "/settings/forge-access?bind=11").Body.String()
	if !strings.Contains(bindBody, `<dialog id="forge-bind-confirm" open`) ||
		!strings.Contains(bindBody, `action="/settings/forge-access/repositories/bind"`) {
		t.Fatalf("server-rendered bind confirmation missing")
	}
	bindForm := formForAction(t, bindBody, "/settings/forge-access/repositories/bind")
	for _, field := range []string{
		`name="expected_connection_id" value="3"`,
		`name="expected_config_revision" value="1"`,
		`name="expected_check_generation" value="1"`,
		`name="expected_binding_revision" value="4"`,
		`name="repository_id" value="11"`,
		`name="repository_created_at" value="2026-08-02T10:00:00.000000011Z"`,
		`name="confirm_bind" value="bind"`,
	} {
		if !strings.Contains(bindForm, field) {
			t.Fatalf("bind form missing %q: %s", field, bindForm)
		}
	}
	for _, forbidden := range []string{"remote_repository_id", "owner", "default_branch", "visibility", "alpha-remote"} {
		if strings.Contains(bindForm, forbidden) {
			t.Fatalf("bind mutation form contains %q: %s", forbidden, bindForm)
		}
	}

	unbindBody := forgeAccessGET(server, session, "/settings/forge-access?unbind=12").Body.String()
	if !strings.Contains(unbindBody, `<dialog id="forge-unbind-confirm" open`) ||
		!strings.Contains(unbindBody, `action="/settings/forge-access/repositories/unbind"`) {
		t.Fatalf("server-rendered unbind confirmation missing")
	}
	unbindForm := formForAction(t, unbindBody, "/settings/forge-access/repositories/unbind")
	if strings.Contains(unbindForm, "repository_created_at") || strings.Contains(unbindForm, "remote_repository_id") {
		t.Fatalf("unbind form contains an unsupported identity field: %s", unbindForm)
	}

	resetBody := forgeAccessGET(server, session, "/settings/forge-access?reset=confirm").Body.String()
	if !strings.Contains(resetBody, "Reset blocked by repository bindings") ||
		strings.Contains(resetBody, `action="/settings/forge-access/reset"`) {
		t.Fatalf("reset was not visibly blocked by bindings")
	}
}

func TestForgeAccessDriftedDuplicateConflictUsesAgreedVisibility(t *testing.T) {
	private := true
	service := &fakeForgeConnectionService{
		connection: forgeAccessBindingConnection(),
		found:      true,
		bindingModel: forgeconnection.RepositoryBindingReadModel{
			Current: true,
			Rows: []forgeconnection.RepositoryBindingRow{
				{
					State:               forgeconnection.RepositoryBindingIdentityConflict,
					RepositoryID:        41,
					RepositoryCreatedAt: "2026-08-02T10:00:00.000000041Z",
					LocalFullName:       "fixture-org/renamed-local",
					LocalDefaultBranch:  "main",
					LocalActive:         true,
					RemoteFullName:      "fixture-org/renamed-remote",
					RemoteFullNames:     []string{"fixture-org/renamed-remote"},
					RemoteDefaultBranch: "release",
					RemotePrivate:       &private,
					ObservedAt:          time.Date(2040, 8, 10, 12, 34, 56, 789, time.UTC),
				},
			},
		},
	}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	privateSearch := forgeAccessGET(
		server,
		session,
		"/settings/forge-access?status=private&q=fixture-org%2Frenamed-remote",
	).Body.String()
	for _, want := range []string{
		"fixture-org/renamed-local",
		"fixture-org/renamed-remote",
		"Identity conflict",
		"release",
	} {
		if !strings.Contains(privateSearch, want) {
			t.Fatalf("private conflict search missing %q", want)
		}
	}

	publicOnly := forgeAccessGET(server, session, "/settings/forge-access?status=public").Body.String()
	if strings.Contains(publicOnly, "fixture-org/renamed-local") ||
		strings.Contains(publicOnly, "fixture-org/renamed-remote") {
		t.Fatal("public filter included the agreed-private conflict row")
	}
}

func TestForgeAccessBoundAndAttentionFiltersAreExclusive(t *testing.T) {
	row := func(name string, state forgeconnection.RepositoryBindingState) forgeconnection.RepositoryBindingRow {
		result := forgePreviewRow(name, false, state)
		result.RepositoryID = int64(len(name))
		result.LocalFullName = "fixture-org/local-" + name
		return result
	}
	missing := row("missing", forgeconnection.RepositoryBindingNotVisible)
	missing.RemoteFullName = ""
	missing.RemoteFullNames = nil
	service := &fakeForgeConnectionService{
		connection: forgeAccessBindingConnection(),
		found:      true,
		bindingModel: forgeconnection.RepositoryBindingReadModel{
			Current: true,
			Rows: []forgeconnection.RepositoryBindingRow{
				row("current-only", forgeconnection.RepositoryBindingCurrent),
				row("last-observed", forgeconnection.RepositoryBindingLastObservedOnly),
				row("conflict", forgeconnection.RepositoryBindingIdentityConflict),
				row("drift", forgeconnection.RepositoryBindingLocatorDrift),
				missing,
				row("ready-row", forgeconnection.RepositoryBindingReady),
				row("unmatched-row", forgeconnection.RepositoryBindingUnmatched),
			},
		},
	}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)

	bound := forgeAccessGET(server, session, "/settings/forge-access?binding=bound").Body.String()
	if !strings.Contains(bound, "fixture-org/current-only") {
		t.Fatal("Bound filter omitted the current binding")
	}
	for _, rejected := range []string{"last-observed", "conflict", "drift", "local-missing", "ready-row", "unmatched-row"} {
		if strings.Contains(bound, "fixture-org/"+rejected) {
			t.Fatalf("Bound filter included %q", rejected)
		}
	}

	attention := forgeAccessGET(server, session, "/settings/forge-access?binding=attention").Body.String()
	for _, expected := range []string{"last-observed", "conflict", "drift", "local-missing"} {
		if !strings.Contains(attention, "fixture-org/"+expected) {
			t.Fatalf("Attention filter omitted %q", expected)
		}
	}
	for _, rejected := range []string{"current-only", "ready-row", "unmatched-row"} {
		if strings.Contains(attention, "fixture-org/"+rejected) {
			t.Fatalf("Attention filter included %q", rejected)
		}
	}
}

func TestForgeAccessUnbindConfirmationWorksWithoutCurrentPreviewOrEncryption(t *testing.T) {
	connection := forgeAccessBindingConnection()
	connection.CheckGeneration = 2
	stale := forgeAccessBindingModel().Rows[1]
	stale.State = forgeconnection.RepositoryBindingLastObservedOnly
	service := &fakeForgeConnectionService{
		connection: connection,
		found:      true,
		bindingModel: forgeconnection.RepositoryBindingReadModel{
			Current: false,
			Rows:    []forgeconnection.RepositoryBindingRow{stale},
		},
	}
	server := newForgeAccessServer(service, false)
	session := forgeAccessAdminSession(t, server)
	body := forgeAccessGET(server, session, "/settings/forge-access?unbind=12").Body.String()
	for _, want := range []string{"Service PAT encryption unavailable", "Last observed only", `<dialog id="forge-unbind-confirm" open`, "Unbind identity"} {
		if !strings.Contains(body, want) {
			t.Fatalf("stale no-encryption unbind page missing %q", want)
		}
	}
}

func TestForgeAccessBindingPostsEnforceSecurityAndExactForms(t *testing.T) {
	service := &fakeForgeConnectionService{connection: forgeAccessBindingConnection(), found: true, bindingModel: forgeAccessBindingModel()}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)
	bindForm := forgeAccessBindForm(session)
	unbindForm := forgeAccessUnbindForm(session)

	for _, route := range []struct {
		path string
		form url.Values
	}{
		{path: "/settings/forge-access/repositories/bind", form: bindForm},
		{path: "/settings/forge-access/repositories/unbind", form: unbindForm},
	} {
		for _, origins := range [][]string{nil, {"null"}, {"https://attacker.example"}, {forgeAccessTestPublicURL, forgeAccessTestPublicURL}} {
			response := forgeAccessPOST(server, session, route.path, route.form, origins...)
			if response.Code != http.StatusForbidden {
				t.Fatalf("%s origin %v status=%d", route.path, origins, response.Code)
			}
			assertForgeAccessSecurityHeaders(t, response.Header())
		}
	}
	if len(service.bindCalls) != 0 || len(service.unbindCalls) != 0 {
		t.Fatalf("origin rejection reached binding service: binds=%d unbinds=%d", len(service.bindCalls), len(service.unbindCalls))
	}

	badCSRF := cloneValues(bindForm)
	badCSRF.Set(csrfFormField, "invalid")
	if response := forgeAccessPOST(server, session, "/settings/forge-access/repositories/bind", badCSRF, forgeAccessTestPublicURL); response.Code != http.StatusForbidden {
		t.Fatalf("bind bad CSRF status=%d", response.Code)
	}
	badCSRF = cloneValues(unbindForm)
	badCSRF.Set(csrfFormField, "invalid")
	if response := forgeAccessPOST(server, session, "/settings/forge-access/repositories/unbind", badCSRF, forgeAccessTestPublicURL); response.Code != http.StatusForbidden {
		t.Fatalf("unbind bad CSRF status=%d", response.Code)
	}

	rejected := []struct {
		name string
		path string
		form url.Values
	}{
		{name: "bind query", path: "/settings/forge-access/repositories/bind?x=1", form: cloneValues(bindForm)},
		{name: "bind unknown", path: "/settings/forge-access/repositories/bind", form: withFormValue(bindForm, "remote_repository_id", "999")},
		{name: "bind duplicate", path: "/settings/forge-access/repositories/bind", form: withDuplicateFormValue(bindForm, "repository_id", "11")},
		{name: "bind missing generation", path: "/settings/forge-access/repositories/bind", form: withoutFormValue(bindForm, "expected_check_generation")},
		{name: "bind noncanonical id", path: "/settings/forge-access/repositories/bind", form: withFormValue(withoutFormValue(bindForm, "repository_id"), "repository_id", "011")},
		{name: "bind noncanonical timestamp", path: "/settings/forge-access/repositories/bind", form: withFormValue(withoutFormValue(bindForm, "repository_created_at"), "repository_created_at", "2026-08-02T10:00:00.000000000Z")},
		{name: "bind wrong confirmation", path: "/settings/forge-access/repositories/bind", form: withFormValue(withoutFormValue(bindForm, "confirm_bind"), "confirm_bind", "yes")},
		{name: "unbind query", path: "/settings/forge-access/repositories/unbind?x=1", form: cloneValues(unbindForm)},
		{name: "unbind unknown", path: "/settings/forge-access/repositories/unbind", form: withFormValue(unbindForm, "owner", "fixture-org")},
		{name: "unbind duplicate", path: "/settings/forge-access/repositories/unbind", form: withDuplicateFormValue(unbindForm, "expected_binding_revision", "4")},
		{name: "unbind missing revision", path: "/settings/forge-access/repositories/unbind", form: withoutFormValue(unbindForm, "expected_binding_revision")},
		{name: "unbind wrong confirmation", path: "/settings/forge-access/repositories/unbind", form: withFormValue(withoutFormValue(unbindForm, "confirm_unbind"), "confirm_unbind", "yes")},
	}
	for _, tc := range rejected {
		response := forgeAccessPOST(server, session, tc.path, tc.form, forgeAccessTestPublicURL)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d", tc.name, response.Code)
		}
		assertForgeAccessSecurityHeaders(t, response.Header())
	}
	if len(service.bindCalls) != 0 || len(service.unbindCalls) != 0 {
		t.Fatalf("malformed forms reached service: binds=%d unbinds=%d", len(service.bindCalls), len(service.unbindCalls))
	}

	bindResponse := forgeAccessPOST(server, session, "/settings/forge-access/repositories/bind", bindForm, forgeAccessTestPublicURL)
	if bindResponse.Code != http.StatusSeeOther || bindResponse.Header().Get("Location") != "/settings/forge-access?notice="+forgeAccessBoundNotice {
		t.Fatalf("bind status=%d location=%q", bindResponse.Code, bindResponse.Header().Get("Location"))
	}
	assertForgeAccessSecurityHeaders(t, bindResponse.Header())
	if len(service.bindCalls) != 1 || service.bindCalls[0] != (forgeconnection.BindRepositoryInput{
		ExpectedConnectionID:    3,
		ExpectedConfigRevision:  1,
		ExpectedCheckGeneration: 1,
		ExpectedBindingRevision: 4,
		RepositoryID:            11,
		RepositoryCreatedAt:     "2026-08-02T10:00:00.000000011Z",
		ConfirmBind:             true,
	}) {
		t.Fatalf("bind calls = %+v", service.bindCalls)
	}
	unbindResponse := forgeAccessPOST(server, session, "/settings/forge-access/repositories/unbind", unbindForm, forgeAccessTestPublicURL)
	if unbindResponse.Code != http.StatusSeeOther || unbindResponse.Header().Get("Location") != "/settings/forge-access?notice="+forgeAccessUnboundNotice {
		t.Fatalf("unbind status=%d location=%q", unbindResponse.Code, unbindResponse.Header().Get("Location"))
	}
	if len(service.unbindCalls) != 1 || service.unbindCalls[0] != (forgeconnection.UnbindRepositoryInput{
		ExpectedConnectionID:    3,
		ExpectedConfigRevision:  1,
		ExpectedBindingRevision: 4,
		RepositoryID:            12,
		ConfirmUnbind:           true,
	}) {
		t.Fatalf("unbind calls = %+v", service.unbindCalls)
	}
}

func TestForgeAccessBindingRoutesEnforceBodyAdminAndForcedPasswordGates(t *testing.T) {
	service := &fakeForgeConnectionService{}
	server := newForgeAccessServer(service, true)
	admin := forgeAccessAdminSession(t, server)

	oversized := forgeAccessBindForm(admin)
	oversized.Set("repository_created_at", strings.Repeat("x", int(forgeAccessActionMaxBodyBytes)))
	response := forgeAccessPOST(server, admin, "/settings/forge-access/repositories/bind", oversized, forgeAccessTestPublicURL)
	if response.Code != http.StatusBadRequest || len(service.bindCalls) != 0 {
		t.Fatalf("oversized bind status=%d calls=%d", response.Code, len(service.bindCalls))
	}
	assertForgeAccessSecurityHeaders(t, response.Header())

	nonAdmin, err := server.sessions.create()
	if err != nil {
		t.Fatal(err)
	}
	userID := int64(8)
	nonAdmin.UserID = &userID
	nonAdmin.Grants = auth.NewGrants(false, nil)
	server.sessions.mu.Lock()
	server.sessions.sessions[nonAdmin.ID] = nonAdmin
	server.sessions.mu.Unlock()
	for _, route := range []struct {
		path string
		form url.Values
	}{
		{path: "/settings/forge-access/repositories/bind", form: forgeAccessBindForm(nonAdmin)},
		{path: "/settings/forge-access/repositories/unbind", form: forgeAccessUnbindForm(nonAdmin)},
	} {
		got := forgeAccessPOST(server, nonAdmin, route.path, route.form, forgeAccessTestPublicURL)
		if got.Code != http.StatusForbidden {
			t.Fatalf("non-admin %s status=%d", route.path, got.Code)
		}
	}

	forced := admin
	forced.MustChangePassword = true
	server.sessions.mu.Lock()
	server.sessions.sessions[forced.ID] = forced
	server.sessions.mu.Unlock()
	for _, route := range []struct {
		path string
		form url.Values
	}{
		{path: "/settings/forge-access/repositories/bind", form: forgeAccessBindForm(forced)},
		{path: "/settings/forge-access/repositories/unbind", form: forgeAccessUnbindForm(forced)},
	} {
		got := forgeAccessPOST(server, forced, route.path, route.form, forgeAccessTestPublicURL)
		if got.Code != http.StatusSeeOther || got.Header().Get("Location") != "/account/password" {
			t.Fatalf("forced-password %s status=%d location=%q", route.path, got.Code, got.Header().Get("Location"))
		}
	}
	if len(service.bindCalls) != 0 || len(service.unbindCalls) != 0 {
		t.Fatalf("authorization gate reached service: binds=%d unbinds=%d", len(service.bindCalls), len(service.unbindCalls))
	}
}

func TestForgeAccessResetRequiresBindingRevisionAndReportsBindingBlock(t *testing.T) {
	service := &fakeForgeConnectionService{connection: forgeAccessBindingConnection(), found: true, bindingModel: forgeAccessBindingModel()}
	server := newForgeAccessServer(service, true)
	session := forgeAccessAdminSession(t, server)
	preUpgrade := url.Values{
		csrfFormField:            {session.CSRFToken},
		"expected_connection_id": {"3"},
		"expected_revision":      {"1"},
		"confirm_reset":          {forgeAccessConfirmResetValue},
	}
	if response := forgeAccessPOST(server, session, "/settings/forge-access/reset", preUpgrade, forgeAccessTestPublicURL); response.Code != http.StatusBadRequest || len(service.resetCalls) != 0 {
		t.Fatalf("pre-upgrade reset status=%d calls=%d", response.Code, len(service.resetCalls))
	}
	service.resetErr = forgeconnection.ErrBindingsExist
	current := cloneValues(preUpgrade)
	current.Set("expected_binding_revision", "4")
	response := forgeAccessPOST(server, session, "/settings/forge-access/reset", current, forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings/forge-access?notice="+forgeAccessResetBindingsNotice {
		t.Fatalf("blocked reset status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
}

func formForAction(t *testing.T, body, action string) string {
	t.Helper()
	start := strings.Index(body, `<form method="post" action="`+action+`"`)
	if start < 0 {
		t.Fatalf("form action %q missing", action)
	}
	end := strings.Index(body[start:], "</form>")
	if end < 0 {
		t.Fatalf("form action %q is not closed", action)
	}
	return body[start : start+end]
}

func TestForgeActivityPresentationIgnoresSensitiveUnexpectedDetails(t *testing.T) {
	actorID := int64(7)
	event := audit.Event{
		ActorUserID: &actorID,
		Action:      audit.ActionForgeConnectionChecked,
		SubjectType: audit.SubjectTypeForgeConnection,
		SubjectID:   "3",
		DetailsJSON: `{"revision":1,"generation":1,"result_code":"visible_inventory_observed","visible_count":2,"private_count":1,"base_url":"url-canary","organization":"org-canary"}`,
	}
	view := activityEventViewForEvent(nil, nil, event)
	if view.ActionLabel != "Unrecognized activity" {
		t.Fatalf("unexpected sensitive details were not rejected: %+v", view)
	}
	if strings.Contains(view.Detail, "url-canary") || strings.Contains(view.Target, "org-canary") {
		t.Fatalf("canary leaked into view: %+v", view)
	}

	valid := event
	valid.DetailsJSON = `{"revision":1,"generation":1,"result_code":"visible_inventory_observed","visible_count":2,"private_count":1}`
	view = activityEventViewForEvent(nil, nil, valid)
	if view.ActionLabel != "Forge connection check" || view.Outcome != "Observed" || view.Target != "Forge connection 3" {
		t.Fatalf("valid checked view: %+v", view)
	}
	if !strings.Contains(view.Detail, "2 repositories visible to the attested credential (1 private)") {
		t.Fatalf("checked detail: %q", view.Detail)
	}
}

func TestForgeConnectionResetActivityAcceptsExactHistoricalAndCurrentShapes(t *testing.T) {
	for _, details := range []string{
		`{"revision":1}`,
		`{"revision":1,"binding_revision":0}`,
	} {
		event := audit.Event{
			Action:      audit.ActionForgeConnectionReset,
			SubjectType: audit.SubjectTypeForgeConnection,
			SubjectID:   "3",
			DetailsJSON: details,
		}
		view := activityEventViewForEvent(nil, nil, event)
		if view.ActionLabel != "Forge connection" || view.Outcome != "Reset" {
			t.Fatalf("reset details %s rendered as %+v", details, view)
		}
	}
	event := audit.Event{
		Action:      audit.ActionForgeConnectionReset,
		SubjectType: audit.SubjectTypeForgeConnection,
		SubjectID:   "3",
		DetailsJSON: `{"revision":1,"base_url":"canary"}`,
	}
	if view := activityEventViewForEvent(nil, nil, event); view.ActionLabel != "Unrecognized activity" {
		t.Fatalf("reset activity accepted unexpected details: %+v", view)
	}
}

func TestForgeRepositoryBindingActivityUsesMatchingRepositoryIncarnation(t *testing.T) {
	actorID := int64(7)
	createdAt := time.Date(2026, 8, 2, 10, 0, 0, 11, time.UTC)
	event := audit.Event{
		ActorUserID: &actorID,
		Action:      audit.ActionForgeRepositoryBound,
		SubjectType: audit.SubjectTypeForgeConnection,
		SubjectID:   "3",
		DetailsJSON: `{"repository_id":11,"repository_created_at":"2026-08-02T10:00:00.000000011Z","config_revision":1,"check_generation":2,"binding_revision":4}`,
	}
	repositories := map[int64]domain.Repository{
		11: {ID: 11, Owner: "fixture-org", Name: "alpha", CreatedAt: createdAt},
	}
	view := activityEventViewForEvent(repositories, nil, event)
	if view.ActionLabel != "Forge repository binding" || view.Target != "fixture-org/alpha" || view.Outcome != "Bound" {
		t.Fatalf("matching binding activity: %+v", view)
	}
	if !strings.Contains(view.Detail, "binding revision 4") || strings.Contains(view.Detail, "remote") {
		t.Fatalf("binding activity detail: %q", view.Detail)
	}

	replacement := repositories[11]
	replacement.CreatedAt = createdAt.Add(time.Nanosecond)
	repositories[11] = replacement
	view = activityEventViewForEvent(repositories, nil, event)
	if view.Target != "Former repository" {
		t.Fatalf("reused repository id resolved to replacement: %+v", view)
	}

	for _, details := range []string{
		`{"repository_id":11,"config_revision":1,"check_generation":2,"binding_revision":4}`,
		`{"repository_id":11,"repository_created_at":"malformed","config_revision":1,"check_generation":2,"binding_revision":4}`,
		`{"repository_id":"malformed","repository_created_at":"2026-08-02T10:00:00.000000011Z","config_revision":1,"check_generation":2,"binding_revision":4}`,
	} {
		fallback := event
		fallback.DetailsJSON = details
		view = activityEventViewForEvent(repositories, nil, fallback)
		if view.ActionLabel != "Forge repository binding" || view.Target != "Former repository" || view.Outcome != "Bound" {
			t.Fatalf("malformed or missing incarnation %s did not use the bounded fallback: %+v", details, view)
		}
	}
	for _, details := range []string{
		`{"repository_id":`,
		`{"repository_id":11,"repository_id":12,"repository_created_at":"2026-08-02T10:00:00.000000011Z","config_revision":1,"check_generation":2,"binding_revision":4}`,
	} {
		fallback := event
		fallback.DetailsJSON = details
		view = activityEventViewForEvent(repositories, nil, fallback)
		if view.ActionLabel != "Unrecognized activity" || view.Target != "Former repository" {
			t.Fatalf("invalid binding audit %s did not use the bounded fallback: %+v", details, view)
		}
	}

	unbound := event
	unbound.Action = audit.ActionForgeRepositoryUnbound
	unbound.DetailsJSON = `{"repository_id":11,"repository_created_at":"2026-08-02T10:00:00.000000011Z","config_revision":1,"binding_revision":5}`
	view = activityEventViewForEvent(repositories, nil, unbound)
	if view.ActionLabel != "Forge repository binding" || view.Outcome != "Unbound" ||
		strings.Contains(view.Detail, "check ") || !strings.Contains(view.Detail, "binding revision 5") {
		t.Fatalf("unbind activity shape: %+v", view)
	}
	unbound.DetailsJSON = `{"repository_id":11,"repository_created_at":"2026-08-02T10:00:00.000000011Z","config_revision":1,"check_generation":2,"binding_revision":5}`
	if view = activityEventViewForEvent(repositories, nil, unbound); view.ActionLabel != "Unrecognized activity" {
		t.Fatalf("unbind activity accepted bind-only check evidence: %+v", view)
	}

	unexpected := event
	unexpected.DetailsJSON = `{"repository_id":11,"repository_created_at":"2026-08-02T10:00:00.000000011Z","config_revision":1,"check_generation":2,"binding_revision":4,"remote_repository_id":"remote-canary","base_url":"url-canary"}`
	view = activityEventViewForEvent(repositories, nil, unexpected)
	if view.ActionLabel != "Unrecognized activity" || strings.Contains(view.Target, "remote-canary") || strings.Contains(view.Detail, "url-canary") {
		t.Fatalf("unexpected binding audit details leaked: %+v", view)
	}
}
