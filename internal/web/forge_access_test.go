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

	repositories []forgeconnection.VisibleRepository
	listErr      error

	createErr, editErr, resetErr, checkErr error

	createCalls []forgeconnection.CreateInput
	editCalls   []forgeconnection.EditInput
	resetCalls  []forgeconnection.ResetInput
	checkCalls  []forgeAccessCheckCall
}

type forgeAccessCheckCall struct {
	ConnectionID int64
	Revision     int64
}

func (f *fakeForgeConnectionService) Current(context.Context) (forgeconnection.Connection, bool, error) {
	return f.connection, f.found, f.currentErr
}

func (f *fakeForgeConnectionService) VisibleRepositories(context.Context, int64) ([]forgeconnection.VisibleRepository, error) {
	return f.repositories, f.listErr
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

func forgeVisibleRepositories(generation int64) []forgeconnection.VisibleRepository {
	observed := time.Date(2026, 8, 1, 11, 0, 0, 0, time.UTC)
	return []forgeconnection.VisibleRepository{
		{RemoteID: "100", Owner: "fixture-org", Name: "alpha", DefaultBranch: "main", Private: false, ObservedCheckGeneration: generation, ObservedAt: observed},
		{RemoteID: "101", Owner: "fixture-org", Name: "beta", DefaultBranch: "main", Private: true, ObservedCheckGeneration: generation, ObservedAt: observed},
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
		"Preview only",
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
		name         string
		connection   forgeconnection.Connection
		repositories []forgeconnection.VisibleRepository
		want         []string
		reject       []string
	}{
		{
			name:       "saved never checked",
			connection: savedForgeConnection(),
			want:       []string{"Never checked", "No preview recorded yet", "Administrator-attested PAT stored", "Run connection check"},
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
			name:         "current visible inventory",
			connection:   checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved),
			repositories: forgeVisibleRepositories(1),
			want: []string{
				"Visible inventory observed",
				"Repositories visible to this attested credential",
				"fixture-org/alpha",
				"fixture-org/beta",
				"private-read capability was observed",
				"Identities bound",
				"Forgejo version 15.0.6",
			},
			reject: []string{"Last observed preview"},
		},
		{
			name:         "private read unproven",
			connection:   checkedForgeConnection(forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven),
			repositories: forgeVisibleRepositories(1),
			want:         []string{"private read unproven", "private-read capability is unproven"},
		},
		{
			name: "failed with retained preview",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckUnavailable)
				connection.CheckGeneration = 2
				connection.SetupCheck.CheckGeneration = 2
				return connection
			}(),
			repositories: forgeVisibleRepositories(1),
			want:         []string{"Check failed", "could not be reached", "Last observed preview"},
		},
		{
			name: "stale after edit",
			connection: func() forgeconnection.Connection {
				connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved)
				connection.Revision = 2
				return connection
			}(),
			repositories: forgeVisibleRepositories(1),
			want:         []string{"Evidence predates the current revision", "Last observed preview"},
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
			want:   []string{"Last observed preview", "Empty visible inventory (last observed)"},
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
			want:   []string{"Last observed preview", "Empty visible inventory (last observed)"},
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
			want:   []string{"Last observed preview", "Empty visible inventory (last observed)"},
			reject: []string{"No preview recorded yet"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeForgeConnectionService{connection: tc.connection, found: true, repositories: tc.repositories}
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
	repositories := make([]forgeconnection.VisibleRepository, 0, 45)
	observed := time.Date(2026, 8, 1, 11, 0, 0, 0, time.UTC)
	for i := range 45 {
		name := "repo-" + string(rune('a'+i%26)) + strings.Repeat("x", i/26+1)
		repositories = append(repositories, forgeconnection.VisibleRepository{
			RemoteID:                "10" + strings.Repeat("0", 1) + string(rune('0'+i%10)) + string(rune('0'+i/10)),
			Owner:                   "fixture-org",
			Name:                    name,
			DefaultBranch:           "main",
			Private:                 i%3 == 0,
			ObservedCheckGeneration: 1,
			ObservedAt:              observed,
		})
	}
	connection := checkedForgeConnection(forgeconnection.CheckVisibleInventoryObserved)
	service := &fakeForgeConnectionService{connection: connection, found: true, repositories: repositories}
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
		csrfFormField:            {session.CSRFToken},
		"expected_connection_id": {"3"},
		"expected_revision":      {"1"},
		"confirm_reset":          {forgeAccessConfirmResetValue},
	}
	response = forgeAccessPOST(server, session, "/settings/forge-access/reset", confirmed, forgeAccessTestPublicURL)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/settings/forge-access?notice=forge-reset" {
		t.Fatalf("reset status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	if len(service.resetCalls) != 1 || service.resetCalls[0].ExpectedConnectionID != 3 ||
		service.resetCalls[0].ExpectedRevision != 1 || !service.resetCalls[0].ConfirmReset {
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
