package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// rejectionRecord is the whole diagnostic contract: message, level, and the
// four application attributes. Timestamps and handler formatting stay out of
// the assertions.
type rejectionRecord struct {
	Level  string `json:"level"`
	Msg    string `json:"msg"`
	Method string `json:"method"`
	Route  string `json:"route"`
	Status int    `json:"status"`
	Reason string `json:"reason"`
}

func forbiddenRejection(route, reason string) rejectionRecord {
	return rejectionRecord{
		Level:  "INFO",
		Msg:    "request rejected",
		Method: http.MethodPost,
		Route:  route,
		Status: http.StatusForbidden,
		Reason: reason,
	}
}

// newRejectionLogSink backs a server with a buffered stdlib JSON handler so
// tests can decode whole records instead of matching formatted text.
func newRejectionLogSink() (*slog.Logger, *bytes.Buffer) {
	buffer := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buffer, nil)), buffer
}

func decodeRejectionRecords(t *testing.T, logs *bytes.Buffer) []rejectionRecord {
	t.Helper()
	trimmed := strings.TrimSpace(logs.String())
	if trimmed == "" {
		return nil
	}
	var records []rejectionRecord
	for line := range strings.SplitSeq(trimmed, "\n") {
		var attributes map[string]any
		if err := json.Unmarshal([]byte(line), &attributes); err != nil {
			t.Fatalf("diagnostic line is not a decodable record: %v", err)
		}
		assertContractAttributes(t, attributes)
		var record rejectionRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("diagnostic line does not match the contract shape: %v", err)
		}
		records = append(records, record)
	}
	return records
}

// assertContractAttributes fails on any attribute beyond the contract, which
// is what keeps a future addition from quietly widening what reaches a
// terminal.
func assertContractAttributes(t *testing.T, attributes map[string]any) {
	t.Helper()
	allowed := map[string]bool{
		"time": true, "level": true, "msg": true,
		"method": true, "route": true, "status": true, "reason": true,
	}
	for key := range attributes {
		if !allowed[key] {
			t.Fatalf("diagnostic carries unexpected attribute %q", key)
		}
	}
	for _, required := range []string{"method", "route", "status", "reason"} {
		if _, ok := attributes[required]; !ok {
			t.Fatalf("diagnostic is missing the %q attribute", required)
		}
	}
}

func assertSingleRejection(t *testing.T, logs *bytes.Buffer, want rejectionRecord) {
	t.Helper()
	records := decodeRejectionRecords(t, logs)
	if len(records) != 1 {
		t.Fatalf("emitted %d diagnostics, want exactly 1: %q", len(records), logs.String())
	}
	if records[0] != want {
		t.Fatalf("diagnostic = %+v, want %+v", records[0], want)
	}
}

func assertNoRejection(t *testing.T, logs *bytes.Buffer) {
	t.Helper()
	if records := decodeRejectionRecords(t, logs); len(records) != 0 {
		t.Fatalf("emitted %d diagnostics for a request that must stay silent: %q", len(records), logs.String())
	}
}

func TestOriginRejectionReason(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{name: "missing", want: "origin_missing"},
		{name: "null", values: []string{"null"}, want: "origin_null"},
		{name: "multiple", values: []string{"https://one.example.test", "https://two.example.test"}, want: "origin_multiple"},
		{name: "mismatch", values: []string{"https://hostile.example.test"}, want: "origin_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			for _, value := range test.values {
				request.Header.Add("Origin", value)
			}
			if got := originRejectionReason(request); got != test.want {
				t.Fatalf("reason = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSensitiveOriginRejectionsUseFixedMuxRoutes(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		route string
	}{
		{name: "invitation create", path: "/users/invitations", route: "/users/invitations"},
		{name: "invitation accept", path: "/invitations/accept", route: "/invitations/accept"},
		{name: "recovery issue", path: "/users/7/password-recovery", route: "/users/{id}/password-recovery"},
		{name: "recovery completion", path: "/password-recovery", route: "/password-recovery"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInvitationWebFixture(t)
			recorder := postPasswordRecoveryForm(t, fixture.server, test.path, nil, url.Values{}, []string{"https://hostile.example.test"})
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
			}
			assertSingleRejection(t, fixture.logs, forbiddenRejection(test.route, "origin_mismatch"))
		})
	}
}

func TestAnonymousCSRFRejectionsAreLoggedOnce(t *testing.T) {
	t.Run("invitation acceptance", func(t *testing.T) {
		fixture := newInvitationWebFixture(t)
		credential := fixture.mustCreateServiceInvitation(t, "csrf-diagnostic@example.test", false)
		recorder := postPasswordRecoveryForm(t, fixture.server, "/invitations/accept", nil, url.Values{
			csrfFormField:      {"not a valid invitation csrf token"},
			"invitation_token": {credential.Token},
			"new_password":     {invitedWebTestPassword},
		}, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
		}
		assertSingleRejection(t, fixture.logs, forbiddenRejection("/invitations/accept", "csrf_invalid"))
	})

	t.Run("recovery completion", func(t *testing.T) {
		fixture := newPasswordRecoveryWebFixture(t)
		issued := mustIssuePasswordRecoveryForWeb(t, fixture)
		recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
			csrfFormField:    {"not a valid recovery csrf token"},
			"recovery_token": {issued.Token},
			"new_password":   {recoveredWebTestPassword},
		}, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
		}
		assertSingleRejection(t, fixture.logs, forbiddenRejection("/password-recovery", "csrf_invalid"))
	})
}

func TestUntargetedAndAcceptedRequestsStaySilent(t *testing.T) {
	t.Run("accepted invitation creation", func(t *testing.T) {
		fixture := newInvitationWebFixture(t)
		fixture.mustCreateInvitationOverHTTP(t, fixture.invitationCreateForm("quiet@example.test", "Quiet Invitee"))
		assertNoRejection(t, fixture.logs)
	})

	t.Run("completed recovery", func(t *testing.T) {
		fixture := newPasswordRecoveryWebFixture(t)
		issued := mustIssuePasswordRecoveryForWeb(t, fixture)
		recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
			csrfFormField:    {getPasswordRecoveryCSRF(t, fixture.server)},
			"recovery_token": {issued.Token},
			"new_password":   {recoveredWebTestPassword},
		}, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%q", recorder.Code, recorder.Body.String())
		}
		assertNoRejection(t, fixture.logs)
	})

	// Authenticated session-CSRF rejection is deliberately out of scope: the
	// canonical-Origin gate passed, so nothing is recorded.
	t.Run("authenticated session CSRF failure", func(t *testing.T) {
		fixture := newInvitationWebFixture(t)
		form := fixture.invitationCreateForm("quiet@example.test", "Quiet Invitee")
		form.Set(csrfFormField, "not the session csrf token")
		recorder := postPasswordRecoveryForm(t, fixture.server, "/users/invitations", fixture.adminCookie(), form, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
		}
		assertNoRejection(t, fixture.logs)
	})

	// A malformed sensitive body is rejected past the two gates this slice
	// covers, so it must not produce a record either.
	t.Run("malformed recovery form", func(t *testing.T) {
		fixture := newPasswordRecoveryWebFixture(t)
		recorder := postPasswordRecoveryForm(t, fixture.server, "/password-recovery", nil, url.Values{
			csrfFormField:       {getPasswordRecoveryCSRF(t, fixture.server)},
			"unsupported_field": {"1"},
		}, []string{passwordRecoveryWebPublicURL})
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%q", recorder.Code, recorder.Body.String())
		}
		assertNoRejection(t, fixture.logs)
	})

	t.Run("health static and unrelated requests", func(t *testing.T) {
		fixture := newInvitationWebFixture(t)
		for _, path := range []string{"/healthz", "/login", "/password-recovery", "/invitations/accept", "/static/js/password-recovery.js", "/", "/no-such-page"} {
			recorder := httptest.NewRecorder()
			fixture.server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		}
		// A cross-origin sign-in post is rejected by a gate this slice does not
		// cover; broad 4xx logging stays out.
		postPasswordRecoveryForm(t, fixture.server, "/login", nil, url.Values{}, []string{"https://hostile.example.test"})
		assertNoRejection(t, fixture.logs)
	})
}

func TestNilLoggerRejectionStaysSilentAndNeverUsesDefaultLogger(t *testing.T) {
	defaultLogs := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(defaultLogs, nil)))
	defer slog.SetDefault(previous)

	server := NewServer(Config{AppName: "Thawguard", PublicURL: passwordRecoveryWebPublicURL})
	for _, path := range []string{"/password-recovery", "/invitations/accept", "/users/7/password-recovery"} {
		recorder := postPasswordRecoveryForm(t, server, path, nil, url.Values{}, nil)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("POST %s status = %d, want 403; body=%q", path, recorder.Code, recorder.Body.String())
		}
	}
	if defaultLogs.Len() != 0 {
		t.Fatalf("nil-logger construction wrote to the default logger: %q", defaultLogs.String())
	}
}

func TestRejectionDiagnosticsOmitEverySubmittedSecret(t *testing.T) {
	const (
		originCanary   = "https://origin-canary-6d2a.example.test"
		userIDCanary   = "user-id-canary-4b71"
		queryCanary    = "query-canary-9c30"
		bearerCanary   = "bearer-canary-77ac"
		passwordCanary = "password-canary-2e55"
		csrfCanary     = "csrf-canary-1188"
		cookieCanary   = "cookie-canary-5f19"
		emailCanary    = "email-canary-30da@example.test"
	)
	canaries := []string{originCanary, userIDCanary, queryCanary, bearerCanary, passwordCanary, csrfCanary, cookieCanary, emailCanary}

	fixture := newInvitationWebFixture(t)
	path := fmt.Sprintf("/users/%s/password-recovery?%s=1", userIDCanary, queryCanary)
	form := url.Values{
		csrfFormField:      {csrfCanary},
		"invitation_token": {bearerCanary},
		"recovery_token":   {bearerCanary},
		"new_password":     {passwordCanary},
		"email":            {emailCanary},
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: cookieCanary}
	recorder := postPasswordRecoveryForm(t, fixture.server, path, cookie, form, []string{originCanary})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", recorder.Code, recorder.Body.String())
	}
	assertSingleRejection(t, fixture.logs, forbiddenRejection("/users/{id}/password-recovery", "origin_mismatch"))
	for _, canary := range canaries {
		if strings.Contains(fixture.logs.String(), canary) {
			t.Fatalf("diagnostic recorded %q: %s", canary, fixture.logs.String())
		}
	}
}

type rejectionContextKey struct{}

type contextCapturingHandler struct {
	value string
}

func (*contextCapturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *contextCapturingHandler) Handle(ctx context.Context, _ slog.Record) error {
	h.value, _ = ctx.Value(rejectionContextKey{}).(string)
	return nil
}

func (h *contextCapturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *contextCapturingHandler) WithGroup(string) slog.Handler { return h }

func TestRejectionDiagnosticUsesRequestContext(t *testing.T) {
	handler := &contextCapturingHandler{}
	server := NewServer(Config{Logger: slog.New(handler)})
	request := httptest.NewRequest(http.MethodPost, "/invitations/accept", nil)
	request.Pattern = "POST /invitations/accept"
	request = request.WithContext(context.WithValue(request.Context(), rejectionContextKey{}, "request context"))

	server.logRequestRejected(request, reasonCSRFInvalid)
	if handler.value != "request context" {
		t.Fatalf("diagnostic context value = %q, want request context", handler.value)
	}
}
