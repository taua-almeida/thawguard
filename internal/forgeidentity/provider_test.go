package forgeidentity

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTokenResponseStrictness(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        LinkResultCode
	}{
		{"bad request status", http.StatusBadRequest, "application/json", `{"error":"invalid_grant"}`, LinkProviderInvalid},
		{"server error status", http.StatusInternalServerError, "application/json", `{}`, LinkProviderUnavailable},
		{"rate limited status", http.StatusTooManyRequests, "application/json", `{}`, LinkProviderUnavailable},
		{"redirect status", http.StatusFound, "application/json", `{}`, LinkProviderInvalid},
		{"html content type", http.StatusOK, "text/html", `{"access_token":"a","token_type":"Bearer"}`, LinkProviderInvalid},
		{"foreign charset", http.StatusOK, "application/json; charset=iso-8859-1", `{"access_token":"a","token_type":"Bearer"}`, LinkProviderInvalid},
		{"utf-8 charset accepted", http.StatusOK, "application/json; charset=UTF-8", `{"access_token":"a","token_type":"Bearer"}`, LinkLinked},
		{"trailing JSON", http.StatusOK, "application/json", `{"access_token":"a","token_type":"Bearer"}{}`, LinkProviderInvalid},
		{"root array", http.StatusOK, "application/json", `[{"access_token":"a","token_type":"Bearer"}]`, LinkProviderInvalid},
		{"duplicate critical key", http.StatusOK, "application/json", `{"access_token":"a","access_token":"b","token_type":"Bearer"}`, LinkProviderInvalid},
		{"case-fold alias of critical key", http.StatusOK, "application/json", `{"Access_Token":"a","access_token":"b","token_type":"Bearer"}`, LinkProviderInvalid},
		{"error member on 200", http.StatusOK, "application/json", `{"access_token":"a","token_type":"Bearer","error":"odd"}`, LinkProviderInvalid},
		{"missing access token", http.StatusOK, "application/json", `{"token_type":"Bearer"}`, LinkProviderInvalid},
		{"empty access token", http.StatusOK, "application/json", `{"access_token":"","token_type":"Bearer"}`, LinkProviderInvalid},
		{"wrong token type", http.StatusOK, "application/json", `{"access_token":"a","token_type":"MAC"}`, LinkProviderInvalid},
		{"lowercase bearer accepted", http.StatusOK, "application/json", `{"access_token":"a","token_type":"bearer"}`, LinkLinked},
		{"refresh token discarded", http.StatusOK, "application/json", `{"access_token":"a","token_type":"Bearer","refresh_token":"r"}`, LinkLinked},
		{"nesting beyond depth four", http.StatusOK, "application/json", `{"access_token":"a","token_type":"Bearer","x":{"a":{"b":{"c":{"d":1}}}}}`, LinkProviderInvalid},
		{"nesting at depth four accepted", http.StatusOK, "application/json", `{"access_token":"a","token_type":"Bearer","x":{"a":{"b":{"c":1}}}}`, LinkLinked},
		{"oversized body", http.StatusOK, "application/json", `{"access_token":"` + strings.Repeat("a", maxProviderBodyBytes) + `","token_type":"Bearer"}`, LinkProviderInvalid},
	}
	seed := byte(0x11)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, provider := newProviderFixture(t)
			provider.set(func(p *fakeForgejoProvider) {
				p.tokenStatus = tc.status
				p.tokenType = tc.contentType
				p.tokenBody = tc.body
			})
			start := startLinkSeeded(t, f, testUserSession, testUserID, seed)
			result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
				RawQuery:     callbackQuery(linkStateForSeed(seed), "code=fixture-code"),
				SessionID:    testUserSession,
				BrowserToken: start.BrowserToken,
			})
			if err != nil || result != tc.want {
				t.Fatalf("result = %q err = %v, want %q", result, err, tc.want)
			}
			if tc.want != LinkLinked {
				if f.identityCount(t) != 0 {
					t.Fatal("failed exchange linked an identity")
				}
				if f.ceremonyCount(t) != 0 {
					t.Fatal("failed exchange left the claimed row")
				}
			}
		})
	}
}

func TestCurrentUserResponseStrictness(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        LinkResultCode
	}{
		{"valid user", http.StatusOK, "application/json", `{"id":777,"login":"fixture-user"}`, LinkLinked},
		{"extra unknown members accepted", http.StatusOK, "application/json", `{"id":777,"login":"fixture-user","is_admin":true,"email":"x@example.test"}`, LinkLinked},
		{"maximum int64 id", http.StatusOK, "application/json", `{"id":9223372036854775807,"login":"fixture-user"}`, LinkLinked},
		{"zero id", http.StatusOK, "application/json", `{"id":0,"login":"fixture-user"}`, LinkProviderInvalid},
		{"negative id", http.StatusOK, "application/json", `{"id":-4,"login":"fixture-user"}`, LinkProviderInvalid},
		{"string id", http.StatusOK, "application/json", `{"id":"777","login":"fixture-user"}`, LinkProviderInvalid},
		{"fractional id", http.StatusOK, "application/json", `{"id":777.0,"login":"fixture-user"}`, LinkProviderInvalid},
		{"exponent id", http.StatusOK, "application/json", `{"id":7e2,"login":"fixture-user"}`, LinkProviderInvalid},
		{"id beyond int64", http.StatusOK, "application/json", `{"id":9223372036854775808,"login":"fixture-user"}`, LinkProviderInvalid},
		{"missing login", http.StatusOK, "application/json", `{"id":777}`, LinkProviderInvalid},
		{"empty login", http.StatusOK, "application/json", `{"id":777,"login":""}`, LinkProviderInvalid},
		{"control character login", http.StatusOK, "application/json", `{"id":777,"login":"badname"}`, LinkProviderInvalid},
		{"oversized login", http.StatusOK, "application/json", `{"id":777,"login":"` + strings.Repeat("a", 256) + `"}`, LinkProviderInvalid},
		{"duplicate id member", http.StatusOK, "application/json", `{"id":777,"id":778,"login":"fixture-user"}`, LinkProviderInvalid},
		{"case-fold alias of id", http.StatusOK, "application/json", `{"ID":778,"id":777,"login":"fixture-user"}`, LinkProviderInvalid},
		{"user endpoint failure", http.StatusNotFound, "application/json", `{}`, LinkProviderInvalid},
		{"user endpoint unavailable", http.StatusServiceUnavailable, "application/json", `{}`, LinkProviderUnavailable},
	}
	seed := byte(0x11)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, provider := newProviderFixture(t)
			provider.set(func(p *fakeForgejoProvider) {
				p.userStatus = tc.status
				p.userType = tc.contentType
				p.userBody = tc.body
			})
			start := startLinkSeeded(t, f, testUserSession, testUserID, seed)
			result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
				RawQuery:     callbackQuery(linkStateForSeed(seed), "code=fixture-code"),
				SessionID:    testUserSession,
				BrowserToken: start.BrowserToken,
			})
			if err != nil || result != tc.want {
				t.Fatalf("result = %q err = %v, want %q", result, err, tc.want)
			}
			if tc.want != LinkLinked && f.identityCount(t) != 0 {
				t.Fatal("invalid user response linked an identity")
			}
		})
	}
}

// deadlineRecordingTransport captures each outbound request's context
// deadline on the client side, where the ceremony's timeout is visible.
type deadlineRecordingTransport struct {
	next        http.RoundTripper
	deadlines   []time.Time
	hasDeadline []bool
}

func (t *deadlineRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, ok := request.Context().Deadline()
	t.deadlines = append(t.deadlines, deadline)
	t.hasDeadline = append(t.hasDeadline, ok)
	return t.next.RoundTrip(request)
}

// TestProviderRequestsShareOneDeadline proves the token exchange and the
// current-user read run under the same single ten-second deadline; a
// second per-request timeout would surface as a later second deadline.
func TestProviderRequestsShareOneDeadline(t *testing.T) {
	f, _ := newProviderFixture(t)
	recorder := &deadlineRecordingTransport{next: http.DefaultTransport}
	f.service.client.Transport = recorder

	start := startLinkForUser(t, f, testUserSession, testUserID)
	result, err := f.service.CompleteLinkCallback(f.ctx, CallbackInput{
		RawQuery:     callbackQuery(linkStateForSeed(0x11), "code=fixture-code"),
		SessionID:    testUserSession,
		BrowserToken: start.BrowserToken,
	})
	if err != nil || result != LinkLinked {
		t.Fatalf("result = %q err = %v", result, err)
	}
	if len(recorder.deadlines) != 2 || !recorder.hasDeadline[0] || !recorder.hasDeadline[1] {
		t.Fatalf("provider requests recorded = %d with deadlines %v", len(recorder.deadlines), recorder.hasDeadline)
	}
	if !recorder.deadlines[0].Equal(recorder.deadlines[1]) {
		t.Fatalf(
			"provider requests carry different deadlines: token %v, user %v",
			recorder.deadlines[0],
			recorder.deadlines[1],
		)
	}
}

func TestParseCallbackQueryBoundary(t *testing.T) {
	state := linkStateForSeed(0x11)
	longValue := strings.Repeat("a", maxCallbackCodeBytes)
	cases := []struct {
		name      string
		query     string
		valid     bool
		wantCode  string
		wantError string
	}{
		{"code flow", "state=" + state + "&code=abc", true, "abc", ""},
		{"error flow", "state=" + state + "&error=access_denied", true, "", "access_denied"},
		{"unknown keys ignored", "state=" + state + "&code=abc&foo=bar&error_description=ignored&error_uri=https%3A%2F%2Fx", true, "abc", ""},
		{"escaped known key honoured", "%73tate=" + state + "&code=abc", true, "abc", ""},
		{"maximum code accepted", "state=" + state + "&code=" + longValue, true, longValue, ""},
		{"missing state", "code=abc", false, "", ""},
		{"short state", "state=abc&code=abc", false, "", ""},
		{"duplicate state", "state=" + state + "&state=" + state + "&code=abc", false, "", ""},
		{"duplicate code", "state=" + state + "&code=a&code=b", false, "", ""},
		{"case-fold alias state", "STATE=x&state=" + state + "&code=abc", false, "", ""},
		{"case-fold alias error", "state=" + state + "&Error=x&code=abc", false, "", ""},
		{"code and error", "state=" + state + "&code=a&error=b", false, "", ""},
		{"neither code nor error", "state=" + state, false, "", ""},
		{"empty code", "state=" + state + "&code=", false, "", ""},
		{"oversized code", "state=" + state + "&code=" + longValue + "a", false, "", ""},
		{"oversized error", "state=" + state + "&error=" + strings.Repeat("e", maxCallbackErrorBytes+1), false, "", ""},
		{"control character code", "state=" + state + "&code=a%00b", false, "", ""},
		{"oversized raw query", "state=" + state + "&code=abc&pad=" + strings.Repeat("p", maxCallbackRawQueryBytes), false, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, valid := parseCallbackQuery(tc.query)
			if valid != tc.valid {
				t.Fatalf("valid = %v, want %v", valid, tc.valid)
			}
			if !valid {
				return
			}
			if response.state != state || response.code != tc.wantCode || response.providerError != tc.wantError {
				t.Fatalf("response = %+v", response)
			}
		})
	}
}
