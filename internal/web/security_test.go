package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCookieSecurityUsesCanonicalPublicURLOrDirectTLS(t *testing.T) {
	tests := []struct {
		name       string
		publicURL  string
		requestURL string
		forwarded  string
		wantSecure bool
	}{
		{
			name:       "canonical HTTPS behind plain backend",
			publicURL:  "https://thawguard.example.test",
			requestURL: "http://backend.internal",
			wantSecure: true,
		},
		{
			name:       "direct TLS with loopback HTTP canonical URL",
			publicURL:  "http://127.0.0.1:8080",
			requestURL: "https://127.0.0.1:8080",
			wantSecure: true,
		},
		{
			name:       "loopback HTTP development",
			publicURL:  "http://127.0.0.1:8080",
			requestURL: "http://127.0.0.1:8080",
			wantSecure: false,
		},
		{
			name:       "forwarded HTTPS is not trusted",
			publicURL:  "http://localhost:8080",
			requestURL: "http://backend.internal",
			forwarded:  "https",
			wantSecure: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer(Config{PublicURL: tc.publicURL})
			request := httptest.NewRequest(http.MethodGet, tc.requestURL, nil)
			if tc.forwarded != "" {
				request.Header.Set("X-Forwarded-Proto", tc.forwarded)
			}

			assertCookiePairSecurity(t, sessionCookieName, "/", tc.wantSecure,
				func(w http.ResponseWriter) {
					server.setSessionCookie(w, request, sessionState{ID: "session", ExpiresAt: time.Now().Add(time.Hour)})
				},
				func(w http.ResponseWriter) { server.clearSessionCookie(w, request) },
			)
			assertCookiePairSecurity(t, setupCookieName, "/setup", tc.wantSecure,
				func(w http.ResponseWriter) {
					if _, err := server.newSetupCSRFToken(w, request); err != nil {
						t.Fatal(err)
					}
				},
				func(w http.ResponseWriter) { server.clearSetupCSRFCookie(w, request) },
			)
			assertCookiePairSecurity(t, loginCookieName, "/login", tc.wantSecure,
				func(w http.ResponseWriter) {
					if _, err := server.newLoginCSRFToken(w, request); err != nil {
						t.Fatal(err)
					}
				},
				func(w http.ResponseWriter) { server.clearLoginCSRFCookie(w, request) },
			)
		})
	}
}

func assertCookiePairSecurity(
	t *testing.T,
	name string,
	path string,
	wantSecure bool,
	set func(http.ResponseWriter),
	clearCookie func(http.ResponseWriter),
) {
	t.Helper()

	setRecorder := httptest.NewRecorder()
	set(setRecorder)
	setCookie := responseCookie(t, setRecorder, name)

	clearRecorder := httptest.NewRecorder()
	clearCookie(clearRecorder)
	deleted := responseCookie(t, clearRecorder, name)

	for label, cookie := range map[string]*http.Cookie{"set": setCookie, "delete": deleted} {
		if cookie.Secure != wantSecure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != path {
			t.Fatalf("%s %s cookie attributes = Secure:%v HttpOnly:%v SameSite:%v Path:%q", label, name, cookie.Secure, cookie.HttpOnly, cookie.SameSite, cookie.Path)
		}
	}
	if deleted.Value != "" || deleted.MaxAge >= 0 {
		t.Fatalf("deleted %s cookie was not expired: value=%q max-age=%d", name, deleted.Value, deleted.MaxAge)
	}
}

func responseCookie(t *testing.T, recorder *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response did not set %s cookie", name)
	return nil
}
