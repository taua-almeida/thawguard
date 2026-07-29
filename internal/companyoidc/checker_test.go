package companyoidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiscoveryURLFollowsOIDCPathConstruction(t *testing.T) {
	tests := map[string]string{
		"https://id.example":          "https://id.example/.well-known/openid-configuration",
		"https://id.example/":         "https://id.example/.well-known/openid-configuration",
		"https://id.example/tenant":   "https://id.example/tenant/.well-known/openid-configuration",
		"https://id.example/tenant/":  "https://id.example/tenant/.well-known/openid-configuration",
		"https://id.example/tenant//": "https://id.example/tenant//.well-known/openid-configuration",
	}
	for issuer, want := range tests {
		if got := discoveryURL(issuer); got != want {
			t.Fatalf("discoveryURL(%q) = %q, want %q", issuer, got, want)
		}
	}
}

func TestCheckerVerifiesSameHostAndCrossHostJWKS(t *testing.T) {
	t.Run("same host", func(t *testing.T) {
		provider := newTLSOIDCProvider(t, "/tenant")
		provider.discoveryContentType = "application/json; charset=utf-8"
		provider.jwksContentType = "application/jwk-set+json; charset=utf-8"
		provider.jwksBody = mustJSON(t, map[string]any{"keys": []any{validRSAJWK(), validRSAJWK()}})

		report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
		assertCheckReport(t, report, SetupCheckVerified, "", 2)
		if got := provider.paths(); !slices.Equal(got, []string{"/tenant/.well-known/openid-configuration", "/jwks"}) {
			t.Fatalf("request paths = %v", got)
		}
	})

	t.Run("cross host", func(t *testing.T) {
		var jwksRequests atomic.Int64
		jwksServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwksRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(mustJSON(t, map[string]any{"keys": []any{validRSAJWK()}}))
		}))
		t.Cleanup(jwksServer.Close)
		provider := newTLSOIDCProvider(t, "")
		provider.discoveryMutate = func(document map[string]any) {
			document["jwks_uri"] = jwksServer.URL + "/keys?set=current"
		}

		report := NewChecker(trustedTransport(t, provider.server, jwksServer)).Check(context.Background(), provider.issuer)
		assertCheckReport(t, report, SetupCheckVerified, "", 1)
		if jwksRequests.Load() != 1 {
			t.Fatalf("cross-host JWKS requests = %d", jwksRequests.Load())
		}
	})
}

func TestCheckerDiscoveryFailureCodesAreStableAndSanitized(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*testOIDCProvider)
		want          SetupCheckResultCode
		forbiddenText string
	}{
		{
			name: "non-200",
			configure: func(provider *testOIDCProvider) {
				provider.discoveryStatus = http.StatusBadGateway
				provider.discoveryBody = []byte("upstream prose canary")
			},
			want:          SetupCheckDiscoveryUnavailable,
			forbiddenText: "upstream prose canary",
		},
		{
			name: "malformed",
			configure: func(provider *testOIDCProvider) {
				provider.discoveryBody = []byte(`{"issuer":`)
			},
			want:          SetupCheckDiscoveryInvalid,
			forbiddenText: "issuer",
		},
		{
			name: "oversized",
			configure: func(provider *testOIDCProvider) {
				provider.discoveryBody = []byte(strings.Repeat("x", setupCheckMaxBodySize+1))
			},
			want: SetupCheckDiscoveryInvalid,
		},
		{
			name: "wrong content type",
			configure: func(provider *testOIDCProvider) {
				provider.discoveryContentType = "text/html"
			},
			want: SetupCheckDiscoveryInvalid,
		},
		{
			name: "redirect",
			configure: func(provider *testOIDCProvider) {
				provider.discoveryRedirect = "/hidden-discovery"
			},
			want: SetupCheckDiscoveryUnavailable,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTLSOIDCProvider(t, "")
			tc.configure(provider)
			report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
			assertCheckReport(t, report, tc.want, "", -1)
			if tc.forbiddenText != "" && strings.Contains(fmt.Sprintf("%+v", report), tc.forbiddenText) {
				t.Fatalf("stable report leaked upstream text: %+v", report)
			}
			if provider.hiddenRequests.Load() != 0 {
				t.Fatal("checker followed a discovery redirect")
			}
		})
	}
}

func TestCheckerRejectsInvalidUTF8BeforeJSONDecoding(t *testing.T) {
	t.Run("discovery", func(t *testing.T) {
		provider := newTLSOIDCProvider(t, "")
		body := mustJSON(t, validDiscoveryDocument(provider.issuer, provider.server.URL+"/jwks"))
		provider.discoveryBody = withIgnoredInvalidUTF8String(t, body)

		report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
		assertCheckReport(t, report, SetupCheckDiscoveryInvalid, "", -1)
		if provider.jwksRequests.Load() != 0 {
			t.Fatal("invalid UTF-8 discovery response triggered a JWKS request")
		}
	})

	t.Run("JWKS", func(t *testing.T) {
		provider := newTLSOIDCProvider(t, "")
		body := mustJSON(t, map[string]any{"keys": []any{validRSAJWK()}})
		provider.jwksBody = withIgnoredInvalidUTF8String(t, body)

		report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
		assertCheckReport(t, report, SetupCheckJWKSInvalid, "", -1)
	})
}

func TestCheckerIssuerValidationKeepsTerminalSlashIdentityExact(t *testing.T) {
	tests := []struct {
		name     string
		observed any
		want     SetupCheckResultCode
	}{
		{name: "missing", observed: nil, want: SetupCheckIssuerInvalid},
		{name: "wrong type", observed: 7, want: SetupCheckIssuerInvalid},
		{name: "relative", observed: "/tenant", want: SetupCheckIssuerInvalid},
		{name: "outer whitespace", observed: " https://id.example.test", want: SetupCheckIssuerInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTLSOIDCProvider(t, "")
			provider.discoveryMutate = func(document map[string]any) {
				if tc.observed == nil {
					delete(document, "issuer")
					return
				}
				document["issuer"] = tc.observed
			}
			report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
			assertCheckReport(t, report, tc.want, "", -1)
		})
	}

	provider := newTLSOIDCProvider(t, "/tenant/")
	provider.discoveryMutate = func(document map[string]any) {
		document["issuer"] = strings.TrimSuffix(provider.issuer, "/")
	}
	report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
	assertCheckReport(t, report, SetupCheckIssuerMismatch, strings.TrimSuffix(provider.issuer, "/"), -1)
	if got := provider.paths(); len(got) != 1 || got[0] != "/tenant/.well-known/openid-configuration" {
		t.Fatalf("terminal-slash discovery path = %v", got)
	}
}

func TestCheckerRejectsIncompatibleRequiredMetadataBeforeJWKS(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "authorization endpoint missing", mutate: func(document map[string]any) { delete(document, "authorization_endpoint") }},
		{name: "authorization endpoint HTTP", mutate: func(document map[string]any) { document["authorization_endpoint"] = "http://id.example/authorize" }},
		{name: "token endpoint relative", mutate: func(document map[string]any) { document["token_endpoint"] = "/token" }},
		{name: "JWKS userinfo", mutate: func(document map[string]any) { document["jwks_uri"] = "https://user@id.example/keys" }},
		{name: "JWKS fragment", mutate: func(document map[string]any) { document["jwks_uri"] = "https://id.example/keys#fragment" }},
		{name: "response type missing code", mutate: func(document map[string]any) { document["response_types_supported"] = []string{"id_token"} }},
		{name: "subject type unrecognized", mutate: func(document map[string]any) { document["subject_types_supported"] = []string{"sector"} }},
		{name: "signing algorithm missing RS256", mutate: func(document map[string]any) { document["id_token_signing_alg_values_supported"] = []string{"ES256"} }},
		{name: "present grants missing authorization code", mutate: func(document map[string]any) { document["grant_types_supported"] = []string{"implicit"} }},
		{name: "present grants null", mutate: func(document map[string]any) { document["grant_types_supported"] = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTLSOIDCProvider(t, "")
			provider.discoveryMutate = tc.mutate
			report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
			assertCheckReport(t, report, SetupCheckMetadataIncompatible, "", -1)
			if provider.jwksRequests.Load() != 0 {
				t.Fatal("incompatible metadata still triggered a JWKS request")
			}
		})
	}

	provider := newTLSOIDCProvider(t, "")
	provider.discoveryMutate = func(document map[string]any) {
		delete(document, "grant_types_supported")
		document["subject_types_supported"] = []string{"pairwise"}
	}
	report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
	assertCheckReport(t, report, SetupCheckVerified, "", 1)
}

func TestCheckerJWKSFailureCodesAndShapes(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*testOIDCProvider)
		want      SetupCheckResultCode
		count     int64
	}{
		{name: "non-200", configure: func(provider *testOIDCProvider) { provider.jwksStatus = http.StatusServiceUnavailable }, want: SetupCheckJWKSUnavailable, count: -1},
		{name: "redirect", configure: func(provider *testOIDCProvider) { provider.jwksRedirect = "/hidden-jwks" }, want: SetupCheckJWKSUnavailable, count: -1},
		{name: "malformed JSON", configure: func(provider *testOIDCProvider) { provider.jwksBody = []byte(`{"keys":`) }, want: SetupCheckJWKSInvalid, count: -1},
		{name: "oversized", configure: func(provider *testOIDCProvider) {
			provider.jwksBody = []byte(strings.Repeat("x", setupCheckMaxBodySize+1))
		}, want: SetupCheckJWKSInvalid, count: -1},
		{name: "wrong content type", configure: func(provider *testOIDCProvider) { provider.jwksContentType = "application/jwk+json" }, want: SetupCheckJWKSInvalid, count: -1},
		{name: "missing keys", configure: func(provider *testOIDCProvider) { provider.jwksBody = []byte(`{}`) }, want: SetupCheckJWKSInvalid, count: -1},
		{name: "null keys", configure: func(provider *testOIDCProvider) { provider.jwksBody = []byte(`{"keys":null}`) }, want: SetupCheckJWKSInvalid, count: -1},
		{name: "empty keys", configure: func(provider *testOIDCProvider) { provider.jwksBody = []byte(`{"keys":[]}`) }, want: SetupCheckJWKSInvalid, count: -1},
		{name: "malformed key", configure: func(provider *testOIDCProvider) { provider.jwksBody = []byte(`{"keys":[7]}`) }, want: SetupCheckJWKSInvalid, count: -1},
		{name: "unsupported set", configure: func(provider *testOIDCProvider) { provider.jwksBody = []byte(`{"keys":[{"kty":"EC","crv":"P-256"}]}`) }, want: SetupCheckJWKSNoCandidate, count: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := newTLSOIDCProvider(t, "")
			tc.configure(provider)
			report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
			assertCheckReport(t, report, tc.want, "", tc.count)
			if provider.hiddenRequests.Load() != 0 {
				t.Fatal("checker followed a JWKS redirect")
			}
		})
	}
}

func TestSupportedRSACandidatePredicateAndNumericBoundaries(t *testing.T) {
	validModulus := testModulus(0x80, 0x01)
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   bool
	}{
		{name: "minimal supported", want: true},
		{name: "exact optional fields", mutate: func(key map[string]any) {
			key["alg"] = "RS256"
			key["use"] = "sig"
			key["key_ops"] = []string{"verify"}
		}, want: true},
		{name: "lower exponent boundary", mutate: func(key map[string]any) { key["e"] = encodeUInt(3) }, want: true},
		{name: "upper exponent boundary", mutate: func(key map[string]any) { key["e"] = encodeUInt(1<<31 - 1) }, want: true},
		{name: "wrong kty", mutate: func(key map[string]any) { key["kty"] = "rsa" }},
		{name: "zero modulus", mutate: func(key map[string]any) { key["n"] = base64.RawURLEncoding.EncodeToString([]byte{0}) }},
		{name: "leading-zero modulus", mutate: func(key map[string]any) {
			key["n"] = base64.RawURLEncoding.EncodeToString(append([]byte{0}, validModulus...))
		}},
		{name: "short modulus", mutate: func(key map[string]any) { key["n"] = base64.RawURLEncoding.EncodeToString(testModulus(0x40, 0x01)) }},
		{name: "even modulus", mutate: func(key map[string]any) { key["n"] = base64.RawURLEncoding.EncodeToString(testModulus(0x80, 0x02)) }},
		{name: "padded exponent", mutate: func(key map[string]any) { key["e"] = "AQAB=" }},
		{name: "leading-zero exponent", mutate: func(key map[string]any) { key["e"] = base64.RawURLEncoding.EncodeToString([]byte{0, 3}) }},
		{name: "low exponent", mutate: func(key map[string]any) { key["e"] = encodeUInt(1) }},
		{name: "even exponent", mutate: func(key map[string]any) { key["e"] = encodeUInt(4) }},
		{name: "high exponent", mutate: func(key map[string]any) { key["e"] = encodeUInt(1<<31 + 1) }},
		{name: "wrong alg", mutate: func(key map[string]any) { key["alg"] = "PS256" }},
		{name: "null alg", mutate: func(key map[string]any) { key["alg"] = nil }},
		{name: "wrong use", mutate: func(key map[string]any) { key["use"] = "enc" }},
		{name: "empty key ops", mutate: func(key map[string]any) { key["key_ops"] = []string{} }},
		{name: "wrong key op", mutate: func(key map[string]any) { key["key_ops"] = []string{"sign"} }},
		{name: "duplicate verify key ops", mutate: func(key map[string]any) { key["key_ops"] = []string{"verify", "verify"} }},
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		field := privateField
		tests = append(tests, struct {
			name   string
			mutate func(map[string]any)
			want   bool
		}{name: "private field " + field, mutate: func(key map[string]any) { key[field] = "private" }})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := validRSAJWK()
			if tc.mutate != nil {
				tc.mutate(key)
			}
			raw := mustJSON(t, key)
			object, ok := decodeJSONObject(raw)
			if !ok {
				t.Fatal("test key did not decode")
			}
			if got := supportedRSACandidate(object); got != tc.want {
				t.Fatalf("supportedRSACandidate = %v, want %v; key=%s", got, tc.want, raw)
			}
		})
	}
}

func TestCheckerUsesOneDeadlineAndHonorsCancellationDuringBodyReads(t *testing.T) {
	t.Run("already cancelled", func(t *testing.T) {
		provider := newTLSOIDCProvider(t, "")
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report := NewChecker(trustedTransport(t, provider.server)).Check(ctx, provider.issuer)
		assertCheckReport(t, report, SetupCheckDiscoveryUnavailable, "", -1)
	})

	t.Run("one deadline spans delayed stages", func(t *testing.T) {
		provider := newTLSOIDCProvider(t, "")
		provider.discoveryDelay = 60 * time.Millisecond
		provider.jwksDelay = 60 * time.Millisecond
		recorder := &deadlineRecordingTransport{next: trustedTransport(t, provider.server)}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		report := NewChecker(recorder).Check(ctx, provider.issuer)
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("cancelled run took %v", elapsed)
		}
		assertCheckReport(t, report, SetupCheckJWKSUnavailable, "", -1)
		deadlines := recorder.recordedDeadlines()
		if len(deadlines) != 2 || deadlines[0].IsZero() || !deadlines[0].Equal(deadlines[1]) {
			t.Fatalf("request deadlines = %v, want one shared deadline", deadlines)
		}
	})

	t.Run("discovery body read cancellation", func(t *testing.T) {
		started := make(chan struct{})
		var server *httptest.Server
		server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"issuer":"`))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			close(started)
			<-r.Context().Done()
		}))
		t.Cleanup(server.Close)
		checker := NewChecker(trustedTransport(t, server))
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		result := make(chan SetupCheckReport, 1)
		go func() {
			result <- checker.Check(ctx, server.URL)
		}()
		<-started
		report := <-result
		assertCheckReport(t, report, SetupCheckDiscoveryUnavailable, "", -1)
	})
}

func TestCheckerSendsNoCookiesOrCredentials(t *testing.T) {
	provider := newTLSOIDCProvider(t, "")
	provider.setCookie = true
	canaries := []string{"authorization", "cookie", "client-id", "client-secret"}
	provider.inspectRequest = func(r *http.Request) {
		for _, header := range []string{"Authorization", "Cookie", "Client-ID", "Client-Secret", "X-Client-ID", "X-Client-Secret"} {
			if value := r.Header.Get(header); value != "" {
				t.Errorf("request sent %s=%q", header, value)
			}
		}
		for name, values := range r.Header {
			joined := strings.ToLower(strings.Join(values, " "))
			for _, canary := range canaries {
				if strings.Contains(joined, canary) {
					t.Errorf("request header %s contains credential canary %q", name, canary)
				}
			}
		}
	}
	report := NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), provider.issuer)
	assertCheckReport(t, report, SetupCheckVerified, "", 1)

	before := len(provider.paths())
	userinfoIssuer := strings.Replace(provider.issuer, "https://", "https://user@", 1)
	report = NewChecker(trustedTransport(t, provider.server)).Check(context.Background(), userinfoIssuer)
	assertCheckReport(t, report, SetupCheckDiscoveryInvalid, "", -1)
	if after := len(provider.paths()); after != before {
		t.Fatal("checker sent a request for an issuer URL containing user information")
	}
}

type testOIDCProvider struct {
	t *testing.T

	server               *httptest.Server
	issuer               string
	discoveryPath        string
	discoveryStatus      int
	discoveryContentType string
	discoveryBody        []byte
	discoveryRedirect    string
	discoveryDelay       time.Duration
	discoveryMutate      func(map[string]any)
	jwksStatus           int
	jwksContentType      string
	jwksBody             []byte
	jwksRedirect         string
	jwksDelay            time.Duration
	setCookie            bool
	inspectRequest       func(*http.Request)

	mu             sync.Mutex
	requestPaths   []string
	jwksRequests   atomic.Int64
	hiddenRequests atomic.Int64
}

func newTLSOIDCProvider(t *testing.T, issuerPath string) *testOIDCProvider {
	t.Helper()
	provider := &testOIDCProvider{
		t:                    t,
		discoveryStatus:      http.StatusOK,
		discoveryContentType: "application/json",
		jwksStatus:           http.StatusOK,
		jwksContentType:      "application/json",
		jwksBody:             mustJSON(t, map[string]any{"keys": []any{validRSAJWK()}}),
	}
	provider.server = httptest.NewTLSServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	provider.issuer = provider.server.URL + issuerPath
	provider.discoveryPath = strings.TrimSuffix(issuerPath, "/") + "/.well-known/openid-configuration"
	return provider
}

func (provider *testOIDCProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	provider.mu.Lock()
	provider.requestPaths = append(provider.requestPaths, r.URL.Path)
	provider.mu.Unlock()
	if provider.inspectRequest != nil {
		provider.inspectRequest(r)
	}
	switch r.URL.Path {
	case provider.discoveryPath:
		if !waitForRequest(r, provider.discoveryDelay) {
			return
		}
		if provider.discoveryRedirect != "" {
			http.Redirect(w, r, provider.discoveryRedirect, http.StatusFound)
			return
		}
		if provider.setCookie {
			http.SetCookie(w, &http.Cookie{Name: "provider", Value: "cookie-canary", Path: "/"})
		}
		w.Header().Set("Content-Type", provider.discoveryContentType)
		w.WriteHeader(provider.discoveryStatus)
		body := provider.discoveryBody
		if body == nil {
			document := validDiscoveryDocument(provider.issuer, provider.server.URL+"/jwks")
			if provider.discoveryMutate != nil {
				provider.discoveryMutate(document)
			}
			body = mustJSON(provider.t, document)
		}
		_, _ = w.Write(body)
	case "/jwks":
		provider.jwksRequests.Add(1)
		if !waitForRequest(r, provider.jwksDelay) {
			return
		}
		if provider.jwksRedirect != "" {
			http.Redirect(w, r, provider.jwksRedirect, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", provider.jwksContentType)
		w.WriteHeader(provider.jwksStatus)
		_, _ = w.Write(provider.jwksBody)
	case "/hidden-discovery", "/hidden-jwks":
		provider.hiddenRequests.Add(1)
		http.Error(w, "redirect followed", http.StatusInternalServerError)
	default:
		http.NotFound(w, r)
	}
}

func (provider *testOIDCProvider) paths() []string {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	return slices.Clone(provider.requestPaths)
}

func waitForRequest(r *http.Request, delay time.Duration) bool {
	if delay == 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-r.Context().Done():
		return false
	}
}

func validDiscoveryDocument(issuer, jwksURI string) map[string]any {
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize?prompt=login",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              jwksURI,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported":                 []string{"authorization_code"},
	}
}

func validRSAJWK() map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(testModulus(0x80, 0x01)),
		"e":   encodeUInt(65537),
	}
}

func testModulus(first, last byte) []byte {
	modulus := make([]byte, 256)
	modulus[0] = first
	modulus[len(modulus)-1] = last
	return modulus
}

func encodeUInt(value uint64) string {
	return base64.RawURLEncoding.EncodeToString(new(big.Int).SetUint64(value).Bytes())
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func withIgnoredInvalidUTF8String(t *testing.T, document []byte) []byte {
	t.Helper()
	if len(document) == 0 || document[len(document)-1] != '}' {
		t.Fatalf("test JSON document is not an object: %q", document)
	}
	result := slices.Clone(document[:len(document)-1])
	result = append(result, []byte(`,"ignored":"`)...)
	result = append(result, 0xff, '"', '}')
	return result
}

func trustedTransport(t *testing.T, servers ...*httptest.Server) *http.Transport {
	t.Helper()
	roots := x509.NewCertPool()
	for _, server := range servers {
		roots.AddCert(server.Certificate())
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func assertCheckReport(
	t *testing.T,
	report SetupCheckReport,
	wantCode SetupCheckResultCode,
	wantObserved string,
	wantCandidates int64,
) {
	t.Helper()
	if report.ResultCode != wantCode {
		t.Fatalf("result code = %q, want %q", report.ResultCode, wantCode)
	}
	if wantObserved == "" {
		if report.ObservedIssuer != nil {
			t.Fatalf("observed issuer = %q, want nil", *report.ObservedIssuer)
		}
	} else if report.ObservedIssuer == nil || *report.ObservedIssuer != wantObserved {
		t.Fatalf("observed issuer = %v, want %q", report.ObservedIssuer, wantObserved)
	}
	if wantCandidates < 0 {
		if report.PublicKeyCandidateCount != nil {
			t.Fatalf("candidate count = %d, want nil", *report.PublicKeyCandidateCount)
		}
	} else if report.PublicKeyCandidateCount == nil || *report.PublicKeyCandidateCount != wantCandidates {
		t.Fatalf("candidate count = %v, want %d", report.PublicKeyCandidateCount, wantCandidates)
	}
}

type deadlineRecordingTransport struct {
	next http.RoundTripper
	mu   sync.Mutex
	seen []time.Time
}

func (transport *deadlineRecordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	deadline, _ := request.Context().Deadline()
	transport.mu.Lock()
	transport.seen = append(transport.seen, deadline)
	transport.mu.Unlock()
	return transport.next.RoundTrip(request)
}

func (transport *deadlineRecordingTransport) recordedDeadlines() []time.Time {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return slices.Clone(transport.seen)
}
