package forgejo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestReadVersionDecodesStrictly(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        string
		wantStatus  int
		wantErr     error
	}{
		{name: "ok", status: 200, contentType: "application/json", body: `{"version":"15.0.6"}`, want: "15.0.6"},
		{name: "missing version", status: 200, contentType: "application/json", body: `{}`, wantErr: ErrResponseMalformed},
		{name: "empty version", status: 200, contentType: "application/json", body: `{"version":""}`, wantErr: ErrResponseMalformed},
		{name: "wrong type", status: 200, contentType: "application/json", body: `{"version":15}`, wantErr: ErrResponseMalformed},
		{name: "trailing data", status: 200, contentType: "application/json", body: `{"version":"15.0.6"}{}`, wantErr: ErrResponseMalformed},
		{name: "wrong content type", status: 200, contentType: "text/html", body: `{"version":"15.0.6"}`, wantErr: ErrResponseMalformed},
		{name: "unauthorized", status: 401, contentType: "application/json", body: `{}`, wantStatus: 401},
		{name: "server error", status: 500, contentType: "application/json", body: `{}`, wantStatus: 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v1/version" {
					t.Fatalf("unexpected path %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := New(server.URL, "fixture-token")
			version, err := client.ReadVersion(context.Background())
			if tc.wantStatus != 0 {
				var statusErr *StatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.wantStatus {
					t.Fatalf("expected status %d error, got %v", tc.wantStatus, err)
				}
				return
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || version != tc.want {
				t.Fatalf("version = %q err=%v", version, err)
			}
		})
	}
}

func TestReadCurrentUserRequiresCompleteIdentity(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "ok", body: `{"id":42,"login":"svc-preview","is_admin":false}`},
		{name: "missing id", body: `{"login":"svc-preview","is_admin":false}`, wantErr: true},
		{name: "zero id", body: `{"id":0,"login":"svc-preview","is_admin":false}`, wantErr: true},
		{name: "missing login", body: `{"id":42,"is_admin":false}`, wantErr: true},
		{name: "missing is_admin", body: `{"id":42,"login":"svc-preview"}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := jsonServer(t, "/api/v1/user", tc.body, nil)
			defer server.Close()
			client := New(server.URL, "fixture-token")
			user, err := client.ReadCurrentUser(context.Background())
			if tc.wantErr {
				if !errors.Is(err, ErrResponseMalformed) {
					t.Fatalf("expected malformed response, got %v", err)
				}
				return
			}
			if err != nil || user.ID != 42 || user.Login != "svc-preview" || user.IsAdmin {
				t.Fatalf("user = %+v err=%v", user, err)
			}
		})
	}
}

func TestReadListEndpointsRequireTotalCount(t *testing.T) {
	server := jsonServer(t, "/api/v1/user/orgs", `[{"id":7,"name":"fixture-org","full_name":"Fixture Organization"}]`, nil)
	defer server.Close()
	client := New(server.URL, "fixture-token")
	if _, _, err := client.ReadCurrentUserOrganizations(context.Background(), 1, 50); !errors.Is(err, ErrTotalCountInvalid) {
		t.Fatalf("expected total-count error without header, got %v", err)
	}

	for _, header := range []string{"", "-1", "01", "1x"} {
		withHeader := jsonServer(t, "/api/v1/user/orgs", `[]`, map[string]string{"X-Total-Count": header})
		client := New(withHeader.URL, "fixture-token")
		_, _, err := client.ReadCurrentUserOrganizations(context.Background(), 1, 50)
		withHeader.Close()
		if !errors.Is(err, ErrTotalCountInvalid) {
			t.Fatalf("expected total-count rejection for %q, got %v", header, err)
		}
	}

	valid := jsonServer(t, "/api/v1/user/orgs", `[{"id":7,"name":"fixture-org","full_name":""}]`, map[string]string{"X-Total-Count": "1"})
	defer valid.Close()
	client = New(valid.URL, "fixture-token")
	organizations, total, err := client.ReadCurrentUserOrganizations(context.Background(), 1, 50)
	if err != nil || total != 1 || len(organizations) != 1 || organizations[0].ID != 7 || organizations[0].Name != "fixture-org" {
		t.Fatalf("organizations=%+v total=%d err=%v", organizations, total, err)
	}
}

func TestReadOrganizationRepositoriesValidatesRecords(t *testing.T) {
	body := `[{"id":100,"name":"alpha","owner":{"login":"fixture-org"},"private":false,"default_branch":"main"}]`
	server := jsonServer(t, "/api/v1/orgs/fixture-org/repos", body, map[string]string{"X-Total-Count": "1"})
	defer server.Close()
	client := New(server.URL, "fixture-token")
	repositories, total, err := client.ReadOrganizationRepositories(context.Background(), "fixture-org", 1, 50)
	if err != nil || total != 1 || len(repositories) != 1 {
		t.Fatalf("repositories=%+v total=%d err=%v", repositories, total, err)
	}
	got := repositories[0]
	if got.ID != 100 || got.Owner != "fixture-org" || got.Name != "alpha" || got.DefaultBranch != "main" || got.Private {
		t.Fatalf("repository = %+v", got)
	}

	missingBranch := jsonServer(t, "/api/v1/orgs/fixture-org/repos",
		`[{"id":100,"name":"alpha","owner":{"login":"fixture-org"},"private":false,"default_branch":""}]`,
		map[string]string{"X-Total-Count": "1"})
	defer missingBranch.Close()
	client = New(missingBranch.URL, "fixture-token")
	if _, _, err := client.ReadOrganizationRepositories(context.Background(), "fixture-org", 1, 50); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected malformed record rejection, got %v", err)
	}
}

// TestReadListEndpointsRejectPagesOverTheRequestedLimit proves the hard
// per-page record cap: decoding fails as soon as a page carries more
// records than the requested limit, for both list endpoints.
func TestReadListEndpointsRejectPagesOverTheRequestedLimit(t *testing.T) {
	organizations := make([]string, 0, 3)
	for i := 1; i <= 3; i++ {
		organizations = append(organizations, `{"id":`+strconv.Itoa(i)+`,"name":"org-`+strconv.Itoa(i)+`","full_name":""}`)
	}
	orgServer := jsonServer(t, "/api/v1/user/orgs", "["+strings.Join(organizations, ",")+"]", map[string]string{"X-Total-Count": "3"})
	defer orgServer.Close()
	client := New(orgServer.URL, "fixture-token")
	if _, _, err := client.ReadCurrentUserOrganizations(context.Background(), 1, 2); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected over-limit organization page rejection, got %v", err)
	}

	repositories := make([]string, 0, 3)
	for i := 1; i <= 3; i++ {
		id := strconv.Itoa(i)
		repositories = append(repositories, `{"id":`+id+`,"name":"repo-`+id+`","owner":{"login":"fixture-org"},"private":false,"default_branch":"main"}`)
	}
	repoServer := jsonServer(t, "/api/v1/orgs/fixture-org/repos", "["+strings.Join(repositories, ",")+"]", map[string]string{"X-Total-Count": "3"})
	defer repoServer.Close()
	client = New(repoServer.URL, "fixture-token")
	if _, _, err := client.ReadOrganizationRepositories(context.Background(), "fixture-org", 1, 2); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected over-limit repository page rejection, got %v", err)
	}

	nonArray := jsonServer(t, "/api/v1/user/orgs", `{"id":1}`, map[string]string{"X-Total-Count": "1"})
	defer nonArray.Close()
	client = New(nonArray.URL, "fixture-token")
	if _, _, err := client.ReadCurrentUserOrganizations(context.Background(), 1, 50); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected non-array page rejection, got %v", err)
	}
}

// TestConnectionReadsRejectDuplicateAndAliasedCriticalMembers proves the
// strict object preflight: encoding/json's duplicate-member last-wins and
// case-insensitive field matching can never redefine a critical value —
// top-level or nested — while genuinely unknown Forgejo members stay
// accepted.
func TestConnectionReadsRejectDuplicateAndAliasedCriticalMembers(t *testing.T) {
	version := func(c *Client) error { _, err := c.ReadVersion(context.Background()); return err }
	user := func(c *Client) error { _, err := c.ReadCurrentUser(context.Background()); return err }
	orgs := func(c *Client) error {
		_, _, err := c.ReadCurrentUserOrganizations(context.Background(), 1, 50)
		return err
	}
	repos := func(c *Client) error {
		_, _, err := c.ReadOrganizationRepositories(context.Background(), "fixture-org", 1, 50)
		return err
	}
	repoByID := func(c *Client) error { _, err := c.ReadRepositoryByID(context.Background(), 100); return err }

	cases := []struct {
		name string
		path string
		body string
		call func(*Client) error
	}{
		{name: "duplicate version", path: "/api/v1/version", body: `{"version":"15.0.6","version":"16.0.0"}`, call: version},
		{name: "duplicate user id", path: "/api/v1/user", body: `{"id":42,"id":43,"login":"svc-preview","is_admin":false}`, call: user},
		{name: "aliased is_admin", path: "/api/v1/user", body: `{"id":42,"login":"svc-preview","is_admin":false,"Is_Admin":true}`, call: user},
		{name: "aliased id without canonical member", path: "/api/v1/user", body: `{"ID":42,"login":"svc-preview","is_admin":false}`, call: user},
		{name: "duplicate organization name", path: "/api/v1/user/orgs", body: `[{"id":7,"name":"fixture-org","name":"other-org","full_name":""}]`, call: orgs},
		{name: "aliased organization name", path: "/api/v1/user/orgs", body: `[{"id":7,"Name":"other-org","name":"fixture-org","full_name":""}]`, call: orgs},
		{name: "duplicate repository private", path: "/api/v1/orgs/fixture-org/repos", body: `[{"id":100,"name":"alpha","owner":{"login":"fixture-org"},"private":false,"private":true,"default_branch":"main"}]`, call: repos},
		{name: "aliased repository private", path: "/api/v1/orgs/fixture-org/repos", body: `[{"id":100,"name":"alpha","owner":{"login":"fixture-org"},"Private":true,"private":false,"default_branch":"main"}]`, call: repos},
		{name: "nested duplicate owner login", path: "/api/v1/orgs/fixture-org/repos", body: `[{"id":100,"name":"alpha","owner":{"login":"fixture-org","login":"other-owner"},"private":false,"default_branch":"main"}]`, call: repos},
		{name: "nested aliased owner login", path: "/api/v1/repositories/100", body: `{"id":100,"name":"alpha","owner":{"Login":"other-owner","login":"fixture-org"},"private":false,"default_branch":"main"}`, call: repoByID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := jsonServer(t, tc.path, tc.body, map[string]string{"X-Total-Count": "1"})
			defer server.Close()
			if err := tc.call(New(server.URL, "fixture-token")); !errors.Is(err, ErrResponseMalformed) {
				t.Fatalf("expected strict member rejection, got %v", err)
			}
		})
	}

	// Unknown Forgejo members — top-level and nested — stay accepted.
	userServer := jsonServer(t, "/api/v1/user",
		`{"id":42,"login":"svc-preview","is_admin":false,"avatar_url":"https://cdn.example.test/a.png","language":"en"}`, nil)
	defer userServer.Close()
	account, err := New(userServer.URL, "fixture-token").ReadCurrentUser(context.Background())
	if err != nil || account.ID != 42 || account.Login != "svc-preview" {
		t.Fatalf("unknown user members rejected: %+v err=%v", account, err)
	}
	repoServer := jsonServer(t, "/api/v1/orgs/fixture-org/repos",
		`[{"id":100,"name":"alpha","owner":{"login":"fixture-org","avatar_url":"https://cdn.example.test/o.png"},"private":false,"default_branch":"main","clone_url":"https://forge.example.test/fixture-org/alpha.git"}]`,
		map[string]string{"X-Total-Count": "1"})
	defer repoServer.Close()
	repositories, total, err := New(repoServer.URL, "fixture-token").ReadOrganizationRepositories(context.Background(), "fixture-org", 1, 50)
	if err != nil || total != 1 || len(repositories) != 1 || repositories[0].Owner != "fixture-org" {
		t.Fatalf("unknown repository members rejected: %+v total=%d err=%v", repositories, total, err)
	}
}

// TestConnectionReadRejectsUnsafePathSegments proves the defense-in-depth
// guard: no connection read can be constructed from a segment that would
// alter the API path, so no request leaves the client.
func TestConnectionReadRejectsUnsafePathSegments(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Total-Count", "0")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	client := New(server.URL, "fixture-token")
	for _, organization := range []string{"..", ".", "", "a/b", `a\b`} {
		if _, _, err := client.ReadOrganizationRepositories(context.Background(), organization, 1, 50); !errors.Is(err, ErrResponseMalformed) {
			t.Fatalf("organization %q: expected unsafe segment rejection, got %v", organization, err)
		}
	}
	if requests != 0 {
		t.Fatalf("unsafe segments produced %d requests, want 0", requests)
	}
}

func TestConnectionReadRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"` + strings.Repeat("a", maxConnectionReadBodyBytes) + `"}`))
	}))
	defer server.Close()
	client := New(server.URL, "fixture-token")
	if _, err := client.ReadVersion(context.Background()); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected oversized body rejection, got %v", err)
	}
}

func TestConnectionReadPreservesInstallationSubpath(t *testing.T) {
	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"15.0.6"}`))
	}))
	defer server.Close()
	client := New(server.URL+"/forge", "fixture-token")
	if _, err := client.ReadVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requestedPath != "/forge/api/v1/version" {
		t.Fatalf("requested path = %q, want subpath-joined API path", requestedPath)
	}
}

func jsonServer(t *testing.T, path, body string, headers map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		for key, value := range headers {
			if value != "" {
				w.Header().Set(key, value)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}
