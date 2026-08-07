package forgejo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

// fakeForgejo serves the read-only endpoints the observation uses and
// records every request so tests can prove no write endpoint is touched.
type fakeForgejo struct {
	t *testing.T

	mu       sync.Mutex
	requests []string

	version          string
	user             map[string]any
	userStatus       int
	orgs             []map[string]any
	orgsDuplicateIDs bool
	repos            []map[string]any
	reposStatus      int
	repoByID         map[int64]map[string]any
	repoStatus       int
	totalDrift       bool
	dropTotal        bool
	duplicateIDs     bool
}

func newFakeForgejo(t *testing.T) *fakeForgejo {
	return &fakeForgejo{
		t:       t,
		version: "15.0.6",
		user:    map[string]any{"id": 42, "login": "svc-preview", "is_admin": false},
		orgs: []map[string]any{
			{"id": 7, "name": "fixture-org", "full_name": "Fixture Organization"},
		},
		repos: []map[string]any{
			repoRecord(100, "fixture-org", "alpha", "main", false),
			repoRecord(101, "fixture-org", "beta", "main", true),
		},
		repoByID: map[int64]map[string]any{
			101: repoRecord(101, "fixture-org", "beta", "main", true),
		},
	}
}

func repoRecord(id int64, owner, name, branch string, private bool) map[string]any {
	return map[string]any{
		"id":             id,
		"name":           name,
		"owner":          map[string]any{"login": owner},
		"private":        private,
		"default_branch": branch,
	}
}

func (f *fakeForgejo) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Method != http.MethodGet {
			f.t.Errorf("non-GET request during observation: %s %s", r.Method, r.URL.Path)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/version":
			writeJSON(w, 200, map[string]any{"version": f.version})
		case r.URL.Path == "/api/v1/user":
			status := f.userStatus
			if status == 0 {
				status = 200
			}
			writeJSON(w, status, f.user)
		case r.URL.Path == "/api/v1/user/orgs":
			f.writePage(w, r, f.orgs, 0, f.orgsDuplicateIDs)
		case len(f.orgs) > 0 && r.URL.Path == "/api/v1/orgs/"+f.orgs[0]["name"].(string)+"/repos":
			f.writePage(w, r, f.repos, f.reposStatus, f.duplicateIDs)
		default:
			if id, found := parseRepoIDPath(r.URL.Path); found {
				status := f.repoStatus
				if status == 0 {
					status = 200
				}
				record, ok := f.repoByID[id]
				if !ok {
					status = 404
				}
				writeJSON(w, status, record)
				return
			}
			http.NotFound(w, r)
		}
	})
}

func (f *fakeForgejo) writePage(w http.ResponseWriter, r *http.Request, records []map[string]any, status int, duplicate bool) {
	if status != 0 {
		writeJSON(w, status, map[string]any{})
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page < 1 || limit < 1 {
		f.t.Errorf("missing pagination parameters: %s", r.URL.RawQuery)
	}
	total := len(records)
	if f.totalDrift {
		total += page - 1
	}
	start := min((page-1)*limit, len(records))
	end := min(start+limit, len(records))
	pageRecords := records[start:end]
	if duplicate && page > 1 && len(records) > 0 {
		pageRecords = records[:1]
	}
	if !f.dropTotal {
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
	}
	writeJSON(w, 200, pageRecords)
}

func parseRepoIDPath(path string) (int64, bool) {
	var id int64
	if _, err := fmt.Sscanf(path, "/api/v1/repositories/%d", &id); err != nil {
		return 0, false
	}
	return id, true
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func observe(t *testing.T, fake *fakeForgejo, input forgeconnection.ObserveInput) forgeconnection.Observation {
	t.Helper()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	if input.BaseURL == "" {
		input.BaseURL = server.URL
	}
	if input.OrganizationSlug == "" {
		input.OrganizationSlug = "fixture-org"
	}
	if input.PAT == nil {
		input.PAT = []byte("fictional-service-pat")
	}
	return NewAdapter(nil).Observe(context.Background(), input)
}

func TestObserveSuccessWithPrivateReadProof(t *testing.T) {
	fake := newFakeForgejo(t)
	observation := observe(t, fake, forgeconnection.ObserveInput{})
	if observation.ResultCode != forgeconnection.CheckVisibleInventoryObserved {
		t.Fatalf("result = %s", observation.ResultCode)
	}
	if observation.ObservedVersion != "15.0.6" ||
		observation.ServiceUserRemoteID != "42" ||
		observation.Organization.RemoteID != "7" ||
		observation.Organization.Slug != "fixture-org" ||
		observation.Organization.DisplayName != "Fixture Organization" {
		t.Fatalf("observation identity: %+v", observation)
	}
	if len(observation.Repositories) != 2 ||
		observation.Repositories[0].RemoteID != "100" ||
		observation.Repositories[1].Private != true {
		t.Fatalf("repositories: %+v", observation.Repositories)
	}
	// The proof read hit the direct repository endpoint, and nothing but
	// GETs on the expected read endpoints happened.
	sawProof := false
	for _, request := range fake.requests {
		if request == "GET /api/v1/repositories/101" {
			sawProof = true
		}
	}
	if !sawProof {
		t.Fatalf("private-read proof request missing: %v", fake.requests)
	}
}

func TestObservePrivateReadUnprovenWithoutPrivateRepositories(t *testing.T) {
	fake := newFakeForgejo(t)
	fake.repos = []map[string]any{repoRecord(100, "fixture-org", "alpha", "main", false)}
	observation := observe(t, fake, forgeconnection.ObserveInput{})
	if observation.ResultCode != forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven {
		t.Fatalf("result = %s", observation.ResultCode)
	}
	for _, request := range fake.requests {
		if request == "GET /api/v1/repositories/100" {
			t.Fatal("public repository was probed for private-read proof")
		}
	}
}

func TestObserveClassifiesIdentityFailures(t *testing.T) {
	adminFake := newFakeForgejo(t)
	adminFake.user = map[string]any{"id": 42, "login": "svc-preview", "is_admin": true}
	if got := observe(t, adminFake, forgeconnection.ObserveInput{}); got.ResultCode != forgeconnection.CheckServiceUserIsAdmin {
		t.Fatalf("admin result = %s", got.ResultCode)
	}

	changedFake := newFakeForgejo(t)
	if got := observe(t, changedFake, forgeconnection.ObserveInput{BoundServiceUserRemoteID: "77"}); got.ResultCode != forgeconnection.CheckServiceUserChanged {
		t.Fatalf("changed-user result = %s", got.ResultCode)
	}

	missingOrg := newFakeForgejo(t)
	if got := observe(t, missingOrg, forgeconnection.ObserveInput{OrganizationSlug: "other-org"}); got.ResultCode != forgeconnection.CheckOrganizationUnavailable {
		t.Fatalf("missing-organization result = %s", got.ResultCode)
	}

	changedOrg := newFakeForgejo(t)
	if got := observe(t, changedOrg, forgeconnection.ObserveInput{
		BoundServiceUserRemoteID:  "42",
		BoundOrganizationRemoteID: "9",
	}); got.ResultCode != forgeconnection.CheckOrganizationChanged {
		t.Fatalf("changed-organization result = %s", got.ResultCode)
	}

	renamedOrg := newFakeForgejo(t)
	renamedOrg.orgs = []map[string]any{{"id": 7, "name": "renamed-org", "full_name": "Renamed"}}
	renamedOrg.repos = []map[string]any{repoRecord(100, "renamed-org", "alpha", "main", false)}
	renamedOrg.repoByID = map[int64]map[string]any{}
	got := observe(t, renamedOrg, forgeconnection.ObserveInput{
		BoundServiceUserRemoteID:  "42",
		BoundOrganizationRemoteID: "7",
	})
	if got.ResultCode != forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven ||
		got.Organization.Slug != "renamed-org" {
		t.Fatalf("rename refresh: %+v", got)
	}
	if renamedOrg.requests[len(renamedOrg.requests)-1] != "GET /api/v1/orgs/renamed-org/repos" &&
		got.ResultCode.Observed() {
		t.Fatalf("renamed organization repos were not listed under the current slug: %v", renamedOrg.requests)
	}
}

// TestObserveRejectsUnsafeRenamedOrganizationName proves a bound
// organization renamed outside Forgejo's own name rules can never reach a
// request path: the observation fails as invalid_response before any
// repository listing request is issued.
func TestObserveRejectsUnsafeRenamedOrganizationName(t *testing.T) {
	for _, name := range []string{"..", ".", "renamed org", "renamed/org"} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeForgejo(t)
			fake.orgs = []map[string]any{{"id": 7, "name": name, "full_name": "Renamed"}}
			got := observe(t, fake, forgeconnection.ObserveInput{
				BoundServiceUserRemoteID:  "42",
				BoundOrganizationRemoteID: "7",
			})
			if got.ResultCode != forgeconnection.CheckInvalidResponse {
				t.Fatalf("result = %s, want invalid_response", got.ResultCode)
			}
			for _, request := range fake.requests {
				if strings.Contains(request, "/repos") || strings.Contains(request, name) {
					t.Fatalf("unsafe organization name reached a request path: %v", fake.requests)
				}
			}
		})
	}
}

// TestObserveValidatesEveryOrganizationAndRejectsRepeatedPages proves the
// organization listing protocol: every record is validated and a repeated
// immutable id means the listing is never accepted as complete.
func TestObserveValidatesEveryOrganizationAndRejectsRepeatedPages(t *testing.T) {
	manyOrgs := func(count int) []map[string]any {
		records := make([]map[string]any, 0, count)
		for i := range count {
			records = append(records, map[string]any{"id": 500 + i, "name": fmt.Sprintf("org-%04d", i), "full_name": ""})
		}
		return records
	}

	repeated := newFakeForgejo(t)
	repeated.orgs = manyOrgs(120)
	repeated.orgsDuplicateIDs = true
	if got := observe(t, repeated, forgeconnection.ObserveInput{OrganizationSlug: "org-0000"}); got.ResultCode != forgeconnection.CheckPaginationIncomplete {
		t.Fatalf("repeated organization pages result = %s", got.ResultCode)
	}

	invalidNeighbor := newFakeForgejo(t)
	invalidNeighbor.orgs = []map[string]any{
		{"id": 8, "name": "other-org", "full_name": "Bad\u0001Name"},
		{"id": 7, "name": "fixture-org", "full_name": "Fixture Organization"},
	}
	if got := observe(t, invalidNeighbor, forgeconnection.ObserveInput{}); got.ResultCode != forgeconnection.CheckInvalidResponse {
		t.Fatalf("invalid neighbor organization result = %s", got.ResultCode)
	}
}

func TestObserveClassifiesHTTPFailures(t *testing.T) {
	cases := []struct {
		name string
		set  func(*fakeForgejo)
		want forgeconnection.CheckResultCode
	}{
		{name: "401", set: func(f *fakeForgejo) { f.userStatus = 401 }, want: forgeconnection.CheckAuthenticationFailed},
		{name: "403", set: func(f *fakeForgejo) { f.userStatus = 403 }, want: forgeconnection.CheckAuthorizationFailed},
		{name: "429", set: func(f *fakeForgejo) { f.userStatus = 429 }, want: forgeconnection.CheckUnavailable},
		{name: "500", set: func(f *fakeForgejo) { f.userStatus = 500 }, want: forgeconnection.CheckUnavailable},
		{name: "redirect", set: func(f *fakeForgejo) { f.userStatus = 302 }, want: forgeconnection.CheckInvalidResponse},
		{name: "repos 404 mid-check", set: func(f *fakeForgejo) { f.reposStatus = 404 }, want: forgeconnection.CheckOrganizationUnavailable},
		{name: "masked private 404", set: func(f *fakeForgejo) { f.repoByID = map[int64]map[string]any{} }, want: forgeconnection.CheckAuthorizationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeForgejo(t)
			tc.set(fake)
			if got := observe(t, fake, forgeconnection.ObserveInput{}); got.ResultCode != tc.want {
				t.Fatalf("result = %s, want %s", got.ResultCode, tc.want)
			}
		})
	}
}

func TestObserveEnforcesPaginationProtocol(t *testing.T) {
	manyRepos := func(count int) []map[string]any {
		records := make([]map[string]any, 0, count)
		for i := range count {
			records = append(records, repoRecord(int64(1000+i), "fixture-org", fmt.Sprintf("repo-%04d", i), "main", false))
		}
		return records
	}

	drifting := newFakeForgejo(t)
	drifting.repos = manyRepos(120)
	drifting.totalDrift = true
	if got := observe(t, drifting, forgeconnection.ObserveInput{}); got.ResultCode != forgeconnection.CheckPaginationIncomplete {
		t.Fatalf("drifting total result = %s", got.ResultCode)
	}

	missingTotal := newFakeForgejo(t)
	missingTotal.dropTotal = true
	if got := observe(t, missingTotal, forgeconnection.ObserveInput{}); got.ResultCode != forgeconnection.CheckPaginationIncomplete {
		t.Fatalf("missing total result = %s", got.ResultCode)
	}

	duplicates := newFakeForgejo(t)
	duplicates.repos = manyRepos(120)
	duplicates.duplicateIDs = true
	if got := observe(t, duplicates, forgeconnection.ObserveInput{}); got.ResultCode != forgeconnection.CheckPaginationIncomplete {
		t.Fatalf("duplicate ids result = %s", got.ResultCode)
	}

	oversized := newFakeForgejo(t)
	oversized.repos = manyRepos(1001)
	if got := observe(t, oversized, forgeconnection.ObserveInput{}); got.ResultCode != forgeconnection.CheckInventoryLimitExceeded {
		t.Fatalf("oversized inventory result = %s", got.ResultCode)
	}

	// An advertised total over the limit rejects before any further pages.
	if len(oversized.requests) > 4 {
		t.Fatalf("oversized inventory kept reading pages: %v", oversized.requests)
	}
}

// TestBudgetReaderClampsToRemainingAllowance proves the cumulative body
// budget is hard: reads are clamped to the remaining allowance, the first
// byte past the cap fails an integrated io.ReadAll, and an exhausted
// budget rejects new requests before any network activity.
func TestBudgetReaderClampsToRemainingAllowance(t *testing.T) {
	budget := &bodyBudget{}
	budget.remaining.Store(10)
	reader := &budgetReader{inner: io.NopCloser(strings.NewReader("0123456789ABCDEF")), budget: budget}
	buffer := make([]byte, 64)
	read, err := reader.Read(buffer)
	if err != nil || read != 10 || string(buffer[:read]) != "0123456789" {
		t.Fatalf("clamped read = %d err=%v, want exactly the 10-byte allowance", read, err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, errBodyBudgetExhausted) {
		t.Fatalf("past-limit read error = %v", err)
	}

	transport := &budgetTransport{inner: refusingTransport{t: t}, budget: budget}
	request := httptest.NewRequest(http.MethodGet, "http://forge.example.test/", nil)
	if _, err := transport.RoundTrip(request); !errors.Is(err, errBodyBudgetExhausted) {
		t.Fatalf("exhausted-transport error = %v", err)
	}
}

// TestBudgetReaderExactLimitBodySucceeds pins the inclusive-cap semantics:
// a body ending exactly at the remaining allowance reads completely under
// io.ReadAll (EOF, not exhaustion), and only a subsequent request is
// rejected because no allowance remains.
func TestBudgetReaderExactLimitBodySucceeds(t *testing.T) {
	budget := &bodyBudget{}
	budget.remaining.Store(10)
	reader := &budgetReader{inner: io.NopCloser(strings.NewReader("0123456789")), budget: budget}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "0123456789" {
		t.Fatalf("exact-limit body = %q err=%v, want full body and EOF", body, err)
	}

	transport := &budgetTransport{inner: refusingTransport{t: t}, budget: budget}
	request := httptest.NewRequest(http.MethodGet, "http://forge.example.test/", nil)
	if _, err := transport.RoundTrip(request); !errors.Is(err, errBodyBudgetExhausted) {
		t.Fatalf("exhausted-transport error = %v", err)
	}
}

// refusingTransport fails the test if any request is issued through it.
type refusingTransport struct{ t *testing.T }

func (r refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	r.t.Error("request issued despite exhausted budget")
	return nil, errors.New("unexpected request")
}

func TestObserveTransportFailureIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	baseURL := server.URL
	server.Close()
	observation := NewAdapter(nil).Observe(context.Background(), forgeconnection.ObserveInput{
		BaseURL:          baseURL,
		OrganizationSlug: "fixture-org",
		PAT:              []byte("fictional-service-pat"),
	})
	if observation.ResultCode != forgeconnection.CheckUnavailable {
		t.Fatalf("result = %s", observation.ResultCode)
	}
}
