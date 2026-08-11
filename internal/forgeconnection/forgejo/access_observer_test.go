package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

// fakeShadowForgejo serves the read-only endpoints of the shadow snapshot
// and records every request so tests can prove no write endpoint and no
// skipped listing is touched.
type fakeShadowForgejo struct {
	t *testing.T

	mu        sync.Mutex
	requests  []string
	protocols []string
	overTLS   []bool

	user       map[string]any
	userStatus int

	org          map[string]any
	orgStatus    int
	orgOversized bool

	orgRepos          []map[string]any
	orgReposStatus    int
	orgMembers        []map[string]any
	orgMembersStatus  int
	orgMembersRawBody []byte
	teams             []map[string]any

	// perPage forces a smaller server-side page length per listing kind
	// ("org-repos", "org-members", "org-teams", "team-repos",
	// "team-members", "collaborators"); zero uses the client limit.
	perPage map[string]int
	// paddingBytes injects one large unknown member into the first record
	// of every listing page, inflating each response toward the 1 MiB
	// per-response cap without touching any validated field.
	paddingBytes int

	teamRepos   map[string][]map[string]any
	teamMembers map[string][]map[string]any

	collaborators map[string][]map[string]any // owner/name -> users

	usersByName map[string]map[string]any
	userLookup  map[string]int // status override per username

	permissions      map[string]map[string]any // owner/name/username -> payload
	permissionStatus map[string]int

	memberTotalOverride  int64
	memberTotalDrift     bool
	duplicateMemberPages bool
}

func userRecord(id int64, login string) map[string]any {
	return map[string]any{"id": id, "login": login}
}

func newFakeShadowForgejo(t *testing.T) *fakeShadowForgejo {
	return &fakeShadowForgejo{
		t:    t,
		user: map[string]any{"id": 42, "login": "svc-shadow", "is_admin": false},
		org:  map[string]any{"id": 7, "name": "fixture-org", "full_name": "Fixture Organization"},
		orgRepos: []map[string]any{
			repoRecord(100, "fixture-org", "alpha", "main", true),
			repoRecord(101, "fixture-org", "beta", "main", true),
		},
		orgMembers: []map[string]any{
			userRecord(77, "admin-user"),
			userRecord(79, "uninvolved-user"),
		},
		teams: []map[string]any{{"id": 5}, {"id": 6}},
		teamRepos: map[string][]map[string]any{
			"5": {repoRecord(100, "fixture-org", "alpha", "main", true)},
			"6": {repoRecord(900, "fixture-org", "unbound", "main", true)},
		},
		teamMembers: map[string][]map[string]any{
			"5": {userRecord(77, "admin-user")},
			"6": {userRecord(79, "uninvolved-user")},
		},
		collaborators: map[string][]map[string]any{
			"fixture-org/alpha": {userRecord(78, "dev-user")},
			"fixture-org/beta":  {},
		},
		usersByName: map[string]map[string]any{
			"dev-user": userRecord(78, "dev-user"),
		},
		userLookup: map[string]int{},
		permissions: map[string]map[string]any{
			"fixture-org/alpha/admin-user": {"permission": "read", "role_name": "ignored", "user": userRecord(77, "admin-user")},
			"fixture-org/beta/admin-user":  {"permission": "none", "user": userRecord(77, "admin-user")},
			"fixture-org/alpha/dev-user":   {"permission": "write", "user": userRecord(78, "dev-user")},
			"fixture-org/beta/dev-user":    {"permission": "read", "user": userRecord(78, "dev-user")},
		},
		permissionStatus: map[string]int{},
		perPage:          map[string]int{},
	}
}

func (f *fakeShadowForgejo) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.protocols = append(f.protocols, r.Proto)
		f.overTLS = append(f.overTLS, r.TLS != nil)
		f.mu.Unlock()
		if r.Method != http.MethodGet {
			f.t.Errorf("non-GET request during shadow snapshot: %s %s", r.Method, r.URL.Path)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/api/v1")
		switch {
		case path == "/user":
			f.writeObject(w, f.userStatus, f.user)
		case path == "/orgs/fixture-org":
			if f.orgOversized {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"id":7,"name":"`))
				_, _ = w.Write(bytes.Repeat([]byte("a"), 1<<20))
				_, _ = w.Write([]byte(`","full_name":""}`))
				return
			}
			f.writeObject(w, f.orgStatus, f.org)
		case path == "/orgs/fixture-org/repos":
			f.writeShadowPage(w, r, f.orgRepos, f.orgReposStatus, 0, false, false, f.perPage["org-repos"])
		case path == "/orgs/fixture-org/members":
			if len(f.orgMembersRawBody) > 0 {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Total-Count", "1")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(f.orgMembersRawBody)
				return
			}
			f.writeShadowPage(w, r, f.orgMembers, f.orgMembersStatus, f.memberTotalOverride, f.memberTotalDrift, f.duplicateMemberPages, f.perPage["org-members"])
		case path == "/orgs/fixture-org/teams":
			f.writeShadowPage(w, r, f.teams, 0, 0, false, false, f.perPage["org-teams"])
		case strings.HasPrefix(path, "/teams/") && strings.HasSuffix(path, "/repos"):
			teamID := strings.TrimSuffix(strings.TrimPrefix(path, "/teams/"), "/repos")
			f.writeShadowPage(w, r, f.teamRepos[teamID], 0, 0, false, false, f.perPage["team-repos"])
		case strings.HasPrefix(path, "/teams/") && strings.HasSuffix(path, "/members"):
			teamID := strings.TrimSuffix(strings.TrimPrefix(path, "/teams/"), "/members")
			f.writeShadowPage(w, r, f.teamMembers[teamID], 0, 0, false, false, f.perPage["team-members"])
		case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/collaborators"):
			key := strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"), "/collaborators")
			collaborators, known := f.collaborators[key]
			if !known {
				f.writeObject(w, http.StatusNotFound, map[string]any{"message": "not found"})
				return
			}
			f.writeShadowPage(w, r, collaborators, 0, 0, false, false, f.perPage["collaborators"])
		case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/permission"):
			key := strings.TrimPrefix(path, "/repos/")
			key = strings.TrimSuffix(key, "/permission")
			key = strings.Replace(key, "/collaborators/", "/", 1)
			if status := f.permissionStatus[key]; status != 0 {
				f.writeObject(w, status, map[string]any{"message": "status"})
				return
			}
			payload, known := f.permissions[key]
			if !known {
				f.writeObject(w, http.StatusNotFound, map[string]any{"message": "not found"})
				return
			}
			f.writeObject(w, 0, payload)
		case strings.HasPrefix(path, "/users/"):
			username := strings.TrimPrefix(path, "/users/")
			if status := f.userLookup[username]; status != 0 {
				f.writeObject(w, status, map[string]any{"message": "status"})
				return
			}
			payload, known := f.usersByName[username]
			if !known {
				f.writeObject(w, http.StatusNotFound, map[string]any{"message": "not found"})
				return
			}
			f.writeObject(w, 0, payload)
		default:
			f.t.Errorf("unexpected shadow request path %s", r.URL.Path)
			f.writeObject(w, http.StatusNotFound, map[string]any{"message": "not found"})
		}
	})
}

func (f *fakeShadowForgejo) writeObject(w http.ResponseWriter, status int, payload any) {
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (f *fakeShadowForgejo) writeShadowPage(
	w http.ResponseWriter,
	r *http.Request,
	items []map[string]any,
	status int,
	totalOverride int64,
	totalDrift bool,
	duplicatePages bool,
	perPage int,
) {
	if status != 0 {
		f.writeObject(w, status, map[string]any{"message": "status"})
		return
	}
	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit < 1 {
		limit = 50
	}
	if perPage > 0 && perPage < limit {
		limit = perPage
	}
	total := int64(len(items))
	if totalOverride != 0 {
		total = totalOverride
	}
	if totalDrift {
		total += int64(page) - 1
	}
	start := (page - 1) * limit
	if duplicatePages {
		start = 0
	}
	end := min(start+limit, len(items))
	if start > len(items) {
		start, end = 0, 0
	}
	pageItems := items[start:end]
	if pageItems == nil {
		pageItems = []map[string]any{}
	}
	if f.paddingBytes > 0 && len(pageItems) > 0 {
		padded := make([]map[string]any, len(pageItems))
		copy(padded, pageItems)
		first := make(map[string]any, len(padded[0])+1)
		maps.Copy(first, padded[0])
		first["padding"] = strings.Repeat("a", f.paddingBytes)
		padded[0] = first
		pageItems = padded
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Total-Count", strconv.FormatInt(total, 10))
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(pageItems)
}

func shadowInput(serverURL string) forgeconnection.AccessObserveInput {
	return forgeconnection.AccessObserveInput{
		BaseURL:                   serverURL,
		OrganizationSlug:          "fixture-org",
		PAT:                       []byte("fictional-shadow-pat"),
		BoundServiceUserRemoteID:  "42",
		BoundOrganizationRemoteID: "7",
		Identities: []forgeconnection.AccessShadowIdentity{
			{IdentityID: 21, RemoteUserID: "77", UsernameAtLink: "admin-user"},
			{IdentityID: 22, RemoteUserID: "78", UsernameAtLink: "dev-user"},
		},
		Bindings: []forgeconnection.AccessShadowBinding{
			{RepositoryID: 11, RemoteRepositoryID: "100"},
			{RepositoryID: 12, RemoteRepositoryID: "101"},
		},
	}
}

func observeShadow(t *testing.T, fake *fakeShadowForgejo, mutate func(*forgeconnection.AccessObserveInput)) forgeconnection.AccessObservation {
	t.Helper()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	input := shadowInput(server.URL)
	if mutate != nil {
		mutate(&input)
	}
	return NewAccessObserver(http.DefaultTransport).ObserveAccess(context.Background(), input)
}

func pairReasons(observation forgeconnection.AccessObservation) map[[2]int64]forgeconnection.AccessObservationReason {
	reasons := make(map[[2]int64]forgeconnection.AccessObservationReason, len(observation.Pairs))
	for _, pair := range observation.Pairs {
		reasons[[2]int64{pair.IdentityID, pair.RepositoryID}] = pair.Reason
	}
	return reasons
}

func (f *fakeShadowForgejo) requestPaths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func TestAccessObserverClassifiesCompleteSnapshot(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	observation := observeShadow(t, fake, nil)
	if observation.ResultCode != forgeconnection.AccessSyncComplete {
		t.Fatalf("result = %v", observation.ResultCode)
	}
	reasons := pairReasons(observation)
	expected := map[[2]int64]forgeconnection.AccessObservationReason{
		{21, 11}: forgeconnection.AccessReasonTeamAccess,
		{21, 12}: forgeconnection.AccessReasonNoExplicitAccessNone,
		{22, 11}: forgeconnection.AccessReasonDirectCollaborator,
		{22, 12}: forgeconnection.AccessReasonVisibilitySourceUnproven,
	}
	if len(reasons) != len(expected) {
		t.Fatalf("pairs = %v", observation.Pairs)
	}
	for key, want := range expected {
		if reasons[key] != want {
			t.Fatalf("pair %v = %v, want %v", key, reasons[key], want)
		}
	}

	requests := fake.requestPaths()
	// user + org + org repos + org members + org teams + 2 team repos +
	// 1 intersecting team members + 2 collaborator listings + 4 permission
	// reads = 14. No fallback lookup: both identities resolve from the graph.
	if len(requests) != 14 || observation.RequestCount != 14 {
		t.Fatalf("requests = %d (reported %d): %v", len(requests), observation.RequestCount, requests)
	}
	for _, request := range requests {
		if request == "GET /api/v1/teams/6/members" {
			t.Fatal("members were read for a team that intersects no bound repository")
		}
	}
	teamReposIndex, teamMembersIndex := -1, -1
	for i, request := range requests {
		if request == "GET /api/v1/teams/5/repos" {
			teamReposIndex = i
		}
		if request == "GET /api/v1/teams/5/members" {
			teamMembersIndex = i
		}
	}
	if teamReposIndex == -1 || teamMembersIndex == -1 || teamMembersIndex < teamReposIndex {
		t.Fatalf("team repositories must be read before team members: %v", requests)
	}
}

func TestAccessObserverIdentityFallback(t *testing.T) {
	t.Run("resolves current login by immutable id", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		// The dev identity is absent from the graph; the fallback resolves a
		// renamed current login whose id still matches.
		fake.collaborators["fixture-org/alpha"] = nil
		fake.usersByName["dev-user"] = userRecord(78, "dev-user-renamed")
		fake.permissions["fixture-org/alpha/dev-user-renamed"] = map[string]any{"permission": "none", "user": userRecord(78, "dev-user-renamed")}
		fake.permissions["fixture-org/beta/dev-user-renamed"] = map[string]any{"permission": "none", "user": userRecord(78, "dev-user-renamed")}
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncComplete {
			t.Fatalf("result = %v", observation.ResultCode)
		}
		reasons := pairReasons(observation)
		if reasons[[2]int64{22, 11}] != forgeconnection.AccessReasonNoExplicitAccessNone {
			t.Fatalf("renamed identity pair = %v", reasons[[2]int64{22, 11}])
		}
	})
	t.Run("404 leaves only that identity unresolved", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.collaborators["fixture-org/alpha"] = nil
		delete(fake.usersByName, "dev-user")
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncComplete {
			t.Fatalf("result = %v", observation.ResultCode)
		}
		reasons := pairReasons(observation)
		if reasons[[2]int64{22, 11}] != forgeconnection.AccessReasonIdentityUnresolved ||
			reasons[[2]int64{22, 12}] != forgeconnection.AccessReasonIdentityUnresolved {
			t.Fatalf("reasons = %v", reasons)
		}
		if reasons[[2]int64{21, 11}] != forgeconnection.AccessReasonTeamAccess {
			t.Fatalf("unaffected identity = %v", reasons[[2]int64{21, 11}])
		}
		for _, request := range fake.requestPaths() {
			if strings.Contains(request, "/collaborators/dev-user/permission") {
				t.Fatal("permission was requested for an unresolved identity")
			}
		}
	})
	t.Run("id mismatch leaves the identity unresolved", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.collaborators["fixture-org/alpha"] = nil
		fake.usersByName["dev-user"] = userRecord(999, "dev-user")
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncComplete {
			t.Fatalf("result = %v", observation.ResultCode)
		}
		if pairReasons(observation)[[2]int64{22, 12}] != forgeconnection.AccessReasonIdentityUnresolved {
			t.Fatalf("reasons = %v", pairReasons(observation))
		}
	})
	t.Run("other fallback failures are systemic", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.collaborators["fixture-org/alpha"] = nil
		fake.userLookup["dev-user"] = http.StatusInternalServerError
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncUnavailable || len(observation.Pairs) != 0 {
			t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
		}
	})
}

func TestAccessObserverTeamOnlyRepositoryIsUnavailable(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	// Bound repository 101 leaves the top-level organization listing but a
	// team still lists it. A team-only mention never establishes
	// availability in the credential-visible inventory.
	fake.orgRepos = fake.orgRepos[:1]
	fake.teamRepos["5"] = append(fake.teamRepos["5"], repoRecord(101, "fixture-org", "beta", "main", true))
	observation := observeShadow(t, fake, nil)
	if observation.ResultCode != forgeconnection.AccessSyncComplete {
		t.Fatalf("result = %v", observation.ResultCode)
	}
	reasons := pairReasons(observation)
	if reasons[[2]int64{21, 12}] != forgeconnection.AccessReasonRepositoryUnavailable ||
		reasons[[2]int64{22, 12}] != forgeconnection.AccessReasonRepositoryUnavailable {
		t.Fatalf("team-only repository pairs = %v", reasons)
	}
	if reasons[[2]int64{21, 11}] != forgeconnection.AccessReasonTeamAccess {
		t.Fatalf("unrelated repository was affected: %v", reasons)
	}
	for _, request := range fake.requestPaths() {
		if strings.Contains(request, "/repos/fixture-org/beta") {
			t.Fatalf("team-only repository was requested: %s", request)
		}
	}
}

func TestAccessObserverConflictingRepositoryFieldsFailTheGraph(t *testing.T) {
	cases := []struct {
		name   string
		record map[string]any
	}{
		{name: "conflicting visibility", record: repoRecord(101, "fixture-org", "beta", "main", false)},
		{name: "conflicting name", record: repoRecord(101, "fixture-org", "beta-renamed", "main", true)},
		// A second immutable id at a bound repository's exact locator could
		// answer the locator-addressed collaborator and permission reads
		// and be published as the bound id's evidence.
		{name: "second id at the same locator", record: repoRecord(999, "fixture-org", "beta", "main", true)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			// The org listing carries beta as private=true on main; a team
			// listing disagreeing on identity or visibility fails the graph.
			fake.teamRepos["6"] = []map[string]any{tc.record}
			observation := observeShadow(t, fake, nil)
			if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse || len(observation.Pairs) != 0 {
				t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
			}
		})
	}
	t.Run("default branch differences are tolerated", func(t *testing.T) {
		// The default branch is mutable and excluded from conflict
		// equality: a branch rename between listings must never
		// invalidate access evidence.
		fake := newFakeShadowForgejo(t)
		fake.teamRepos["6"] = []map[string]any{repoRecord(101, "fixture-org", "beta", "renamed-main", true)}
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncComplete {
			t.Fatalf("result = %v", observation.ResultCode)
		}
		if pairReasons(observation)[[2]int64{21, 12}] != forgeconnection.AccessReasonNoExplicitAccessNone {
			t.Fatalf("reasons = %v", pairReasons(observation))
		}
	})
}

// TestAccessObserverOneWireConnectionPerRequest is the transport-retry
// regression: net/http retries an idempotent GET transparently only on a
// reused keep-alive connection, so proving every counted request rides its
// own fresh connection proves the retry path is unreachable and the counted
// budget bounds the wire exactly.
func TestAccessObserverOneWireConnectionPerRequest(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	server := httptest.NewUnstartedServer(fake.handler())
	var connections atomic.Int64
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()

	observation := NewAccessObserver(http.DefaultTransport).ObserveAccess(context.Background(), shadowInput(server.URL))
	if observation.ResultCode != forgeconnection.AccessSyncComplete {
		t.Fatalf("result = %v", observation.ResultCode)
	}
	if observation.RequestCount != 14 || connections.Load() != 14 {
		t.Fatalf("requests = %d, wire connections = %d; want 14 of each", observation.RequestCount, connections.Load())
	}
}

// buildFormulaScaleFixture reshapes the fake into the constructive request
// formula's worst-case listing shape (T=8 teams over four forced pages of
// the top-level listings and two forced pages of every nested listing, R=8
// bound repositories) with identityCount linked identities that resolve
// only through the username-at-link fallback.
func buildFormulaScaleFixture(
	fake *fakeShadowForgejo,
	identityCount int,
) ([]forgeconnection.AccessShadowIdentity, []forgeconnection.AccessShadowBinding) {
	boundNames := make([]string, 8)
	orgRepos := make([]map[string]any, 0, 160)
	for i := range 8 {
		boundNames[i] = fmt.Sprintf("bound-%d", i)
		orgRepos = append(orgRepos, repoRecord(int64(100+i), "fixture-org", boundNames[i], "main", true))
	}
	for i := range 152 {
		orgRepos = append(orgRepos, repoRecord(int64(1000+i), "fixture-org", fmt.Sprintf("filler-%d", i), "main", true))
	}
	fake.orgRepos = orgRepos // 160 records: four 50-record pages
	members := make([]map[string]any, 0, 160)
	for i := range 160 {
		members = append(members, userRecord(int64(5000+i), fmt.Sprintf("member-%d", i)))
	}
	fake.orgMembers = members // 160 records: four pages
	fake.teams = nil
	fake.teamRepos = map[string][]map[string]any{}
	fake.teamMembers = map[string][]map[string]any{}
	fake.collaborators = map[string][]map[string]any{}
	fake.permissions = map[string]map[string]any{}
	fake.usersByName = map[string]map[string]any{}
	for team := range 8 {
		teamID := int64(30 + team)
		key := strconv.FormatInt(teamID, 10)
		fake.teams = append(fake.teams, map[string]any{"id": teamID})
		// Two records over two forced pages; every team intersects a bound
		// repository so all eight member listings are read.
		fake.teamRepos[key] = []map[string]any{
			repoRecord(int64(100+team), "fixture-org", boundNames[team], "main", true),
			repoRecord(int64(2000+team), "fixture-org", fmt.Sprintf("team-extra-%d", team), "main", true),
		}
		fake.teamMembers[key] = []map[string]any{
			userRecord(int64(6000+2*team), fmt.Sprintf("tm-%d-a", team)),
			userRecord(int64(6001+2*team), fmt.Sprintf("tm-%d-b", team)),
		}
	}
	identities := make([]forgeconnection.AccessShadowIdentity, 0, identityCount)
	for i := range identityCount {
		// No linked identity appears anywhere in the graph, so every one
		// resolves through the username-at-link fallback.
		login := fmt.Sprintf("linked-%d", i)
		fake.usersByName[login] = userRecord(int64(70+i), login)
		identities = append(identities, forgeconnection.AccessShadowIdentity{
			IdentityID:     int64(21 + i),
			RemoteUserID:   strconv.FormatInt(int64(70+i), 10),
			UsernameAtLink: login,
		})
	}
	bindings := make([]forgeconnection.AccessShadowBinding, 0, 8)
	for i := range 8 {
		bindings = append(bindings, forgeconnection.AccessShadowBinding{
			RepositoryID:       int64(11 + i),
			RemoteRepositoryID: strconv.FormatInt(int64(100+i), 10),
		})
		repoKey := "fixture-org/" + boundNames[i]
		fake.collaborators[repoKey] = []map[string]any{
			userRecord(int64(7000+2*i), fmt.Sprintf("collab-%d-a", i)),
			userRecord(int64(7001+2*i), fmt.Sprintf("collab-%d-b", i)),
		}
		for j := range identityCount {
			login := fmt.Sprintf("linked-%d", j)
			fake.permissions[repoKey+"/"+login] = map[string]any{
				"permission": "none",
				"user":       userRecord(int64(70+j), login),
			}
		}
	}
	fake.perPage = map[string]int{"org-teams": 2, "team-repos": 1, "team-members": 1, "collaborators": 1}
	return identities, bindings
}

// TestAccessObserverCompletesAtTheRequestFormulaMaximum drives the
// constructive worst case 2 + 12 + 2T + 2T + 2R + I + I*R at T=8, R=8, I=3:
// exactly 89 requests, inside the 96 budget.
func TestAccessObserverCompletesAtTheRequestFormulaMaximum(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	identities, bindings := buildFormulaScaleFixture(fake, 3)

	observation := observeShadow(t, fake, func(input *forgeconnection.AccessObserveInput) {
		input.Identities = identities
		input.Bindings = bindings
	})
	if observation.ResultCode != forgeconnection.AccessSyncComplete {
		t.Fatalf("result = %v", observation.ResultCode)
	}
	// 1 user + 1 org + 4 org repos + 4 members + 4 teams + 16 team repos +
	// 16 team members + 16 collaborators + 3 fallbacks + 24 permissions.
	if observation.RequestCount != 89 {
		t.Fatalf("requests = %d, want the 89-request maximum", observation.RequestCount)
	}
	if observation.RequestCount > forgeconnection.AccessSyncRequestLimit {
		t.Fatalf("maximum %d exceeds the %d budget", observation.RequestCount, forgeconnection.AccessSyncRequestLimit)
	}
	if len(observation.Pairs) != 24 {
		t.Fatalf("pairs = %d", len(observation.Pairs))
	}
	for _, pair := range observation.Pairs {
		if pair.Reason != forgeconnection.AccessReasonNoExplicitAccessNone {
			t.Fatalf("pair %d/%d = %v", pair.IdentityID, pair.RepositoryID, pair.Reason)
		}
	}
}

// TestAccessObserverForcesHTTP1OverTLS is the HTTP/2 regression: against a
// TLS server that offers h2 via ALPN (and speaks it to an unmodified
// client), the observer's configured client must negotiate HTTP/1.1 only,
// keeping the HTTP/2 transport's internal stream retries unreachable.
func TestAccessObserverForcesHTTP1OverTLS(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	server := httptest.NewUnstartedServer(fake.handler())
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	base, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("test client transport is not *http.Transport")
	}

	observation := NewAccessObserver(base).ObserveAccess(context.Background(), shadowInput(server.URL))
	if observation.ResultCode != forgeconnection.AccessSyncComplete || observation.RequestCount != 14 {
		t.Fatalf("result = %v requests = %d", observation.ResultCode, observation.RequestCount)
	}

	// Control: the same base transport, unmodified, negotiates HTTP/2 with
	// this server — proving the observer's HTTP/1.1 came from its own
	// configuration, not from the server lacking h2.
	response, err := server.Client().Get(server.URL + "/api/v1/user")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.protocols) != 15 {
		t.Fatalf("server saw %d requests, want 15", len(fake.protocols))
	}
	for i, protocol := range fake.protocols[:14] {
		if protocol != "HTTP/1.1" {
			t.Fatalf("observer request %d used %q, want HTTP/1.1", i, protocol)
		}
		if !fake.overTLS[i] {
			t.Fatalf("observer request %d did not use TLS", i)
		}
	}
	if fake.protocols[14] != "HTTP/2.0" {
		t.Fatalf("control request used %q; the server does not prove h2 was on offer", fake.protocols[14])
	}
}

// TestAccessObserverSystemicStatusMatrix pins the fallback and permission
// endpoints to the shared systemic matrix for every non-404 status class:
// systemic classification and zero publication.
func TestAccessObserverSystemicStatusMatrix(t *testing.T) {
	statuses := []struct {
		status int
		want   forgeconnection.AccessSyncResultCode
	}{
		{status: http.StatusUnauthorized, want: forgeconnection.AccessSyncAuthenticationFailed},
		{status: http.StatusForbidden, want: forgeconnection.AccessSyncAuthorizationFailed},
		{status: http.StatusTooManyRequests, want: forgeconnection.AccessSyncUnavailable},
		{status: http.StatusFound, want: forgeconnection.AccessSyncInvalidResponse},
		{status: http.StatusBadGateway, want: forgeconnection.AccessSyncUnavailable},
	}
	for _, tc := range statuses {
		t.Run(fmt.Sprintf("identity fallback %d", tc.status), func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			// Empty alpha collaborators force the dev identity through the
			// username-at-link fallback.
			fake.collaborators["fixture-org/alpha"] = nil
			fake.userLookup["dev-user"] = tc.status
			observation := observeShadow(t, fake, nil)
			if observation.ResultCode != tc.want || len(observation.Pairs) != 0 {
				t.Fatalf("result = %v pairs = %d, want %v", observation.ResultCode, len(observation.Pairs), tc.want)
			}
		})
		t.Run(fmt.Sprintf("permission %d", tc.status), func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			fake.permissionStatus["fixture-org/beta/admin-user"] = tc.status
			observation := observeShadow(t, fake, nil)
			if observation.ResultCode != tc.want || len(observation.Pairs) != 0 {
				t.Fatalf("result = %v pairs = %d, want %v", observation.ResultCode, len(observation.Pairs), tc.want)
			}
		})
	}
}

func TestAccessObserverTransportFailuresAreUnavailable(t *testing.T) {
	t.Run("connection refused", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		server := httptest.NewServer(fake.handler())
		input := shadowInput(server.URL)
		server.Close()
		observation := NewAccessObserver(http.DefaultTransport).ObserveAccess(context.Background(), input)
		if observation.ResultCode != forgeconnection.AccessSyncUnavailable || len(observation.Pairs) != 0 {
			t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
		}
	})
	t.Run("deadline already expired", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		server := httptest.NewServer(fake.handler())
		defer server.Close()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		observation := NewAccessObserver(http.DefaultTransport).ObserveAccess(ctx, shadowInput(server.URL))
		if observation.ResultCode != forgeconnection.AccessSyncUnavailable || len(observation.Pairs) != 0 {
			t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
		}
	})
}

func TestAccessObserverMalformedListingBodies(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{name: "malformed JSON", body: []byte(`[{"id":77,"login":`)},
		{name: "invalid UTF-8", body: []byte("\xff\xfe[]")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			fake.orgMembersRawBody = tc.body
			observation := observeShadow(t, fake, nil)
			if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse || len(observation.Pairs) != 0 {
				t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
			}
		})
	}
}

// TestAccessObserverPermissionValueClassification pins every permission
// value against pairs with and without an explicit edge.
func TestAccessObserverPermissionValueClassification(t *testing.T) {
	edgeless := [2]int64{21, 12} // admin-user on beta: no explicit edge
	withEdge := [2]int64{21, 11} // admin-user on alpha: team edge via team 5
	cases := []struct {
		name         string
		permission   string
		pair         [2]int64
		want         forgeconnection.AccessObservationReason
		permissionAt string
	}{
		{name: "none without edge", permission: "none", pair: edgeless, want: forgeconnection.AccessReasonNoExplicitAccessNone, permissionAt: "fixture-org/beta/admin-user"},
		{name: "read without edge", permission: "read", pair: edgeless, want: forgeconnection.AccessReasonVisibilitySourceUnproven, permissionAt: "fixture-org/beta/admin-user"},
		{name: "write without edge", permission: "write", pair: edgeless, want: forgeconnection.AccessReasonVisibilitySourceUnproven, permissionAt: "fixture-org/beta/admin-user"},
		{name: "admin without edge", permission: "admin", pair: edgeless, want: forgeconnection.AccessReasonVisibilitySourceUnproven, permissionAt: "fixture-org/beta/admin-user"},
		{name: "owner without edge", permission: "owner", pair: edgeless, want: forgeconnection.AccessReasonVisibilitySourceUnproven, permissionAt: "fixture-org/beta/admin-user"},
		{name: "unrecognized without edge", permission: "maintain", pair: edgeless, want: forgeconnection.AccessReasonPermissionUnrecognized, permissionAt: "fixture-org/beta/admin-user"},
		{name: "none with edge", permission: "none", pair: withEdge, want: forgeconnection.AccessReasonEvidenceInconsistent, permissionAt: "fixture-org/alpha/admin-user"},
		{name: "read with edge", permission: "read", pair: withEdge, want: forgeconnection.AccessReasonTeamAccess, permissionAt: "fixture-org/alpha/admin-user"},
		{name: "write with edge", permission: "write", pair: withEdge, want: forgeconnection.AccessReasonTeamAccess, permissionAt: "fixture-org/alpha/admin-user"},
		{name: "admin with edge", permission: "admin", pair: withEdge, want: forgeconnection.AccessReasonTeamAccess, permissionAt: "fixture-org/alpha/admin-user"},
		{name: "owner with edge", permission: "owner", pair: withEdge, want: forgeconnection.AccessReasonTeamAccess, permissionAt: "fixture-org/alpha/admin-user"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			fake.permissions[tc.permissionAt] = map[string]any{"permission": tc.permission, "user": userRecord(77, "admin-user")}
			observation := observeShadow(t, fake, nil)
			if observation.ResultCode != forgeconnection.AccessSyncComplete {
				t.Fatalf("result = %v", observation.ResultCode)
			}
			if got := pairReasons(observation)[tc.pair]; got != tc.want {
				t.Fatalf("pair reason = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAccessObserverCumulativeBodyExhaustionIsSystemic pads every listing
// page toward the 1 MiB per-response cap so the 24 MiB cumulative budget
// runs out mid-run: systemic invalid_response, zero publication.
func TestAccessObserverCumulativeBodyExhaustionIsSystemic(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	identities, bindings := buildFormulaScaleFixture(fake, 3)
	fake.paddingBytes = 990_000
	observation := observeShadow(t, fake, func(input *forgeconnection.AccessObserveInput) {
		input.Identities = identities
		input.Bindings = bindings
	})
	if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse || len(observation.Pairs) != 0 {
		t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
	}
	if observation.RequestCount == 0 || observation.RequestCount >= 89 {
		t.Fatalf("budget exhaustion did not interrupt the run: %d requests", observation.RequestCount)
	}
	// The body-budget preflight runs outside the request counter, so the
	// pre-wire rejection never inflates the count: reported equals the
	// server-observed wire total exactly.
	if serverSeen := int64(len(fake.requestPaths())); observation.RequestCount != serverSeen {
		t.Fatalf("counted %d requests but the server saw %d", observation.RequestCount, serverSeen)
	}
}

// observeShadowWithLimit runs the observer through its package-private
// request-limit seam; production code always uses the approved budget.
func observeShadowWithLimit(
	t *testing.T,
	fake *fakeShadowForgejo,
	limit int64,
	mutate func(*forgeconnection.AccessObserveInput),
) forgeconnection.AccessObservation {
	t.Helper()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	input := shadowInput(server.URL)
	if mutate != nil {
		mutate(&input)
	}
	observer := NewAccessObserver(http.DefaultTransport)
	observer.requestLimit = limit
	return observer.ObserveAccess(context.Background(), input)
}

// TestAccessObserverScopeValidationRejectsBeforeProviderWork proves the
// observer validates the small-alpha scope itself: an over-limit scope
// fails closed with zero provider requests and zero publication.
func TestAccessObserverScopeValidationRejectsBeforeProviderWork(t *testing.T) {
	identity := func(i int64) forgeconnection.AccessShadowIdentity {
		return forgeconnection.AccessShadowIdentity{
			IdentityID:     i,
			RemoteUserID:   strconv.FormatInt(500+i, 10),
			UsernameAtLink: fmt.Sprintf("scope-user-%d", i),
		}
	}
	binding := func(i int64) forgeconnection.AccessShadowBinding {
		return forgeconnection.AccessShadowBinding{
			RepositoryID:       i,
			RemoteRepositoryID: strconv.FormatInt(700+i, 10),
		}
	}
	repeatIdentities := func(count int64) []forgeconnection.AccessShadowIdentity {
		identities := make([]forgeconnection.AccessShadowIdentity, 0, count)
		for i := range count {
			identities = append(identities, identity(i+1))
		}
		return identities
	}
	repeatBindings := func(count int64) []forgeconnection.AccessShadowBinding {
		bindings := make([]forgeconnection.AccessShadowBinding, 0, count)
		for i := range count {
			bindings = append(bindings, binding(i+1))
		}
		return bindings
	}
	cases := []struct {
		name   string
		mutate func(*forgeconnection.AccessObserveInput)
	}{
		{name: "eleven identities", mutate: func(input *forgeconnection.AccessObserveInput) {
			input.Identities = repeatIdentities(11)
			input.Bindings = repeatBindings(2)
		}},
		{name: "eleven bindings", mutate: func(input *forgeconnection.AccessObserveInput) {
			input.Identities = repeatIdentities(2)
			input.Bindings = repeatBindings(11)
		}},
		{name: "thirty pairs within per-side limits", mutate: func(input *forgeconnection.AccessObserveInput) {
			input.Identities = repeatIdentities(6)
			input.Bindings = repeatBindings(5)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			observation := observeShadow(t, fake, tc.mutate)
			if observation.ResultCode != forgeconnection.AccessSyncWorkLimitExceeded || len(observation.Pairs) != 0 {
				t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
			}
			if observation.RequestCount != 0 || len(fake.requestPaths()) != 0 {
				t.Fatalf("over-limit scope reached the provider: counted=%d server=%d",
					observation.RequestCount, len(fake.requestPaths()))
			}
		})
	}
}

// TestAccessObserverPhaseReservationFailsClosedBeforeResolution proves the
// resolution-phase preflight: with a valid scope whose worst-case fallback
// plus permission reservation cannot fit the remaining budget, the run
// fails closed after the shared graph and sends zero fallback and zero
// permission requests.
func TestAccessObserverPhaseReservationFailsClosedBeforeResolution(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	// Empty alpha collaborators leave the dev identity out of the graph, so
	// the phase needs 1 fallback + (2 resolvable x 2 visible) permissions =
	// 5 requests. The shared graph costs 10, so a 12-request budget leaves
	// only 2 remaining.
	fake.collaborators["fixture-org/alpha"] = []map[string]any{}
	observation := observeShadowWithLimit(t, fake, 12, nil)
	if observation.ResultCode != forgeconnection.AccessSyncWorkLimitExceeded || len(observation.Pairs) != 0 {
		t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
	}
	requests := fake.requestPaths()
	if len(requests) != 10 || observation.RequestCount != 10 {
		t.Fatalf("shared graph = %d requests (counted %d), want 10: %v", len(requests), observation.RequestCount, requests)
	}
	for _, request := range requests {
		if strings.Contains(request, "/api/v1/users/") || strings.Contains(request, "/permission") {
			t.Fatalf("resolution request escaped the failed reservation: %s", request)
		}
	}
}

// TestAccessObserverRequestLimitRejectsNextRequestBeforeWire proves the
// budget mechanism at a reduced seam limit on a fully valid scope: the
// first request past the limit is rejected before any network I/O, so the
// counted total equals the server-observed total exactly.
func TestAccessObserverRequestLimitRejectsNextRequestBeforeWire(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	observation := observeShadowWithLimit(t, fake, 5, nil)
	if observation.ResultCode != forgeconnection.AccessSyncWorkLimitExceeded || len(observation.Pairs) != 0 {
		t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
	}
	if observation.RequestCount != 5 || len(fake.requestPaths()) != 5 {
		t.Fatalf("counted=%d server=%d, want 5 of each", observation.RequestCount, len(fake.requestPaths()))
	}
}

// TestRequestCountingTransportRejectsRequest97PreWire exercises the
// production 96-request budget directly: the 97th request never reaches
// the wrapped transport and the count stays at exactly 96.
func TestRequestCountingTransportRejectsRequest97PreWire(t *testing.T) {
	stub := &stubRoundTripper{}
	requests := &requestBudget{limit: forgeconnection.AccessSyncRequestLimit}
	transport := &requestCountingTransport{inner: stub, requests: requests}
	request := httptest.NewRequest(http.MethodGet, "http://forge.example.test/", nil)
	for i := range int(forgeconnection.AccessSyncRequestLimit) {
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		response.Body.Close()
	}
	if _, err := transport.RoundTrip(request); !errors.Is(err, errAccessRequestExhausted) {
		t.Fatalf("request 97 error = %v, want errAccessRequestExhausted", err)
	}
	if stub.calls.Load() != forgeconnection.AccessSyncRequestLimit {
		t.Fatalf("wire requests = %d, want exactly %d", stub.calls.Load(), forgeconnection.AccessSyncRequestLimit)
	}
	if requests.used.Load() != forgeconnection.AccessSyncRequestLimit {
		t.Fatalf("counted requests = %d, want exactly %d", requests.used.Load(), forgeconnection.AccessSyncRequestLimit)
	}
}

type stubRoundTripper struct {
	calls atomic.Int64
}

func (s *stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{}}, nil
}

// TestAccessObserverLatePermissionFailureCreatesNoPartialEvidence proves
// request ordering cannot create partial evidence: a systemic failure on
// the final pair's permission read, after earlier permission requests
// succeeded on the wire, still publishes nothing.
func TestAccessObserverLatePermissionFailureCreatesNoPartialEvidence(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	// Deterministic pair order is identities then bindings ascending; the
	// last permission read is dev-user on beta.
	fake.permissionStatus["fixture-org/beta/dev-user"] = http.StatusInternalServerError
	observation := observeShadow(t, fake, nil)
	if observation.ResultCode != forgeconnection.AccessSyncUnavailable || len(observation.Pairs) != 0 {
		t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
	}
	earlierPermissions := 0
	for _, request := range fake.requestPaths() {
		if strings.HasSuffix(request, "/permission") && !strings.Contains(request, "beta/collaborators/dev-user") {
			earlierPermissions++
		}
	}
	if earlierPermissions != 3 {
		t.Fatalf("earlier permission requests = %d, want 3 before the systemic failure", earlierPermissions)
	}
}

func TestAccessObserverMissingBoundRepositoryIsPairScoped(t *testing.T) {
	fake := newFakeShadowForgejo(t)
	// Bound repository 101 vanishes from every listing.
	fake.orgRepos = fake.orgRepos[:1]
	observation := observeShadow(t, fake, nil)
	if observation.ResultCode != forgeconnection.AccessSyncComplete {
		t.Fatalf("result = %v", observation.ResultCode)
	}
	reasons := pairReasons(observation)
	if reasons[[2]int64{21, 12}] != forgeconnection.AccessReasonRepositoryUnavailable ||
		reasons[[2]int64{22, 12}] != forgeconnection.AccessReasonRepositoryUnavailable {
		t.Fatalf("reasons = %v", reasons)
	}
	if reasons[[2]int64{21, 11}] != forgeconnection.AccessReasonTeamAccess {
		t.Fatalf("unrelated repository was affected: %v", reasons)
	}
	for _, request := range fake.requestPaths() {
		if strings.Contains(request, "beta") {
			t.Fatalf("invisible bound repository was requested: %s", request)
		}
	}
}

func TestAccessObserverPairPermissionMatrix(t *testing.T) {
	t.Run("permission 404 is pair unavailable", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.permissionStatus["fixture-org/beta/admin-user"] = http.StatusNotFound
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncComplete {
			t.Fatalf("result = %v", observation.ResultCode)
		}
		if pairReasons(observation)[[2]int64{21, 12}] != forgeconnection.AccessReasonPermissionUnavailable {
			t.Fatalf("reasons = %v", pairReasons(observation))
		}
	})
	t.Run("unknown permission value is pair unknown", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.permissions["fixture-org/beta/admin-user"] = map[string]any{"permission": "maintain", "user": userRecord(77, "admin-user")}
		observation := observeShadow(t, fake, nil)
		if pairReasons(observation)[[2]int64{21, 12}] != forgeconnection.AccessReasonPermissionUnrecognized {
			t.Fatalf("reasons = %v", pairReasons(observation))
		}
	})
	t.Run("returned user mismatch is pair unknown", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.permissions["fixture-org/beta/admin-user"] = map[string]any{"permission": "none", "user": userRecord(999, "admin-user")}
		observation := observeShadow(t, fake, nil)
		if pairReasons(observation)[[2]int64{21, 12}] != forgeconnection.AccessReasonEvidenceInconsistent {
			t.Fatalf("reasons = %v", pairReasons(observation))
		}
	})
	t.Run("edge with permission none is pair unknown", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.permissions["fixture-org/alpha/admin-user"] = map[string]any{"permission": "none", "user": userRecord(77, "admin-user")}
		observation := observeShadow(t, fake, nil)
		if pairReasons(observation)[[2]int64{21, 11}] != forgeconnection.AccessReasonEvidenceInconsistent {
			t.Fatalf("reasons = %v", pairReasons(observation))
		}
	})
	t.Run("malformed permission payload is systemic", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.permissions["fixture-org/beta/admin-user"] = map[string]any{"permission": "read"}
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse || len(observation.Pairs) != 0 {
			t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
		}
	})
	t.Run("permission server failure is systemic", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.permissionStatus["fixture-org/beta/admin-user"] = http.StatusInternalServerError
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncUnavailable || len(observation.Pairs) != 0 {
			t.Fatalf("result = %v pairs = %d", observation.ResultCode, len(observation.Pairs))
		}
	})
}

func TestAccessObserverControlChecks(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*fakeShadowForgejo)
		want   forgeconnection.AccessSyncResultCode
	}{
		{
			name:   "site administrator service user",
			mutate: func(f *fakeShadowForgejo) { f.user["is_admin"] = true },
			want:   forgeconnection.AccessSyncServiceUserIsAdmin,
		},
		{
			name:   "changed service user",
			mutate: func(f *fakeShadowForgejo) { f.user["id"] = 43 },
			want:   forgeconnection.AccessSyncServiceUserChanged,
		},
		{
			name:   "changed organization identity",
			mutate: func(f *fakeShadowForgejo) { f.org["id"] = 8 },
			want:   forgeconnection.AccessSyncOrganizationChanged,
		},
		{
			// A 404 on the organization control read is masking, per the
			// systemic matrix; organization_changed needs an id mismatch.
			name:   "organization slug no longer resolves",
			mutate: func(f *fakeShadowForgejo) { f.orgStatus = http.StatusNotFound },
			want:   forgeconnection.AccessSyncInvalidResponse,
		},
		{
			name:   "authentication rejected",
			mutate: func(f *fakeShadowForgejo) { f.userStatus = http.StatusUnauthorized },
			want:   forgeconnection.AccessSyncAuthenticationFailed,
		},
		{
			name:   "authorization rejected on a shared listing",
			mutate: func(f *fakeShadowForgejo) { f.orgMembersStatus = http.StatusForbidden },
			want:   forgeconnection.AccessSyncAuthorizationFailed,
		},
		{
			name:   "rate limited",
			mutate: func(f *fakeShadowForgejo) { f.userStatus = http.StatusTooManyRequests },
			want:   forgeconnection.AccessSyncUnavailable,
		},
		{
			name:   "redirecting endpoint",
			mutate: func(f *fakeShadowForgejo) { f.userStatus = http.StatusFound },
			want:   forgeconnection.AccessSyncInvalidResponse,
		},
		{
			name:   "shared listing 404 masking",
			mutate: func(f *fakeShadowForgejo) { f.orgReposStatus = http.StatusNotFound },
			want:   forgeconnection.AccessSyncInvalidResponse,
		},
		{
			name:   "server failure on a shared listing",
			mutate: func(f *fakeShadowForgejo) { f.orgReposStatus = http.StatusInternalServerError },
			want:   forgeconnection.AccessSyncUnavailable,
		},
		{
			name:   "oversized response body",
			mutate: func(f *fakeShadowForgejo) { f.orgOversized = true },
			want:   forgeconnection.AccessSyncInvalidResponse,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeShadowForgejo(t)
			tc.mutate(fake)
			observation := observeShadow(t, fake, nil)
			if observation.ResultCode != tc.want || len(observation.Pairs) != 0 {
				t.Fatalf("result = %v pairs = %d, want %v", observation.ResultCode, len(observation.Pairs), tc.want)
			}
		})
	}
}

func TestAccessObserverSharedGraphProtocol(t *testing.T) {
	t.Run("team count beyond the limit fails closed", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.teams = nil
		for i := range 9 {
			fake.teams = append(fake.teams, map[string]any{"id": int64(100 + i)})
		}
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncWorkLimitExceeded {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
	t.Run("total beyond the record ceiling is incomplete", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.memberTotalOverride = 201
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncPaginationIncomplete {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
	t.Run("changed totals are invalid", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.orgMembers = nil
		for i := range 60 {
			fake.orgMembers = append(fake.orgMembers, userRecord(int64(1000+i), "member-"+strconv.Itoa(i)))
		}
		fake.memberTotalDrift = true
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
	t.Run("repeated ids are invalid", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.orgMembers = nil
		for i := range 60 {
			fake.orgMembers = append(fake.orgMembers, userRecord(int64(1000+i), "member-"+strconv.Itoa(i)))
		}
		fake.duplicateMemberPages = true
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
	t.Run("same login on different ids is invalid", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.orgMembers = []map[string]any{userRecord(77, "admin-user")}
		fake.teamMembers["5"] = []map[string]any{userRecord(770, "admin-user")}
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
	t.Run("same id with a conflicting login is invalid", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		fake.teamMembers["5"] = []map[string]any{userRecord(77, "renamed-mid-run")}
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
	t.Run("collaborator 404 on a visible repository is invalid masking", func(t *testing.T) {
		fake := newFakeShadowForgejo(t)
		delete(fake.collaborators, "fixture-org/beta")
		observation := observeShadow(t, fake, nil)
		if observation.ResultCode != forgeconnection.AccessSyncInvalidResponse {
			t.Fatalf("result = %v", observation.ResultCode)
		}
	})
}
