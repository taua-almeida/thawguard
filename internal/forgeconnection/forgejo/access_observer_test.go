package forgejo

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

// fakeShadowForgejo serves the read-only endpoints of the shadow snapshot
// and records every request so tests can prove no write endpoint and no
// skipped listing is touched.
type fakeShadowForgejo struct {
	t *testing.T

	mu       sync.Mutex
	requests []string

	user       map[string]any
	userStatus int

	org       map[string]any
	orgStatus int

	orgRepos         []map[string]any
	orgMembers       []map[string]any
	orgMembersStatus int
	teams            []map[string]any

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
	}
}

func (f *fakeShadowForgejo) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
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
			f.writeObject(w, f.orgStatus, f.org)
		case path == "/orgs/fixture-org/repos":
			f.writeShadowPage(w, r, f.orgRepos, 0, 0, false, false)
		case path == "/orgs/fixture-org/members":
			f.writeShadowPage(w, r, f.orgMembers, f.orgMembersStatus, f.memberTotalOverride, f.memberTotalDrift, f.duplicateMemberPages)
		case path == "/orgs/fixture-org/teams":
			f.writeShadowPage(w, r, f.teams, 0, 0, false, false)
		case strings.HasPrefix(path, "/teams/") && strings.HasSuffix(path, "/repos"):
			teamID := strings.TrimSuffix(strings.TrimPrefix(path, "/teams/"), "/repos")
			f.writeShadowPage(w, r, f.teamRepos[teamID], 0, 0, false, false)
		case strings.HasPrefix(path, "/teams/") && strings.HasSuffix(path, "/members"):
			teamID := strings.TrimSuffix(strings.TrimPrefix(path, "/teams/"), "/members")
			f.writeShadowPage(w, r, f.teamMembers[teamID], 0, 0, false, false)
		case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/collaborators"):
			key := strings.TrimSuffix(strings.TrimPrefix(path, "/repos/"), "/collaborators")
			collaborators, known := f.collaborators[key]
			if !known {
				f.writeObject(w, http.StatusNotFound, map[string]any{"message": "not found"})
				return
			}
			f.writeShadowPage(w, r, collaborators, 0, 0, false, false)
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
			name:   "organization slug no longer resolves",
			mutate: func(f *fakeShadowForgejo) { f.orgStatus = http.StatusNotFound },
			want:   forgeconnection.AccessSyncOrganizationChanged,
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
