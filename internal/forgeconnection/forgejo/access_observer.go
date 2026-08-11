package forgejo

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"sync/atomic"

	forgeclient "github.com/taua-almeida/thawguard/internal/forge/forgejo"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

// AccessObserver performs the read-only shadow-access snapshot for one
// reserved run. Every request is a plain GET under the snapshot's strict
// limits; the observer never calls a write endpoint, never follows a
// redirect, never retries, and never retains raw response data or remote
// identifiers in its report beyond the internal-id pair classifications.
type AccessObserver struct {
	transport http.RoundTripper
	// requestLimit is a package-private test seam; zero means the approved
	// production budget. Production code never sets it.
	requestLimit int64
}

func NewAccessObserver(transport http.RoundTripper) *AccessObserver {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &AccessObserver{transport: transport}
}

var _ forgeconnection.AccessShadowObserver = (*AccessObserver)(nil)

// Approved page ceilings. Top-level organization listings may read four
// pages of fifty records; each team's repositories and members and each
// bound repository's collaborators may read two.
const (
	accessTopLevelMaxPages   = 4
	accessTopLevelMaxRecords = 4 * pageLimit
	accessNestedMaxPages     = 2
	accessNestedMaxRecords   = 2 * pageLimit
	accessMaxTeams           = 8
)

// Approved small-alpha scope ceilings, validated by the observer
// independently of its caller: a scope beyond them fails closed before any
// provider work.
const (
	accessMaxIdentities   = 10
	accessMaxRepositories = 10
	accessMaxPairs        = 25
)

// Sentinels for shadow-specific protocol failures.
var (
	errAccessDuplicateRecord  = errors.New("listing repeated an immutable id")
	errAccessConflictingData  = errors.New("shared graph records conflict")
	errAccessInvalidRecord    = errors.New("shared graph record is invalid")
	errAccessTeamLimit        = errors.New("team count exceeds the approved limit")
	errAccessRequestExhausted = errors.New("request budget exhausted")
)

// ObserveAccess runs the snapshot sequence: verify the service user and
// bound organization, read the complete credential-visible shared graph,
// resolve every identity, request the effective permission for every
// resolvable pair, and classify every pair. Any shared-graph failure
// returns a systemic result with no pair classifications.
func (o *AccessObserver) ObserveAccess(ctx context.Context, input forgeconnection.AccessObserveInput) forgeconnection.AccessObservation {
	if o == nil || o.transport == nil {
		return forgeconnection.AccessObservation{ResultCode: forgeconnection.AccessSyncUnavailable}
	}
	budget := &bodyBudget{}
	budget.remaining.Store(maxCumulativeBodyBytes)
	limit := o.requestLimit
	if limit <= 0 {
		limit = forgeconnection.AccessSyncRequestLimit
	}
	requests := &requestBudget{limit: limit}
	// Transport order matters for truthful accounting: the cumulative-body
	// budget preflight runs OUTSIDE the counter, so a request rejected for
	// an exhausted body budget never increments the count, and the counter
	// rejects the first request past the limit before delegating. The
	// metric is attempted RoundTrips: an attempt that fails before an HTTP
	// request is written (canceled context, DNS, TLS) still counts as one
	// attempt, so the count bounds — and can slightly exceed — what the
	// provider observed, never the reverse.
	client := &forgeclient.Client{
		BaseURL: input.BaseURL,
		Token:   string(input.PAT),
		HTTPClient: &http.Client{
			Transport: &budgetTransport{
				inner:  &requestCountingTransport{inner: singleAttemptTransport(o.transport), requests: requests},
				budget: budget,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	run := &accessRun{ctx: ctx, client: client, budget: budget, requests: requests}
	result := run.observe(input)
	result.RequestCount = requests.used.Load()
	return result
}

// singleAttemptTransport makes one counted request equal one wire request.
// Two transparent retry channels exist inside a single outer RoundTrip:
// net/http retries an idempotent GET that failed on a reused HTTP/1.x
// keep-alive connection, and the HTTP/2 transport retries streams the
// server rejected (REFUSED_STREAM, GOAWAY). Disabling keep-alives removes
// HTTP/1.x connection reuse — net/http never retries a request that failed
// on a first-use connection — and the client is forced to HTTP/1.x only:
// the explicit protocol set, a cleared automatic-upgrade hook, and an ALPN
// offer without h2 keep every HTTP/2 code path unreachable, including at
// TLS negotiation. The 96-request budget therefore bounds the wire
// exactly. A non-*http.Transport round tripper is the caller's
// responsibility and passes through unchanged.
func singleAttemptTransport(transport http.RoundTripper) http.RoundTripper {
	base, ok := transport.(*http.Transport)
	if !ok {
		return transport
	}
	cloned := base.Clone()
	cloned.DisableKeepAlives = true
	cloned.ForceAttemptHTTP2 = false
	cloned.Protocols = new(http.Protocols)
	cloned.Protocols.SetHTTP1(true)
	cloned.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if cloned.TLSClientConfig != nil {
		tlsConfig := cloned.TLSClientConfig.Clone()
		withoutH2 := tlsConfig.NextProtos[:0:0]
		for _, protocol := range tlsConfig.NextProtos {
			if protocol != "h2" {
				withoutH2 = append(withoutH2, protocol)
			}
		}
		tlsConfig.NextProtos = withoutH2
		cloned.TLSClientConfig = tlsConfig
	}
	return cloned
}

// requestBudget caps the total provider requests of one snapshot.
type requestBudget struct {
	used  atomic.Int64
	limit int64
}

func (b *requestBudget) remaining() int64 {
	return b.limit - b.used.Load()
}

// requestCountingTransport counts every attempted RoundTrip and rejects
// the first attempt past the cap before any network activity. A budget
// rejection never counts; an attempt that fails mid-flight does.
type requestCountingTransport struct {
	inner    http.RoundTripper
	requests *requestBudget
}

func (t *requestCountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.requests.used.Add(1) > t.requests.limit {
		t.requests.used.Add(-1)
		return nil, errAccessRequestExhausted
	}
	return t.inner.RoundTrip(request)
}

// accessGraph is the bounded immutable-id graph merged across every shared
// listing. Duplicate edges collapse into set entries; the same id with
// conflicting fields, or the same login on different ids, fails the graph.
// Only orgRepositories establishes bound-repository availability: a
// repository surfaced solely through a team listing is never treated as
// part of the credential-visible top-level inventory.
type accessGraph struct {
	usersByID       map[int64]string // immutable user id -> exact current login
	userIDLogins    map[string]int64 // exact current login -> immutable user id
	repositories    map[int64]accessGraphRepository
	repoIDByLocator map[string]int64         // exact owner/name locator -> immutable repository id
	orgRepositories map[int64]bool           // top-level organization listing membership
	teamRepos       map[int64]map[int64]bool // team id -> repository ids
	teamMembers     map[int64]map[int64]bool // team id -> user ids
	collabs         map[int64]map[int64]bool // repository id -> direct collaborator user ids
}

// accessGraphRepository carries the approved conflict-equality fields:
// owner/name (the immutable id keys the map) plus the decoded visibility.
// The mutable default branch is deliberately excluded — a branch rename
// between listings must never invalidate access evidence.
type accessGraphRepository struct {
	owner   string
	name    string
	private bool
}

func newAccessGraph() *accessGraph {
	return &accessGraph{
		usersByID:       make(map[int64]string),
		userIDLogins:    make(map[string]int64),
		repositories:    make(map[int64]accessGraphRepository),
		repoIDByLocator: make(map[string]int64),
		orgRepositories: make(map[int64]bool),
		teamRepos:       make(map[int64]map[int64]bool),
		teamMembers:     make(map[int64]map[int64]bool),
		collabs:         make(map[int64]map[int64]bool),
	}
}

func (g *accessGraph) mergeUser(user forgeclient.AccessUser) error {
	if user.ID <= 0 || !validForgejoName(user.Login) {
		return errAccessInvalidRecord
	}
	if existing, known := g.usersByID[user.ID]; known && existing != user.Login {
		return errAccessConflictingData
	}
	if existingID, known := g.userIDLogins[user.Login]; known && existingID != user.ID {
		return errAccessConflictingData
	}
	g.usersByID[user.ID] = user.Login
	g.userIDLogins[user.Login] = user.ID
	return nil
}

func (g *accessGraph) mergeRepository(repository forgeclient.ConnectionRepository) error {
	if repository.ID <= 0 || !validForgejoName(repository.Owner) || !validForgejoName(repository.Name) {
		return errAccessInvalidRecord
	}
	merged := accessGraphRepository{
		owner:   repository.Owner,
		name:    repository.Name,
		private: repository.Private,
	}
	if existing, known := g.repositories[repository.ID]; known && existing != merged {
		return errAccessConflictingData
	}
	// The same exact owner/name locator on two immutable ids fails the
	// graph, mirroring the login rule for users: collaborator and
	// permission reads travel by locator, so a replacement repository at a
	// bound repository's locator could otherwise answer for the bound
	// immutable id and be published as its evidence.
	locator := repository.Owner + "/" + repository.Name
	if existingID, known := g.repoIDByLocator[locator]; known && existingID != repository.ID {
		return errAccessConflictingData
	}
	g.repoIDByLocator[locator] = repository.ID
	g.repositories[repository.ID] = merged
	return nil
}

type accessRun struct {
	ctx      context.Context
	client   *forgeclient.Client
	budget   *bodyBudget
	requests *requestBudget
}

// accessLinkedIdentity is one linked identity with its remote id parsed
// exactly once for the whole snapshot.
type accessLinkedIdentity struct {
	identityID     int64
	remoteID       int64
	usernameAtLink string
}

// accessBoundRepository is one bound repository with its remote id parsed
// exactly once for the whole snapshot.
type accessBoundRepository struct {
	repositoryID int64
	remoteID     int64
}

// parseAccessScope parses every identity and binding remote id up front so
// no later stage re-parses or re-fails the same canonical decimal text.
func parseAccessScope(input forgeconnection.AccessObserveInput) ([]accessLinkedIdentity, []accessBoundRepository, bool) {
	identities := make([]accessLinkedIdentity, 0, len(input.Identities))
	for _, identity := range input.Identities {
		remoteID, err := strconv.ParseInt(identity.RemoteUserID, 10, 64)
		if err != nil || remoteID <= 0 {
			return nil, nil, false
		}
		identities = append(identities, accessLinkedIdentity{
			identityID:     identity.IdentityID,
			remoteID:       remoteID,
			usernameAtLink: identity.UsernameAtLink,
		})
	}
	bindings := make([]accessBoundRepository, 0, len(input.Bindings))
	for _, binding := range input.Bindings {
		remoteID, err := strconv.ParseInt(binding.RemoteRepositoryID, 10, 64)
		if err != nil || remoteID <= 0 {
			return nil, nil, false
		}
		bindings = append(bindings, accessBoundRepository{
			repositoryID: binding.RepositoryID,
			remoteID:     remoteID,
		})
	}
	return identities, bindings, true
}

// observe drives the whole snapshot. Request ordering is deterministic
// (identities and bindings ascending by internal id, teams ascending by
// team id) and can never alter results: classification happens only after
// the complete shared graph.
func (r *accessRun) observe(input forgeconnection.AccessObserveInput) forgeconnection.AccessObservation {
	fail := func(code forgeconnection.AccessSyncResultCode) forgeconnection.AccessObservation {
		return forgeconnection.AccessObservation{ResultCode: code}
	}
	// The observer validates the small-alpha scope itself: a caller handing
	// it more work than the approved ceilings fails closed before any
	// provider request is issued.
	if len(input.Identities) > accessMaxIdentities ||
		len(input.Bindings) > accessMaxRepositories ||
		len(input.Identities)*len(input.Bindings) > accessMaxPairs {
		return fail(forgeconnection.AccessSyncWorkLimitExceeded)
	}
	identities, bindings, ok := parseAccessScope(input)
	if !ok {
		return fail(forgeconnection.AccessSyncInvalidResponse)
	}
	if code := r.verifyServiceUser(input.BoundServiceUserRemoteID); code != "" {
		return fail(code)
	}
	organizationName, code := r.verifyOrganization(input.OrganizationSlug, input.BoundOrganizationRemoteID)
	if code != "" {
		return fail(code)
	}

	graph := newAccessGraph()
	if code := r.readOrganizationRepositories(graph, organizationName); code != "" {
		return fail(code)
	}
	if code := r.readOrganizationMembers(graph, organizationName); code != "" {
		return fail(code)
	}
	teams, code := r.readOrganizationTeams(organizationName)
	if code != "" {
		return fail(code)
	}
	for _, teamID := range teams {
		if code := r.readTeamRepositories(graph, teamID); code != "" {
			return fail(code)
		}
	}
	boundRemote := make(map[int64]bool, len(bindings))
	for _, binding := range bindings {
		boundRemote[binding.remoteID] = true
	}
	// Members are read only for teams whose repositories intersect a bound
	// repository; a non-intersecting team can never contribute a pair edge.
	for _, teamID := range teams {
		if !teamIntersectsBound(graph.teamRepos[teamID], boundRemote) {
			continue
		}
		if code := r.readTeamMembers(graph, teamID); code != "" {
			return fail(code)
		}
	}
	if code := r.readBoundRepositoryCollaborators(graph, bindings); code != "" {
		return fail(code)
	}

	// Phase preflight: the whole worst-case resolution phase must fit the
	// remaining budget before its first request is issued.
	if code := r.reserveResolutionRequests(graph, identities, bindings); code != "" {
		return fail(code)
	}
	logins, unresolved, code := r.resolveIdentities(graph, identities)
	if code != "" {
		return fail(code)
	}
	pairs, code := r.classifyPairs(graph, identities, bindings, logins, unresolved)
	if code != "" {
		return fail(code)
	}
	return forgeconnection.AccessObservation{ResultCode: forgeconnection.AccessSyncComplete, Pairs: pairs}
}

func (r *accessRun) verifyServiceUser(boundRemoteID string) forgeconnection.AccessSyncResultCode {
	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	defer cancel()
	user, err := r.client.ReadCurrentUser(requestCtx)
	if err != nil {
		return r.classifySystemic(err, forgeconnection.AccessSyncInvalidResponse)
	}
	if user.IsAdmin {
		return forgeconnection.AccessSyncServiceUserIsAdmin
	}
	if strconv.FormatInt(user.ID, 10) != boundRemoteID {
		return forgeconnection.AccessSyncServiceUserChanged
	}
	return ""
}

// verifyOrganization reads the organization by its last-known slug and
// requires the immutable bound id. Per the systemic matrix, a 404 on this
// control read is masking and classifies as invalid_response;
// organization_changed is reserved for a resolved organization whose
// immutable id no longer matches, or a stored slug that cannot travel as a
// path segment at all.
func (r *accessRun) verifyOrganization(slug, boundRemoteID string) (string, forgeconnection.AccessSyncResultCode) {
	if !validForgejoName(slug) {
		return "", forgeconnection.AccessSyncOrganizationChanged
	}
	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	defer cancel()
	organization, err := r.client.ReadOrganization(requestCtx, slug)
	if err != nil {
		return "", r.classifySystemic(err, forgeconnection.AccessSyncInvalidResponse)
	}
	if strconv.FormatInt(organization.ID, 10) != boundRemoteID {
		return "", forgeconnection.AccessSyncOrganizationChanged
	}
	// The current name becomes an API path segment for every organization
	// listing below.
	if !validForgejoName(organization.Name) {
		return "", forgeconnection.AccessSyncInvalidResponse
	}
	return organization.Name, ""
}

func (r *accessRun) readOrganizationRepositories(graph *accessGraph, organization string) forgeconnection.AccessSyncResultCode {
	seen := make(map[int64]bool)
	return r.paginateAccess(accessTopLevelMaxPages, accessTopLevelMaxRecords, forgeconnection.AccessSyncInvalidResponse,
		func(page int) (int, int64, error) {
			requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
			defer cancel()
			repositories, total, err := r.client.ReadOrganizationRepositories(requestCtx, organization, page, pageLimit)
			if err != nil {
				return 0, 0, err
			}
			for _, repository := range repositories {
				if seen[repository.ID] {
					return 0, 0, errAccessDuplicateRecord
				}
				seen[repository.ID] = true
				if err := graph.mergeRepository(repository); err != nil {
					return 0, 0, err
				}
				graph.orgRepositories[repository.ID] = true
			}
			return len(repositories), total, nil
		})
}

func (r *accessRun) readOrganizationMembers(graph *accessGraph, organization string) forgeconnection.AccessSyncResultCode {
	seen := make(map[int64]bool)
	return r.paginateAccess(accessTopLevelMaxPages, accessTopLevelMaxRecords, forgeconnection.AccessSyncInvalidResponse,
		func(page int) (int, int64, error) {
			requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
			defer cancel()
			members, total, err := r.client.ReadOrganizationMembers(requestCtx, organization, page, pageLimit)
			if err != nil {
				return 0, 0, err
			}
			for _, member := range members {
				if seen[member.ID] {
					return 0, 0, errAccessDuplicateRecord
				}
				seen[member.ID] = true
				if err := graph.mergeUser(member); err != nil {
					return 0, 0, err
				}
			}
			return len(members), total, nil
		})
}

// readOrganizationTeams returns every team id ascending. More teams than
// the approved limit fail closed.
func (r *accessRun) readOrganizationTeams(organization string) ([]int64, forgeconnection.AccessSyncResultCode) {
	seen := make(map[int64]bool)
	code := r.paginateAccess(accessTopLevelMaxPages, accessTopLevelMaxRecords, forgeconnection.AccessSyncInvalidResponse,
		func(page int) (int, int64, error) {
			requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
			defer cancel()
			teams, total, err := r.client.ReadOrganizationTeams(requestCtx, organization, page, pageLimit)
			if err != nil {
				return 0, 0, err
			}
			if total > accessMaxTeams {
				return 0, 0, errAccessTeamLimit
			}
			for _, team := range teams {
				if seen[team.ID] {
					return 0, 0, errAccessDuplicateRecord
				}
				seen[team.ID] = true
				if len(seen) > accessMaxTeams {
					return 0, 0, errAccessTeamLimit
				}
			}
			return len(teams), total, nil
		})
	if code != "" {
		return nil, code
	}
	teams := make([]int64, 0, len(seen))
	for teamID := range seen {
		teams = append(teams, teamID)
	}
	slices.Sort(teams)
	return teams, ""
}

func (r *accessRun) readTeamRepositories(graph *accessGraph, teamID int64) forgeconnection.AccessSyncResultCode {
	repositories := make(map[int64]bool)
	code := r.paginateAccess(accessNestedMaxPages, accessNestedMaxRecords, forgeconnection.AccessSyncInvalidResponse,
		func(page int) (int, int64, error) {
			requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
			defer cancel()
			pageRepositories, total, err := r.client.ReadTeamRepositories(requestCtx, teamID, page, pageLimit)
			if err != nil {
				return 0, 0, err
			}
			for _, repository := range pageRepositories {
				if repositories[repository.ID] {
					return 0, 0, errAccessDuplicateRecord
				}
				repositories[repository.ID] = true
				if err := graph.mergeRepository(repository); err != nil {
					return 0, 0, err
				}
			}
			return len(pageRepositories), total, nil
		})
	if code != "" {
		return code
	}
	graph.teamRepos[teamID] = repositories
	return ""
}

func (r *accessRun) readTeamMembers(graph *accessGraph, teamID int64) forgeconnection.AccessSyncResultCode {
	members := make(map[int64]bool)
	code := r.paginateAccess(accessNestedMaxPages, accessNestedMaxRecords, forgeconnection.AccessSyncInvalidResponse,
		func(page int) (int, int64, error) {
			requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
			defer cancel()
			pageMembers, total, err := r.client.ReadTeamMembers(requestCtx, teamID, page, pageLimit)
			if err != nil {
				return 0, 0, err
			}
			for _, member := range pageMembers {
				if members[member.ID] {
					return 0, 0, errAccessDuplicateRecord
				}
				members[member.ID] = true
				if err := graph.mergeUser(member); err != nil {
					return 0, 0, err
				}
			}
			return len(pageMembers), total, nil
		})
	if code != "" {
		return code
	}
	graph.teamMembers[teamID] = members
	return ""
}

// readBoundRepositoryCollaborators reads the complete direct-collaborator
// list of every bound repository present in the top-level organization
// listing, ascending by internal repository id. A bound repository absent
// from that listing is skipped here and classifies as
// repository_unavailable per pair, even when a team listing mentions it.
func (r *accessRun) readBoundRepositoryCollaborators(
	graph *accessGraph,
	bindings []accessBoundRepository,
) forgeconnection.AccessSyncResultCode {
	for _, binding := range bindings {
		if !graph.orgRepositories[binding.remoteID] {
			continue
		}
		repository := graph.repositories[binding.remoteID]
		collaborators := make(map[int64]bool)
		code := r.paginateAccess(accessNestedMaxPages, accessNestedMaxRecords, forgeconnection.AccessSyncInvalidResponse,
			func(page int) (int, int64, error) {
				requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
				defer cancel()
				pageCollaborators, total, err := r.client.ReadRepositoryCollaborators(requestCtx, repository.owner, repository.name, page, pageLimit)
				if err != nil {
					return 0, 0, err
				}
				for _, collaborator := range pageCollaborators {
					if collaborators[collaborator.ID] {
						return 0, 0, errAccessDuplicateRecord
					}
					collaborators[collaborator.ID] = true
					if err := graph.mergeUser(collaborator); err != nil {
						return 0, 0, err
					}
				}
				return len(pageCollaborators), total, nil
			})
		if code != "" {
			return code
		}
		graph.collabs[binding.remoteID] = collaborators
	}
	return ""
}

// reserveResolutionRequests runs after the shared graph and before the
// first identity-fallback or effective-permission request. It reserves the
// worst case of the remaining phase — one fallback per identity absent from
// the graph whose username-at-link can travel as a path segment, plus one
// permission request per pair whose identity could resolve and whose bound
// repository is in the top-level organization listing — and fails closed as
// work_limit_exceeded when that reservation exceeds the remaining request
// budget, so the resolution phase can never start work it cannot finish.
func (r *accessRun) reserveResolutionRequests(
	graph *accessGraph,
	identities []accessLinkedIdentity,
	bindings []accessBoundRepository,
) forgeconnection.AccessSyncResultCode {
	fallbacks := int64(0)
	resolvable := int64(0)
	for _, identity := range identities {
		if _, known := graph.usersByID[identity.remoteID]; known {
			resolvable++
			continue
		}
		if validForgejoName(identity.usernameAtLink) {
			// Worst case: the fallback request succeeds and the identity
			// then needs a permission request per visible pair.
			fallbacks++
			resolvable++
		}
	}
	visibleBindings := int64(0)
	for _, binding := range bindings {
		if graph.orgRepositories[binding.remoteID] {
			visibleBindings++
		}
	}
	if fallbacks+resolvable*visibleBindings > r.requests.remaining() {
		return forgeconnection.AccessSyncWorkLimitExceeded
	}
	return ""
}

// resolveIdentities maps each identity's immutable remote id to its exact
// current login: from the shared graph when the id already appears there,
// otherwise through the username-at-link fallback whose returned numeric id
// must match. A 404 or id mismatch leaves that identity unresolved; every
// other fallback failure is systemic.
func (r *accessRun) resolveIdentities(
	graph *accessGraph,
	identities []accessLinkedIdentity,
) (map[int64]string, map[int64]bool, forgeconnection.AccessSyncResultCode) {
	logins := make(map[int64]string, len(identities))
	unresolved := make(map[int64]bool)
	for _, identity := range identities {
		if login, known := graph.usersByID[identity.remoteID]; known {
			logins[identity.identityID] = login
			continue
		}
		// The stored username-at-link is historical local data; one that
		// cannot travel as a path segment can only stay unresolved.
		if !validForgejoName(identity.usernameAtLink) {
			unresolved[identity.identityID] = true
			continue
		}
		requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
		user, err := r.client.ReadUserByUsername(requestCtx, identity.usernameAtLink)
		cancel()
		if err != nil {
			var status *forgeclient.StatusError
			if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
				unresolved[identity.identityID] = true
				continue
			}
			return nil, nil, r.classifySystemic(err, forgeconnection.AccessSyncInvalidResponse)
		}
		if user.ID != identity.remoteID {
			unresolved[identity.identityID] = true
			continue
		}
		if err := graph.mergeUser(user); err != nil {
			return nil, nil, forgeconnection.AccessSyncInvalidResponse
		}
		logins[identity.identityID] = user.Login
	}
	return logins, unresolved, ""
}

// classifyPairs requests the effective permission for every resolvable pair
// and classifies all pairs. Unresolved identities and graph-invisible bound
// repositories classify deterministically without a permission call.
func (r *accessRun) classifyPairs(
	graph *accessGraph,
	identities []accessLinkedIdentity,
	bindings []accessBoundRepository,
	logins map[int64]string,
	unresolved map[int64]bool,
) ([]forgeconnection.AccessPairObservation, forgeconnection.AccessSyncResultCode) {
	pairs := make([]forgeconnection.AccessPairObservation, 0, len(identities)*len(bindings))
	for _, identity := range identities {
		for _, binding := range bindings {
			reason, code := r.classifyPair(graph, identity, binding.remoteID, logins, unresolved)
			if code != "" {
				return nil, code
			}
			pairs = append(pairs, forgeconnection.AccessPairObservation{
				IdentityID:   identity.identityID,
				RepositoryID: binding.repositoryID,
				Reason:       reason,
			})
		}
	}
	return pairs, ""
}

func (r *accessRun) classifyPair(
	graph *accessGraph,
	identity accessLinkedIdentity,
	repositoryRemoteID int64,
	logins map[int64]string,
	unresolved map[int64]bool,
) (forgeconnection.AccessObservationReason, forgeconnection.AccessSyncResultCode) {
	if unresolved[identity.identityID] {
		return forgeconnection.AccessReasonIdentityUnresolved, ""
	}
	// Availability requires the top-level organization listing; a team-only
	// mention never counts as credential-visible inventory.
	if !graph.orgRepositories[repositoryRemoteID] {
		return forgeconnection.AccessReasonRepositoryUnavailable, ""
	}
	repository := graph.repositories[repositoryRemoteID]
	login, resolved := logins[identity.identityID]
	if !resolved {
		return forgeconnection.AccessReasonIdentityUnresolved, ""
	}

	directEdge := graph.collabs[repositoryRemoteID][identity.remoteID]
	teamEdge := false
	for teamID, repositories := range graph.teamRepos {
		if repositories[repositoryRemoteID] && graph.teamMembers[teamID][identity.remoteID] {
			teamEdge = true
			break
		}
	}

	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	permission, err := r.client.ReadCollaboratorPermission(requestCtx, repository.owner, repository.name, login)
	cancel()
	if err != nil {
		var status *forgeclient.StatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusNotFound {
			return forgeconnection.AccessReasonPermissionUnavailable, ""
		}
		return "", r.classifySystemic(err, forgeconnection.AccessSyncInvalidResponse)
	}
	if permission.User.ID != identity.remoteID || permission.User.Login != login {
		return forgeconnection.AccessReasonEvidenceInconsistent, ""
	}
	switch permission.Permission {
	case "none":
		if directEdge || teamEdge {
			return forgeconnection.AccessReasonEvidenceInconsistent, ""
		}
		return forgeconnection.AccessReasonNoExplicitAccessNone, ""
	case "read", "write", "admin", "owner":
		if directEdge {
			return forgeconnection.AccessReasonDirectCollaborator, ""
		}
		if teamEdge {
			return forgeconnection.AccessReasonTeamAccess, ""
		}
		// Positive permission with no explicit edge: implicit visibility is
		// never inferred.
		return forgeconnection.AccessReasonVisibilitySourceUnproven, ""
	default:
		return forgeconnection.AccessReasonPermissionUnrecognized, ""
	}
}

func teamIntersectsBound(teamRepositories map[int64]bool, boundRemote map[int64]bool) bool {
	for remoteID := range boundRemote {
		if teamRepositories[remoteID] {
			return true
		}
	}
	return false
}

// paginateAccess drives one listing under the snapshot's pagination
// protocol: a stable valid X-Total-Count on every page, monotonic progress,
// a total within the approved record ceiling, and the page ceiling.
func (r *accessRun) paginateAccess(
	maxPages int,
	maxRecords int64,
	notFound forgeconnection.AccessSyncResultCode,
	readPage func(page int) (int, int64, error),
) forgeconnection.AccessSyncResultCode {
	collected := 0
	expectedTotal := int64(-1)
	for page := 1; ; page++ {
		if page > maxPages {
			return forgeconnection.AccessSyncPaginationIncomplete
		}
		count, total, err := readPage(page)
		if err != nil {
			return r.classifySystemic(err, notFound)
		}
		if count > pageLimit {
			return forgeconnection.AccessSyncInvalidResponse
		}
		if expectedTotal == -1 {
			expectedTotal = total
			if expectedTotal > maxRecords {
				return forgeconnection.AccessSyncPaginationIncomplete
			}
		}
		if total != expectedTotal {
			return forgeconnection.AccessSyncInvalidResponse
		}
		collected += count
		if int64(collected) > expectedTotal {
			return forgeconnection.AccessSyncInvalidResponse
		}
		if int64(collected) == expectedTotal {
			return ""
		}
		if count == 0 {
			return forgeconnection.AccessSyncPaginationIncomplete
		}
	}
}

// classifySystemic maps one failed shared/control read onto the snapshot's
// total error matrix. notFound names the caller-specific meaning of a 404.
func (r *accessRun) classifySystemic(err error, notFound forgeconnection.AccessSyncResultCode) forgeconnection.AccessSyncResultCode {
	switch {
	case errors.Is(err, errAccessRequestExhausted):
		return forgeconnection.AccessSyncWorkLimitExceeded
	case errors.Is(err, errAccessTeamLimit):
		return forgeconnection.AccessSyncWorkLimitExceeded
	case errors.Is(err, errBodyBudgetExhausted), r.budget.exhausted():
		return forgeconnection.AccessSyncInvalidResponse
	case errors.Is(err, errAccessDuplicateRecord),
		errors.Is(err, errAccessConflictingData),
		errors.Is(err, errAccessInvalidRecord),
		errors.Is(err, forgeclient.ErrResponseMalformed),
		errors.Is(err, forgeclient.ErrTotalCountInvalid):
		return forgeconnection.AccessSyncInvalidResponse
	}
	var status *forgeclient.StatusError
	if errors.As(err, &status) {
		switch {
		case status.StatusCode == http.StatusUnauthorized:
			return forgeconnection.AccessSyncAuthenticationFailed
		case status.StatusCode == http.StatusForbidden:
			return forgeconnection.AccessSyncAuthorizationFailed
		case status.StatusCode == http.StatusNotFound:
			return notFound
		case status.StatusCode == http.StatusTooManyRequests:
			return forgeconnection.AccessSyncUnavailable
		case status.StatusCode >= 500:
			return forgeconnection.AccessSyncUnavailable
		default:
			// Redirects and every other non-success status are never a
			// canonical Forgejo API response.
			return forgeconnection.AccessSyncInvalidResponse
		}
	}
	// Timeouts, the global deadline, and transport failures.
	return forgeconnection.AccessSyncUnavailable
}
