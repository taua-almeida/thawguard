package forgejo

import (
	"context"
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
	requests := &requestBudget{limit: forgeconnection.AccessSyncRequestLimit}
	client := &forgeclient.Client{
		BaseURL: input.BaseURL,
		Token:   string(input.PAT),
		HTTPClient: &http.Client{
			Transport: &requestCountingTransport{
				inner:    &budgetTransport{inner: o.transport, budget: budget},
				requests: requests,
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

// requestBudget caps the total provider requests of one snapshot.
type requestBudget struct {
	used  atomic.Int64
	limit int64
}

// requestCountingTransport counts every issued request and rejects the
// first request past the cap before any network activity.
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
type accessGraph struct {
	usersByID    map[int64]string // immutable user id -> exact current login
	userIDLogins map[string]int64 // exact current login -> immutable user id
	repositories map[int64]accessGraphRepository
	teamRepos    map[int64]map[int64]bool // team id -> repository ids
	teamMembers  map[int64]map[int64]bool // team id -> user ids
	collabs      map[int64]map[int64]bool // repository id -> direct collaborator user ids
}

type accessGraphRepository struct {
	owner string
	name  string
}

func newAccessGraph() *accessGraph {
	return &accessGraph{
		usersByID:    make(map[int64]string),
		userIDLogins: make(map[string]int64),
		repositories: make(map[int64]accessGraphRepository),
		teamRepos:    make(map[int64]map[int64]bool),
		teamMembers:  make(map[int64]map[int64]bool),
		collabs:      make(map[int64]map[int64]bool),
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
	merged := accessGraphRepository{owner: repository.Owner, name: repository.Name}
	if existing, known := g.repositories[repository.ID]; known && existing != merged {
		return errAccessConflictingData
	}
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
// requires the immutable bound id. A 404 means the known slug no longer
// names the bound organization.
func (r *accessRun) verifyOrganization(slug, boundRemoteID string) (string, forgeconnection.AccessSyncResultCode) {
	if !validForgejoName(slug) {
		return "", forgeconnection.AccessSyncOrganizationChanged
	}
	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	defer cancel()
	organization, err := r.client.ReadOrganization(requestCtx, slug)
	if err != nil {
		return "", r.classifySystemic(err, forgeconnection.AccessSyncOrganizationChanged)
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
// list of every graph-visible bound repository, ascending by internal
// repository id. A bound repository absent from the graph is skipped here
// and classifies as repository_unavailable per pair.
func (r *accessRun) readBoundRepositoryCollaborators(
	graph *accessGraph,
	bindings []accessBoundRepository,
) forgeconnection.AccessSyncResultCode {
	for _, binding := range bindings {
		repository, visible := graph.repositories[binding.remoteID]
		if !visible {
			continue
		}
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
	repository, visible := graph.repositories[repositoryRemoteID]
	if !visible {
		return forgeconnection.AccessReasonRepositoryUnavailable, ""
	}
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
