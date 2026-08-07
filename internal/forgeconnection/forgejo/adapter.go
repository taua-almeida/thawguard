// Package forgejo observes a Forgejo installation for the connection
// preview check. Every request is a plain GET under the check's strict
// limits; the adapter never calls a write endpoint and never retains raw
// response data in its report.
package forgejo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
	"unicode/utf8"

	forgeclient "github.com/taua-almeida/thawguard/internal/forge/forgejo"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

const (
	perRequestTimeout = 10 * time.Second
	pageLimit         = 50
	// maxListPages bounds one paginated listing; with pageLimit it matches
	// the 1,000-record inventory limit.
	maxListPages = 20
	// maxCumulativeBodyBytes bounds all response bodies of one observation.
	maxCumulativeBodyBytes = 24 << 20
	maxRecords             = 1000
	maxObservedVersion     = 64
)

type Adapter struct {
	transport http.RoundTripper
}

func NewAdapter(transport http.RoundTripper) *Adapter {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Adapter{transport: transport}
}

var _ forgeconnection.CheckObserver = (*Adapter)(nil)

// Observe runs the read-only observation sequence: version, current user,
// the complete credential-visible organization list, every visible
// repository page, and one direct private-repository read when a private
// repository is visible. Failures are classified without retaining any
// response data.
func (a *Adapter) Observe(ctx context.Context, input forgeconnection.ObserveInput) forgeconnection.Observation {
	if a == nil || a.transport == nil {
		return forgeconnection.Observation{ResultCode: forgeconnection.CheckUnavailable}
	}
	budget := &bodyBudget{}
	budget.remaining.Store(maxCumulativeBodyBytes)
	client := &forgeclient.Client{
		BaseURL: input.BaseURL,
		Token:   string(input.PAT),
		HTTPClient: &http.Client{
			Transport: &budgetTransport{inner: a.transport, budget: budget},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	run := &observationRun{ctx: ctx, client: client, budget: budget}

	version, code := run.readVersion()
	if code != "" {
		return forgeconnection.Observation{ResultCode: code}
	}
	fail := func(code forgeconnection.CheckResultCode) forgeconnection.Observation {
		return forgeconnection.Observation{ResultCode: code, ObservedVersion: version}
	}

	user, code := run.readCurrentUser(input.BoundServiceUserRemoteID)
	if code != "" {
		return fail(code)
	}
	organization, code := run.findOrganization(input.OrganizationSlug, input.BoundOrganizationRemoteID)
	if code != "" {
		return fail(code)
	}
	repositories, code := run.readOrganizationRepositories(organization.Name)
	if code != "" {
		return fail(code)
	}
	resultCode, code := run.provePrivateRead(repositories)
	if code != "" {
		return fail(code)
	}

	observed := make([]forgeconnection.ObservedRepository, 0, len(repositories))
	for _, repository := range repositories {
		observed = append(observed, forgeconnection.ObservedRepository{
			RemoteID:      strconv.FormatInt(repository.ID, 10),
			Owner:         repository.Owner,
			Name:          repository.Name,
			DefaultBranch: repository.DefaultBranch,
			Private:       repository.Private,
		})
	}
	displayName := organization.FullName
	if displayName == "" {
		displayName = organization.Name
	}
	return forgeconnection.Observation{
		ResultCode:          resultCode,
		ObservedVersion:     version,
		ServiceUserRemoteID: strconv.FormatInt(user.ID, 10),
		Organization: forgeconnection.ObservedOrganization{
			RemoteID:    strconv.FormatInt(organization.ID, 10),
			Slug:        organization.Name,
			DisplayName: displayName,
		},
		Repositories: observed,
	}
}

// observationRun carries one observation's shared state.
type observationRun struct {
	ctx    context.Context
	client *forgeclient.Client
	budget *bodyBudget
}

func (r *observationRun) readVersion() (string, forgeconnection.CheckResultCode) {
	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	defer cancel()
	version, err := r.client.ReadVersion(requestCtx)
	if err != nil {
		return "", r.classify(err, forgeconnection.CheckInvalidResponse)
	}
	if len(version) > maxObservedVersion || !validObservedText(version) {
		return "", forgeconnection.CheckInvalidResponse
	}
	return version, ""
}

func (r *observationRun) readCurrentUser(boundRemoteID string) (forgeclient.ConnectionUser, forgeconnection.CheckResultCode) {
	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	defer cancel()
	user, err := r.client.ReadCurrentUser(requestCtx)
	if err != nil {
		return forgeclient.ConnectionUser{}, r.classify(err, forgeconnection.CheckInvalidResponse)
	}
	if user.IsAdmin {
		return forgeclient.ConnectionUser{}, forgeconnection.CheckServiceUserIsAdmin
	}
	if boundRemoteID != "" && strconv.FormatInt(user.ID, 10) != boundRemoteID {
		return forgeclient.ConnectionUser{}, forgeconnection.CheckServiceUserChanged
	}
	return user, ""
}

// findOrganization reads the complete credential-visible organization list.
// Before binding it matches the configured slug exactly; after binding it
// finds the immutable remote id so a renamed organization keeps its
// identity and refreshes its current slug.
func (r *observationRun) findOrganization(configuredSlug, boundRemoteID string) (forgeclient.ConnectionOrganization, forgeconnection.CheckResultCode) {
	var found *forgeclient.ConnectionOrganization
	seen := make(map[int64]struct{})
	code := r.paginate(forgeconnection.CheckInvalidResponse, func(page int) (int, int64, error) {
		requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
		defer cancel()
		organizations, total, err := r.client.ReadCurrentUserOrganizations(requestCtx, page, pageLimit)
		if err != nil {
			return 0, 0, err
		}
		for _, organization := range organizations {
			// A repeated immutable id means the listing is drifting or
			// repeating pages; such a listing is never accepted as complete.
			if _, duplicate := seen[organization.ID]; duplicate {
				return 0, 0, errPagination
			}
			seen[organization.ID] = struct{}{}
			if !validObservedText(organization.Name) || len(organization.Name) > 255 ||
				(organization.FullName != "" && (!validObservedText(organization.FullName) || len(organization.FullName) > 255)) {
				return 0, 0, errInvalidRecord
			}
			matches := organization.Name == configuredSlug
			if boundRemoteID != "" {
				matches = strconv.FormatInt(organization.ID, 10) == boundRemoteID
			}
			if matches && found == nil {
				match := organization
				found = &match
			}
		}
		return len(organizations), total, nil
	})
	if code != "" {
		return forgeclient.ConnectionOrganization{}, code
	}
	if found == nil {
		if boundRemoteID != "" {
			return forgeclient.ConnectionOrganization{}, forgeconnection.CheckOrganizationChanged
		}
		return forgeclient.ConnectionOrganization{}, forgeconnection.CheckOrganizationUnavailable
	}
	// The selected organization's current name becomes an API path segment
	// for the repository listing, so it must satisfy Forgejo's own name
	// rules — even after a provider-side rename of a bound organization.
	if !validForgejoName(found.Name) {
		return forgeclient.ConnectionOrganization{}, forgeconnection.CheckInvalidResponse
	}
	return *found, ""
}

func (r *observationRun) readOrganizationRepositories(organization string) ([]forgeclient.ConnectionRepository, forgeconnection.CheckResultCode) {
	repositories := make([]forgeclient.ConnectionRepository, 0)
	seen := make(map[int64]struct{})
	// A vanished organization masks the listing as 404 mid-check.
	code := r.paginate(forgeconnection.CheckOrganizationUnavailable, func(page int) (int, int64, error) {
		requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
		defer cancel()
		pageRepositories, total, err := r.client.ReadOrganizationRepositories(requestCtx, organization, page, pageLimit)
		if err != nil {
			return 0, 0, err
		}
		if total > maxRecords {
			return 0, 0, errInventoryLimit
		}
		for _, repository := range pageRepositories {
			if _, duplicate := seen[repository.ID]; duplicate {
				return 0, 0, errPagination
			}
			seen[repository.ID] = struct{}{}
			if !validRepositoryFields(repository) {
				return 0, 0, errInvalidRecord
			}
			repositories = append(repositories, repository)
			if len(repositories) > maxRecords {
				return 0, 0, errInventoryLimit
			}
		}
		return len(pageRepositories), total, nil
	})
	if code != "" {
		return nil, code
	}
	return repositories, ""
}

// provePrivateRead fetches one visible private repository directly. A
// masked 404 on that read means the credential cannot actually read the
// private repository it listed, which is an authorization failure.
func (r *observationRun) provePrivateRead(repositories []forgeclient.ConnectionRepository) (forgeconnection.CheckResultCode, forgeconnection.CheckResultCode) {
	var private *forgeclient.ConnectionRepository
	for _, repository := range repositories {
		if repository.Private {
			match := repository
			private = &match
			break
		}
	}
	if private == nil {
		return forgeconnection.CheckVisibleInventoryObservedPrivateReadUnproven, ""
	}
	requestCtx, cancel := context.WithTimeout(r.ctx, perRequestTimeout)
	defer cancel()
	proof, err := r.client.ReadRepositoryByID(requestCtx, private.ID)
	if err != nil {
		return "", r.classify(err, forgeconnection.CheckAuthorizationFailed)
	}
	if proof.ID != private.ID || !proof.Private {
		return "", forgeconnection.CheckInvalidResponse
	}
	return forgeconnection.CheckVisibleInventoryObserved, ""
}

// pagination protocol failures inside a page callback.
var (
	errPagination     = errors.New("pagination protocol violated")
	errInventoryLimit = errors.New("inventory limit exceeded")
	errInvalidRecord  = errors.New("record is invalid")
)

// paginate drives one listing under the check's pagination protocol: a
// stable valid X-Total-Count on every page, monotonic progress, a reachable
// total, and the page work limit. notFound names the caller-specific
// meaning of a 404 on the listing endpoint.
func (r *observationRun) paginate(notFound forgeconnection.CheckResultCode, readPage func(page int) (int, int64, error)) forgeconnection.CheckResultCode {
	collected := 0
	expectedTotal := int64(-1)
	for page := 1; ; page++ {
		if page > maxListPages {
			return forgeconnection.CheckPaginationIncomplete
		}
		count, total, err := readPage(page)
		if err != nil {
			return r.classify(err, notFound)
		}
		if count > pageLimit {
			return forgeconnection.CheckInvalidResponse
		}
		if expectedTotal == -1 {
			expectedTotal = total
		}
		if total != expectedTotal {
			return forgeconnection.CheckPaginationIncomplete
		}
		collected += count
		if int64(collected) > expectedTotal {
			return forgeconnection.CheckPaginationIncomplete
		}
		if int64(collected) == expectedTotal {
			return ""
		}
		if count == 0 {
			return forgeconnection.CheckPaginationIncomplete
		}
	}
}

// classify maps one failed read to a sanitized result code. notFound names
// the caller-specific meaning of a 404 response.
func (r *observationRun) classify(err error, notFound forgeconnection.CheckResultCode) forgeconnection.CheckResultCode {
	switch {
	case errors.Is(err, errInventoryLimit), r.budget.exhausted():
		return forgeconnection.CheckInventoryLimitExceeded
	case errors.Is(err, errPagination):
		return forgeconnection.CheckPaginationIncomplete
	case errors.Is(err, errInvalidRecord), errors.Is(err, forgeclient.ErrResponseMalformed):
		return forgeconnection.CheckInvalidResponse
	case errors.Is(err, forgeclient.ErrTotalCountInvalid):
		return forgeconnection.CheckPaginationIncomplete
	}
	var status *forgeclient.StatusError
	if errors.As(err, &status) {
		switch {
		case status.StatusCode == http.StatusUnauthorized:
			return forgeconnection.CheckAuthenticationFailed
		case status.StatusCode == http.StatusForbidden:
			return forgeconnection.CheckAuthorizationFailed
		case status.StatusCode == http.StatusNotFound:
			return notFound
		case status.StatusCode == http.StatusTooManyRequests:
			return forgeconnection.CheckUnavailable
		case status.StatusCode >= 500:
			return forgeconnection.CheckUnavailable
		case status.StatusCode >= 300 && status.StatusCode < 400:
			// Redirects are rejected; a redirecting endpoint is not a
			// canonical Forgejo API response.
			return forgeconnection.CheckInvalidResponse
		default:
			return forgeconnection.CheckInvalidResponse
		}
	}
	// Timeouts and transport failures.
	return forgeconnection.CheckUnavailable
}

func validRepositoryFields(repository forgeclient.ConnectionRepository) bool {
	return validObservedText(repository.Owner) && len(repository.Owner) <= 255 &&
		validObservedText(repository.Name) && len(repository.Name) <= 255 &&
		validObservedText(repository.DefaultBranch) && len(repository.DefaultBranch) <= 255
}

// validForgejoName accepts the character set Forgejo allows for user and
// organization names, matching the configured-slug rules. It bounds the only
// observed value this adapter ever places into a request path, so a renamed
// organization can never contribute a traversal or ambiguous segment.
func validForgejoName(value string) bool {
	if len(value) < 1 || len(value) > 255 {
		return false
	}
	for i := range len(value) {
		character := value[i]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return value != "." && value != ".."
}

func validObservedText(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// bodyBudget is the cumulative response-body allowance for one observation.
type bodyBudget struct {
	remaining atomic.Int64
}

func (b *bodyBudget) exhausted() bool {
	return b.remaining.Load() <= 0
}

var errBodyBudgetExhausted = errors.New("cumulative response body limit exceeded")

// budgetTransport wraps every response body in a counting reader so one
// observation can never read more than the cumulative body limit.
type budgetTransport struct {
	inner  http.RoundTripper
	budget *bodyBudget
}

func (t *budgetTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// An exhausted budget rejects the request before any network activity.
	if t.budget.exhausted() {
		return nil, errBodyBudgetExhausted
	}
	response, err := t.inner.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	response.Body = &budgetReader{inner: response.Body, budget: t.budget}
	return response, nil
}

type budgetReader struct {
	inner  io.ReadCloser
	budget *bodyBudget
}

// Read clamps every read to the remaining allowance, so callers can never
// receive or retain bytes beyond the cumulative budget. The cap is
// inclusive: a body ending exactly at the limit still surfaces its EOF and
// succeeds, detected by a one-byte probe that is never handed to the
// caller; only the first byte past the cap fails the read.
func (r *budgetReader) Read(buffer []byte) (int, error) {
	remaining := r.budget.remaining.Load()
	if remaining <= 0 {
		var probe [1]byte
		read, err := r.inner.Read(probe[:])
		if read > 0 {
			return 0, errBodyBudgetExhausted
		}
		if err == io.EOF {
			return 0, io.EOF
		}
		if err != nil {
			return 0, err
		}
		return 0, errBodyBudgetExhausted
	}
	if int64(len(buffer)) > remaining {
		buffer = buffer[:remaining]
	}
	read, err := r.inner.Read(buffer)
	if read > 0 {
		r.budget.remaining.Add(int64(-read))
	}
	return read, err
}

func (r *budgetReader) Close() error { return r.inner.Close() }
