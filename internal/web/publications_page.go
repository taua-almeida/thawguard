package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
)

// publicationsPageSize caps one page of each diagnostics table; the
// pagination footers walk the rest of the history independently.
const publicationsPageSize = 20

// publicationsQuery is the /publications view selection. Each table carries
// its own filter chip and 1-based page (dstate/dpage for desired statuses,
// aresult/apage for attempts); the repository filter is shared and applies to
// both tables at once. The page is read-only, so the query never rides a
// mutating form.
type publicationsQuery struct {
	DesiredState  string
	AttemptResult string
	RepositoryID  int64
	DesiredPage   int
	AttemptPage   int
}

// publicationDesiredFilterOptions orders the desired-statuses chips; values
// double as the ?dstate= values and, "all" aside, as the stored state values.
var publicationDesiredFilterOptions = []filterChipOption{
	{Value: "all", Label: "All"},
	{Value: "success", Label: "Success"},
	{Value: "failure", Label: "Failure"},
	{Value: "pending", Label: "Pending"},
	{Value: "error", Label: "Error"},
}

// publicationAttemptFilterOptions orders the attempts chips; values double as
// the ?aresult= values and, "all" aside, as the stored result values.
// Historical results from removed delivery modes stay reachable through the
// unfiltered view.
var publicationAttemptFilterOptions = []filterChipOption{
	{Value: "all", Label: "All"},
	{Value: "posted", Label: "Posted"},
	{Value: "failed", Label: "Failed"},
}

// publicationFilterValue normalizes a raw chip parameter to one of the given
// options. Unknown values fall back to "all" instead of erroring.
func publicationFilterValue(raw string, options []filterChipOption) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, option := range options {
		if option.Value == value {
			return value
		}
	}
	return "all"
}

func publicationsPageValue(raw string) int {
	page, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || page < 1 {
		return 1
	}
	return page
}

func publicationsQueryFromValues(values url.Values) publicationsQuery {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(values.Get("repo")), 10, 64)
	if err != nil || repositoryID < 0 {
		repositoryID = 0
	}
	return publicationsQuery{
		DesiredState:  publicationFilterValue(values.Get("dstate"), publicationDesiredFilterOptions),
		AttemptResult: publicationFilterValue(values.Get("aresult"), publicationAttemptFilterOptions),
		RepositoryID:  repositoryID,
		DesiredPage:   publicationsPageValue(values.Get("dpage")),
		AttemptPage:   publicationsPageValue(values.Get("apage")),
	}
}

func publicationsURL(query publicationsQuery) string {
	params := url.Values{}
	if query.DesiredState != "" && query.DesiredState != "all" {
		params.Set("dstate", query.DesiredState)
	}
	if query.AttemptResult != "" && query.AttemptResult != "all" {
		params.Set("aresult", query.AttemptResult)
	}
	if query.RepositoryID > 0 {
		params.Set("repo", strconv.FormatInt(query.RepositoryID, 10))
	}
	if query.DesiredPage > 1 {
		params.Set("dpage", strconv.Itoa(query.DesiredPage))
	}
	if query.AttemptPage > 1 {
		params.Set("apage", strconv.Itoa(query.AttemptPage))
	}
	if len(params) == 0 {
		return "/publications"
	}
	return "/publications?" + params.Encode()
}

// publicationStoreFilter maps a chip value to the store's filter argument:
// "all" means the filter is off.
func publicationStoreFilter(value string) string {
	if value == "all" {
		return ""
	}
	return value
}

// publicationStateBadge maps a desired commit-status state to the table badge.
// Tones follow the forge's own presentation: a freeze-driven "failure" renders
// red because that is exactly what the forge shows and what blocks the merge.
func publicationStateBadge(state domain.CommitStatusState) (tone, icon string) {
	switch state {
	case domain.CommitStatusSuccess:
		return "success", "tg-i-check"
	case domain.CommitStatusFailure:
		return "danger", "tg-i-close"
	case domain.CommitStatusPending:
		return "scheduled", "tg-i-schedule"
	case domain.CommitStatusError:
		return "danger", "tg-i-warning"
	default:
		return "warning", "tg-i-warning"
	}
}

// publicationResultBadge maps an attempt result to the table badge.
func publicationResultBadge(result string) (tone, icon string) {
	switch result {
	case statuspublication.AttemptResultPosted:
		return "success", "tg-i-check"
	case statuspublication.AttemptResultFailed:
		return "danger", "tg-i-close"
	default:
		return "warning", "tg-i-warning"
	}
}

// publicationTime renders one stored timestamp for the diagnostics tables:
// the fixed UTC display string plus the RFC3339 value for <time datetime>.
// A zero time yields "Time unavailable" and no <time> element.
func publicationTime(at time.Time) (display, utc string) {
	if at.IsZero() {
		return "Time unavailable", ""
	}
	return at.UTC().Format("2006-01-02 15:04 UTC"), at.UTC().Format(time.RFC3339)
}

// publicationRepositoryLabel names the repository a record belongs to, falling
// back to the stored ID when the repository is no longer configured.
func publicationRepositoryLabel(repository domain.Repository, repositoryID int64) string {
	if repository.ID != 0 {
		return repository.FullName()
	}
	return "Repository #" + strconv.FormatInt(repositoryID, 10)
}

// publicationRowView is one desired-status record in the diagnostics table,
// with every cell precomputed as curated display text.
type publicationRowView struct {
	UpdatedAt    string
	UpdatedAtUTC string
	Repository   string
	PullRequest  string
	TargetBranch string
	HeadSHA      string
	HeadSHAFull  string
	Context      string
	State        string
	StateTone    string
	StateIcon    string
	Mode         string
	Description  string
}

// publicationAttemptRowView is one delivery attempt in the diagnostics table.
// Error text arrives already sanitized from the store and is the only
// error-derived value rendered.
type publicationAttemptRowView struct {
	AttemptedAt    string
	AttemptedAtUTC string
	Repository     string
	PullRequest    string
	TargetBranch   string
	HeadSHA        string
	HeadSHAFull    string
	Context        string
	State          string
	Mode           string
	Result         string
	ResultTone     string
	ResultIcon     string
	Description    string
	Error          string
}

func publicationRowViews(repositories []domain.Repository, publications []statuspublication.Publication) []publicationRowView {
	repositoriesByID := repositoriesByID(repositories)
	rows := make([]publicationRowView, 0, len(publications))
	for _, publication := range publications {
		updatedAt := publication.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = publication.CreatedAt
		}
		row := publicationRowView{
			Repository:   publicationRepositoryLabel(repositoriesByID[publication.RepositoryID], publication.RepositoryID),
			PullRequest:  "#" + strconv.Itoa(publication.PullRequestIndex),
			TargetBranch: publication.TargetBranch,
			HeadSHA:      shortHeadSHA(publication.HeadSHA),
			HeadSHAFull:  publication.HeadSHA,
			Context:      publication.Context,
			State:        string(publication.State),
			Mode:         publication.DeliveryMode,
			Description:  publication.Description,
		}
		row.UpdatedAt, row.UpdatedAtUTC = publicationTime(updatedAt)
		row.StateTone, row.StateIcon = publicationStateBadge(publication.State)
		rows = append(rows, row)
	}
	return rows
}

func publicationAttemptRowViews(repositories []domain.Repository, attempts []statuspublication.Attempt) []publicationAttemptRowView {
	repositoriesByID := repositoriesByID(repositories)
	rows := make([]publicationAttemptRowView, 0, len(attempts))
	for _, attempt := range attempts {
		row := publicationAttemptRowView{
			Repository:   publicationRepositoryLabel(repositoriesByID[attempt.RepositoryID], attempt.RepositoryID),
			PullRequest:  "#" + strconv.Itoa(attempt.PullRequestIndex),
			TargetBranch: attempt.TargetBranch,
			HeadSHA:      shortHeadSHA(attempt.HeadSHA),
			HeadSHAFull:  attempt.HeadSHA,
			Context:      attempt.Context,
			State:        string(attempt.State),
			Mode:         attempt.Mode,
			Result:       attempt.Result,
			Description:  attempt.Description,
			Error:        attempt.Error,
		}
		row.AttemptedAt, row.AttemptedAtUTC = publicationTime(attempt.AttemptedAt)
		row.ResultTone, row.ResultIcon = publicationResultBadge(attempt.Result)
		rows = append(rows, row)
	}
	return rows
}

type publicationsPageData struct {
	AppName            string
	PageTitle          string
	Theme              string
	ActivePage         string
	CurrentUser        currentUserView
	Publications       []publicationRowView
	Attempts           []publicationAttemptRowView
	PublicationsTotal  int
	AttemptsTotal      int
	Query              publicationsQuery
	DesiredChips       []filterChip
	AttemptChips       []filterChip
	DesiredPager       *tablePager
	AttemptPager       *tablePager
	FilterRepositories []domain.Repository
	CSRFToken          string
	CSRFField          string
	Toasts             []toastView
}

// loadPublicationsPageData assembles the /publications view model for the
// requested filters and pages, clamping each table's out-of-range page back
// to its last one independently. Writes a 500 and returns ok=false on load
// failure. Callers must have already handled the nil-StatusPublicationStore
// 503 guard.
func (s *Server) loadPublicationsPageData(w http.ResponseWriter, r *http.Request, query publicationsQuery, session sessionState) (publicationsPageData, bool) {
	ctx := r.Context()
	store := s.cfg.StatusPublicationStore
	desiredState := publicationStoreFilter(query.DesiredState)
	publications, publicationsTotal, err := store.ListPage(ctx, desiredState, query.RepositoryID, (query.DesiredPage-1)*publicationsPageSize, publicationsPageSize)
	if err != nil {
		internalServerError(w)
		return publicationsPageData{}, false
	}
	if len(publications) == 0 && publicationsTotal > 0 && query.DesiredPage > 1 {
		lastPage := (publicationsTotal + publicationsPageSize - 1) / publicationsPageSize
		query.DesiredPage = lastPage
		publications, publicationsTotal, err = store.ListPage(ctx, desiredState, query.RepositoryID, (lastPage-1)*publicationsPageSize, publicationsPageSize)
		if err != nil {
			internalServerError(w)
			return publicationsPageData{}, false
		}
	}
	attemptResult := publicationStoreFilter(query.AttemptResult)
	attempts, attemptsTotal, err := store.ListAttemptsPage(ctx, attemptResult, query.RepositoryID, (query.AttemptPage-1)*publicationsPageSize, publicationsPageSize)
	if err != nil {
		internalServerError(w)
		return publicationsPageData{}, false
	}
	if len(attempts) == 0 && attemptsTotal > 0 && query.AttemptPage > 1 {
		lastPage := (attemptsTotal + publicationsPageSize - 1) / publicationsPageSize
		query.AttemptPage = lastPage
		attempts, attemptsTotal, err = store.ListAttemptsPage(ctx, attemptResult, query.RepositoryID, (lastPage-1)*publicationsPageSize, publicationsPageSize)
		if err != nil {
			internalServerError(w)
			return publicationsPageData{}, false
		}
	}
	repositories, err := s.repositories(ctx)
	if err != nil {
		internalServerError(w)
		return publicationsPageData{}, false
	}
	data := publicationsPageData{
		AppName:            s.cfg.AppName,
		PageTitle:          "Status diagnostics",
		ActivePage:         "publications",
		CurrentUser:        currentUserFromSession(session),
		Publications:       publicationRowViews(repositories, publications),
		Attempts:           publicationAttemptRowViews(repositories, attempts),
		PublicationsTotal:  publicationsTotal,
		AttemptsTotal:      attemptsTotal,
		Query:              query,
		FilterRepositories: repositories,
		CSRFToken:          session.CSRFToken,
		CSRFField:          csrfFormField,
	}
	data.DesiredChips = filterChips(query.DesiredState, publicationDesiredFilterOptions, func(value string) string {
		next := query
		next.DesiredState = value
		next.DesiredPage = 1
		return publicationsURL(next)
	})
	data.AttemptChips = filterChips(query.AttemptResult, publicationAttemptFilterOptions, func(value string) string {
		next := query
		next.AttemptResult = value
		next.AttemptPage = 1
		return publicationsURL(next)
	})
	data.DesiredPager = paginateTable(publicationsTotal, query.DesiredPage, publicationsPageSize, func(page int) string {
		next := query
		next.DesiredPage = page
		return publicationsURL(next)
	})
	data.AttemptPager = paginateTable(attemptsTotal, query.AttemptPage, publicationsPageSize, func(page int) string {
		next := query
		next.AttemptPage = page
		return publicationsURL(next)
	})
	return data, true
}
