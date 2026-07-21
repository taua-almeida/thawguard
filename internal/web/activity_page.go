package web

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

// activityPageSize caps one page of the activity table; the pagination
// footer walks the rest of the audit history.
const activityPageSize = 20

// activityQuery is the activity-table view selection: a filter chip and a
// 1-based page, traveling as ?filter=&page= on GETs. The page is read-only,
// so the query never rides a form.
type activityQuery struct {
	Filter string
	Page   int
}

// activityFilterOptions orders the chips; values double as the ?filter=
// values ("all" is normalized away). The facets are views, not partitions:
// an event may match more than one chip, and that is intentional.
var activityFilterOptions = []filterChipOption{
	{Value: "all", Label: "All"},
	{Value: "failures", Label: "Failures"},
	{Value: "freeze", Label: "Freeze control"},
	{Value: "repositories", Label: "Repositories"},
	{Value: "users", Label: "Users"},
}

// activityFilterValue normalizes a raw ?filter= value to a chip value.
// Unknown values fall back to "all" instead of erroring.
func activityFilterValue(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	for _, option := range activityFilterOptions {
		if option.Value == value {
			return value
		}
	}
	return "all"
}

// activityFilterActions translates a chip value into the exact action names
// the audit store filters on; nil means no filter. Failures collects every
// action whose curated definition carries the failed outcome class, so a new
// failure action joins the chip when its definition is added. The family
// chips group known actions by prefix at build time; the store still matches
// exact names only.
func activityFilterActions(filter string) []string {
	switch filter {
	case "failures":
		actions := make([]string, 0)
		for action, definition := range activityActionDefinitions {
			if definition.OutcomeClass == "failed" {
				actions = append(actions, action)
			}
		}
		sort.Strings(actions)
		return actions
	case "freeze":
		// "schedule." is matched from the string start, so it does not
		// double-count the "freeze_schedule." one-time window actions.
		return activityActionsWithPrefix("branch_freeze.", "freeze_schedule.", "schedule.", "thaw_exception.")
	case "repositories":
		return activityActionsWithPrefix("repository.")
	case "users":
		return activityActionsWithPrefix("user.")
	default:
		return nil
	}
}

func activityActionsWithPrefix(prefixes ...string) []string {
	actions := make([]string, 0)
	for _, action := range audit.KnownActions() {
		for _, prefix := range prefixes {
			if strings.HasPrefix(action, prefix) {
				actions = append(actions, action)
				break
			}
		}
	}
	return actions
}

func activityQueryFromValues(values url.Values) activityQuery {
	page, err := strconv.Atoi(strings.TrimSpace(values.Get("page")))
	if err != nil || page < 1 {
		page = 1
	}
	return activityQuery{Filter: activityFilterValue(values.Get("filter")), Page: page}
}

func activityURL(query activityQuery) string {
	params := url.Values{}
	if query.Filter != "" && query.Filter != "all" {
		params.Set("filter", query.Filter)
	}
	if query.Page > 1 {
		params.Set("page", strconv.Itoa(query.Page))
	}
	if len(params) == 0 {
		return "/activity"
	}
	return "/activity?" + params.Encode()
}

// activityOutcomeBadge maps a curated outcome to the table badge. "Changed"
// outcomes ride the info tone instead of their stored frozen class: on this
// system the frozen tone is reserved for actual freeze semantics, and a
// routine settings change should not read as a freeze event.
func activityOutcomeBadge(outcome, outcomeClass string) (tone, icon string) {
	switch outcomeClass {
	case "ok":
		return "success", "tg-i-check"
	case "warning":
		return "warning", "tg-i-warning"
	case "failed":
		return "danger", "tg-i-close"
	case "frozen":
		if outcome == "Changed" {
			return "info", ""
		}
		return "frozen", "tg-i-lock"
	case "pending":
		return "scheduled", "tg-i-schedule"
	default:
		return "warning", "tg-i-warning"
	}
}

// activityRowView is one audit event in the activity table: the shared
// curated view (also behind the dashboard's recent-activity card) plus the
// precomputed badge and the machine-readable timestamp.
type activityRowView struct {
	activityEventView
	CreatedAtUTC string // RFC3339 for <time datetime>; "" when unavailable
	BadgeTone    string
	BadgeIcon    string
}

func activityRowViews(repositories []domain.Repository, users []auth.User, events []audit.Event) []activityRowView {
	views := activityEventViews(repositories, users, events)
	rows := make([]activityRowView, 0, len(views))
	for i, view := range views {
		row := activityRowView{activityEventView: view}
		if !events[i].CreatedAt.IsZero() {
			row.CreatedAtUTC = events[i].CreatedAt.UTC().Format(time.RFC3339)
		}
		row.BadgeTone, row.BadgeIcon = activityOutcomeBadge(view.Outcome, view.OutcomeClass)
		rows = append(rows, row)
	}
	return rows
}

type activityPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	Rows        []activityRowView
	Total       int
	Filter      string
	Chips       []filterChip
	Pagination  *tablePager
	Query       activityQuery
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView
}

// loadActivityPageData assembles the /activity view model for the requested
// filter and page, clamping an out-of-range page back to the last one.
// Writes a 500 and returns ok=false on load failure. Callers must have
// already handled the nil-AuditStore 503 guard.
func (s *Server) loadActivityPageData(w http.ResponseWriter, r *http.Request, query activityQuery, session sessionState) (activityPageData, bool) {
	ctx := r.Context()
	actions := activityFilterActions(query.Filter)
	var events []audit.Event
	var total int
	// A chip whose family maps to zero known actions must match nothing; the
	// store reads an empty action list as "all actions", so never hand it one.
	if actions == nil || len(actions) > 0 {
		var err error
		events, total, err = s.cfg.AuditStore.ListPage(ctx, actions, (query.Page-1)*activityPageSize, activityPageSize)
		if err != nil {
			internalServerError(w)
			return activityPageData{}, false
		}
		if len(events) == 0 && total > 0 && query.Page > 1 {
			lastPage := (total + activityPageSize - 1) / activityPageSize
			query.Page = lastPage
			events, total, err = s.cfg.AuditStore.ListPage(ctx, actions, (lastPage-1)*activityPageSize, activityPageSize)
			if err != nil {
				internalServerError(w)
				return activityPageData{}, false
			}
		}
	}
	repositories, err := s.repositories(ctx)
	if err != nil {
		internalServerError(w)
		return activityPageData{}, false
	}
	var users []auth.User
	if s.cfg.AuthService != nil {
		users, err = s.cfg.AuthService.ListUsers(ctx)
		if err != nil {
			internalServerError(w)
			return activityPageData{}, false
		}
	}
	data := activityPageData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Activity",
		ActivePage:  "activity",
		CurrentUser: currentUserFromSession(session),
		Rows:        activityRowViews(repositories, users, events),
		Total:       total,
		Filter:      query.Filter,
		Query:       query,
		CSRFToken:   session.CSRFToken,
		CSRFField:   csrfFormField,
	}
	data.Chips = filterChips(query.Filter, activityFilterOptions, func(value string) string {
		return activityURL(activityQuery{Filter: value, Page: 1})
	})
	data.Pagination = paginateTable(total, query.Page, activityPageSize, func(page int) string {
		return activityURL(activityQuery{Filter: query.Filter, Page: page})
	})
	return data, true
}
