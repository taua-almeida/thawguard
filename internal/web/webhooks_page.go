package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

// webhooksPageSize caps one page of the delivery table; the pagination footer
// walks the rest of the history.
const webhooksPageSize = 20

// webhooksQuery is the /webhooks view selection: one processing-state chip,
// the shared repository select, one sortable column, and a 1-based page. The
// page is read-only, so the query never rides a mutating form.
type webhooksQuery struct {
	Processing   string
	RepositoryID int64
	Sort         tableSort
	Page         int
}

// webhookProcessingFilterOptions orders the processing chips; values double
// as the ?processing= values and, "all" aside, as the store's derived-state
// filter values.
var webhookProcessingFilterOptions = []filterChipOption{
	{Value: "all", Label: "All"},
	{Value: webhook.DeliveryProcessingReceived, Label: "Received"},
	{Value: webhook.DeliveryProcessingProcessing, Label: "Processing"},
	{Value: webhook.DeliveryProcessingProcessed, Label: "Processed"},
	{Value: webhook.DeliveryProcessingProcessedWithError, Label: "Processed with error"},
	{Value: webhook.DeliveryProcessingRetryableFailure, Label: "Retryable failure"},
}

func webhooksQueryFromValues(values url.Values) webhooksQuery {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(values.Get("repo")), 10, 64)
	if err != nil || repositoryID < 0 {
		repositoryID = 0
	}
	sort := tableSort{Field: "received", Dir: "desc"}
	if strings.TrimSpace(values.Get("sort")) == "processed" {
		sort.Field = "processed"
	}
	if strings.TrimSpace(values.Get("dir")) == "asc" {
		sort.Dir = "asc"
	}
	return webhooksQuery{
		Processing:   publicationFilterValue(values.Get("processing"), webhookProcessingFilterOptions),
		RepositoryID: repositoryID,
		Sort:         sort,
		Page:         publicationsPageValue(values.Get("page")),
	}
}

func webhooksURL(query webhooksQuery) string {
	params := url.Values{}
	if query.Processing != "" && query.Processing != "all" {
		params.Set("processing", query.Processing)
	}
	if query.RepositoryID > 0 {
		params.Set("repo", strconv.FormatInt(query.RepositoryID, 10))
	}
	if query.Sort.Field == "processed" {
		params.Set("sort", "processed")
	}
	if query.Sort.Dir == "asc" {
		params.Set("dir", "asc")
	}
	if query.Page > 1 {
		params.Set("page", strconv.Itoa(query.Page))
	}
	if len(params) == 0 {
		return "/webhooks"
	}
	return "/webhooks?" + params.Encode()
}

// webhookDeliveryOrder maps the applied sort to the store's closed ordering
// enum; the store treats anything unknown as received-desc anyway.
func webhookDeliveryOrder(sort tableSort) webhook.DeliveryOrder {
	switch {
	case sort.Field == "processed" && sort.Dir == "asc":
		return webhook.DeliveryOrderProcessedAsc
	case sort.Field == "processed":
		return webhook.DeliveryOrderProcessedDesc
	case sort.Dir == "asc":
		return webhook.DeliveryOrderReceivedAsc
	default:
		return webhook.DeliveryOrderReceivedDesc
	}
}

// webhookDeliveryProcessing derives one delivery's processing-state value,
// mirroring the store's ListPage partition over the same three columns.
func webhookDeliveryProcessing(delivery webhook.Delivery) string {
	switch {
	case delivery.ProcessedAt != nil && delivery.Error == "":
		return webhook.DeliveryProcessingProcessed
	case delivery.ProcessedAt != nil:
		return webhook.DeliveryProcessingProcessedWithError
	case delivery.ProcessingStartedAt != nil:
		return webhook.DeliveryProcessingProcessing
	case delivery.Error != "":
		return webhook.DeliveryProcessingRetryableFailure
	default:
		return webhook.DeliveryProcessingReceived
	}
}

// webhookProcessingBadge maps a delivery's derived processing state to its
// badge. A stuck "received" row is anomalous (the processor claims work
// quickly), so it renders as a warning rather than a neutral in-progress
// tone.
func webhookProcessingBadge(delivery webhook.Delivery) (label, tone, icon string) {
	switch webhookDeliveryProcessing(delivery) {
	case webhook.DeliveryProcessingProcessed:
		return "Processed", "success", "tg-i-check"
	case webhook.DeliveryProcessingProcessedWithError:
		return "Processed with error", "warning", "tg-i-warning"
	case webhook.DeliveryProcessingProcessing:
		return "Processing", "scheduled", "tg-i-schedule"
	case webhook.DeliveryProcessingRetryableFailure:
		return "Retryable failure", "danger", "tg-i-close"
	default:
		return "Received", "warning", "tg-i-warning"
	}
}

// webhookVerificationBadge maps signature verification to its badge. New rows
// are always verified (unverified deliveries are dropped before storage);
// "Not verified" only appears on historical rows from older databases.
func webhookVerificationBadge(verified bool) (label, tone, icon string) {
	if verified {
		return "Verified", "success", "tg-i-check"
	}
	return "Not verified", "warning", "tg-i-warning"
}

// webhookOptionalTime renders a nullable stored timestamp: an em dash for
// nil (the step has not happened), otherwise the shared UTC display pair.
func webhookOptionalTime(at *time.Time) (display, utc string) {
	if at == nil {
		return "—", ""
	}
	return publicationTime(*at)
}

// webhookRowView is one delivery in the diagnostics table, with every cell
// precomputed as curated display text. Error text arrives already sanitized
// from the receiver and is the only error-derived value rendered.
type webhookRowView struct {
	ReceivedAt        string
	ReceivedAtUTC     string
	Repository        string
	EventAction       string
	DeliveryIDShort   string
	DeliveryIDFull    string
	VerificationLabel string
	VerificationTone  string
	VerificationIcon  string
	ProcessingLabel   string
	ProcessingTone    string
	ProcessingIcon    string
	ClaimedAt         string
	ClaimedAtUTC      string
	ProcessedAt       string
	ProcessedAtUTC    string
	Error             string
}

// shortDeliveryID abbreviates a forge delivery UUID to its first eight
// characters; the full value stays available as a title.
func shortDeliveryID(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

func webhookRowViews(repositories []domain.Repository, deliveries []webhook.Delivery) []webhookRowView {
	repositoriesByID := repositoriesByID(repositories)
	rows := make([]webhookRowView, 0, len(deliveries))
	for _, delivery := range deliveries {
		eventAction := delivery.Event
		if delivery.Action != "" {
			eventAction += " · " + delivery.Action
		}
		row := webhookRowView{
			Repository:      publicationRepositoryLabel(repositoriesByID[delivery.RepositoryID], delivery.RepositoryID),
			EventAction:     eventAction,
			DeliveryIDShort: shortDeliveryID(delivery.DeliveryID),
			DeliveryIDFull:  delivery.DeliveryID,
			Error:           delivery.Error,
		}
		row.ReceivedAt, row.ReceivedAtUTC = publicationTime(delivery.ReceivedAt)
		row.VerificationLabel, row.VerificationTone, row.VerificationIcon = webhookVerificationBadge(delivery.Verified)
		row.ProcessingLabel, row.ProcessingTone, row.ProcessingIcon = webhookProcessingBadge(delivery)
		row.ClaimedAt, row.ClaimedAtUTC = webhookOptionalTime(delivery.ProcessingStartedAt)
		row.ProcessedAt, row.ProcessedAtUTC = webhookOptionalTime(delivery.ProcessedAt)
		rows = append(rows, row)
	}
	return rows
}

type webhooksPageData struct {
	AppName            string
	PageTitle          string
	Theme              string
	ActivePage         string
	CurrentUser        currentUserView
	Rows               []webhookRowView
	Total              int
	Query              webhooksQuery
	Chips              []filterChip
	Pager              *tablePager
	SortReceived       tableSortHeader
	SortProcessed      tableSortHeader
	HasFilters         bool
	FilterRepositories []domain.Repository
	CSRFToken          string
	CSRFField          string
	Toasts             []toastView
}

// loadWebhooksPageData assembles the /webhooks view model for the requested
// filters, sort, and page, clamping an out-of-range page back to the last
// one. Writes a 500 and returns ok=false on load failure. Callers must have
// already handled the nil-WebhookDeliveryStore 503 guard.
func (s *Server) loadWebhooksPageData(w http.ResponseWriter, r *http.Request, query webhooksQuery, session sessionState) (webhooksPageData, bool) {
	ctx := r.Context()
	scope := session.Grants.RepositoryReadScope()
	store := s.cfg.WebhookDeliveryStore
	processing := publicationStoreFilter(query.Processing)
	order := webhookDeliveryOrder(query.Sort)
	deliveries, total, err := store.ListPageForScope(ctx, scope, processing, query.RepositoryID, order, (query.Page-1)*webhooksPageSize, webhooksPageSize)
	if err != nil {
		internalServerError(w)
		return webhooksPageData{}, false
	}
	if len(deliveries) == 0 && total > 0 && query.Page > 1 {
		lastPage := (total + webhooksPageSize - 1) / webhooksPageSize
		query.Page = lastPage
		deliveries, total, err = store.ListPageForScope(ctx, scope, processing, query.RepositoryID, order, (lastPage-1)*webhooksPageSize, webhooksPageSize)
		if err != nil {
			internalServerError(w)
			return webhooksPageData{}, false
		}
	}
	repositories, err := s.repositories(ctx, scope)
	if err != nil {
		internalServerError(w)
		return webhooksPageData{}, false
	}
	data := webhooksPageData{
		AppName:            s.cfg.AppName,
		PageTitle:          "Webhook deliveries",
		ActivePage:         "webhooks",
		CurrentUser:        currentUserFromSession(session),
		Rows:               webhookRowViews(repositories, deliveries),
		Total:              total,
		Query:              query,
		HasFilters:         query.Processing != "all" || query.RepositoryID > 0,
		FilterRepositories: repositories,
		CSRFToken:          session.CSRFToken,
		CSRFField:          csrfFormField,
	}
	data.Chips = filterChips(query.Processing, webhookProcessingFilterOptions, func(value string) string {
		next := query
		next.Processing = value
		next.Page = 1
		return webhooksURL(next)
	})
	sortURL := func(sort tableSort) string {
		next := query
		next.Sort = sort
		next.Page = 1
		return webhooksURL(next)
	}
	data.SortReceived = sortHeader(query.Sort, "received", "Received", sortURL)
	data.SortProcessed = sortHeader(query.Sort, "processed", "Processed", sortURL)
	data.Pager = paginateTable(total, query.Page, webhooksPageSize, func(page int) string {
		next := query
		next.Page = page
		return webhooksURL(next)
	})
	return data, true
}
