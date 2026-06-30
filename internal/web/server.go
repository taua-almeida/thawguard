package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

const defaultWebhookMaxBodyBytes int64 = 1 << 20

type Config struct {
	AppName                              string
	RepositoryStore                      RepositoryStore
	RepositorySecretEncryptionConfigured bool
	SetupCheckStore                      SetupCheckStore
	SetupCheckRunner                     SetupCheckRunner
	FreezeStore                          FreezeStore
	AuditStore                           AuditStore
	StatusDecisionStore                  StatusDecisionStore
	StatusPublicationStore               StatusPublicationStore
	WebhookRepositoryStore               WebhookRepositoryStore
	WebhookDeliveryStore                 WebhookDeliveryStore
	PullRequestWebhookProcessor          PullRequestWebhookProcessor
	WebhookMaxBodyBytes                  int64
}

type RepositoryStore interface {
	List(ctx context.Context) ([]domain.Repository, error)
	Create(ctx context.Context, params repository.CreateParams, actor domain.Actor) (domain.Repository, error)
	SetWebhookSecret(ctx context.Context, repositoryID int64, secret string, actor domain.Actor) (domain.Repository, error)
}

type SetupCheckStore interface {
	ListByRepository(ctx context.Context, repositoryID int64) ([]setupcheck.Check, error)
}

type SetupCheckRunner interface {
	Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error)
}

type FreezeStore interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
	CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error)
	End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type AuditStore interface {
	ListBySubjectType(ctx context.Context, subjectType string, limit int) ([]audit.Event, error)
}

type StatusDecisionStore interface {
	ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error)
	RunLocal(ctx context.Context, params statusresult.LocalDecisionParams) (statusresult.Result, error)
}

type StatusPublicationStore interface {
	ListRecent(ctx context.Context, limit int) ([]statuspublication.Publication, error)
}

type WebhookRepositoryStore interface {
	FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error)
	WebhookSecret(ctx context.Context, repositoryID int64) (string, bool, error)
}

type WebhookDeliveryStore interface {
	Record(ctx context.Context, params webhook.DeliveryRecordParams) (webhook.Delivery, error)
	MarkProcessed(ctx context.Context, id int64, params webhook.DeliveryProcessParams) (webhook.Delivery, error)
}

type PullRequestWebhookProcessor interface {
	Process(ctx context.Context, body []byte) (webhook.PullRequestProcessResult, error)
}

type repositoryView struct {
	Repository  domain.Repository
	SetupChecks []setupcheck.Check
}

type freezeView struct {
	Freeze     domain.BranchFreeze
	Repository domain.Repository
}

type freezeAuditView struct {
	Action       string
	SubjectID    string
	RepositoryID string
	Repository   domain.Repository
	Branch       string
	Status       string
	Reason       string
	Actor        string
	CreatedAt    string
}

type statusResultView struct {
	Result     statusresult.Result
	Repository domain.Repository
	CreatedAt  string
}

type statusPublicationView struct {
	Publication statuspublication.Publication
	Repository  domain.Repository
	CreatedAt   string
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	sessions *sessionStore
}

func NewServer(cfg Config) *Server {
	if cfg.AppName == "" {
		cfg.AppName = "Thawguard"
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), sessions: newSessionStore()}
	s.routes()
	return s
}

func (s *Server) Routes() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /repositories", s.handleRepositories)
	s.mux.HandleFunc("POST /repositories", s.handleCreateRepository)
	s.mux.HandleFunc("POST /repositories/webhook-secret", s.handleSetRepositoryWebhookSecret)
	s.mux.HandleFunc("POST /repositories/setup-check", s.handleRunRepositorySetupCheck)
	s.mux.HandleFunc("GET /freezes", s.handleFreezes)
	s.mux.HandleFunc("POST /freezes", s.handleCreateFreeze)
	s.mux.HandleFunc("POST /freezes/end", s.handleEndFreeze)
	s.mux.HandleFunc("POST /freezes/cancel", s.handleCancelFreeze)
	s.mux.HandleFunc("GET /decisions", s.handleDecisions)
	s.mux.HandleFunc("POST /decisions", s.handleCreateDecision)
	s.mux.HandleFunc("GET /publications", s.handlePublications)
	s.mux.HandleFunc("POST /webhooks/forgejo", s.handleForgejoWebhook)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	repositories, err := s.repositories(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	freezes, err := s.activeFreezes(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.render(w, dashboardTemplate, map[string]any{
		"AppName":           s.cfg.AppName,
		"RepositoryCount":   len(repositories),
		"ActiveFreezeCount": len(freezes),
	})
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, results, err := s.decisionPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), "", session.CSRFToken)
}

func (s *Server) handleCreateDecision(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	pullRequestIndex, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("pull_request_index")))
	if err != nil {
		pullRequestIndex = 0
	}
	_, err = s.cfg.StatusDecisionStore.RunLocal(r.Context(), statusresult.LocalDecisionParams{
		RepositoryID:     repositoryID,
		PullRequestIndex: pullRequestIndex,
		TargetBranch:     r.PostFormValue("target_branch"),
		HeadSHA:          r.PostFormValue("head_sha"),
	})
	if err != nil {
		if !statusresult.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, results, dataErr := s.decisionPageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/decisions", http.StatusSeeOther)
}

func (s *Server) handlePublications(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusPublicationStore == nil {
		http.Error(w, "status publication store is not configured", http.StatusServiceUnavailable)
		return
	}
	if _, err := s.sessions.getOrCreate(w, r); err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, publications, err := s.publicationPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderPublications(w, s.statusPublicationViews(repositories, publications))
}

func (s *Server) handleForgejoWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WebhookRepositoryStore == nil || s.cfg.WebhookDeliveryStore == nil || s.cfg.PullRequestWebhookProcessor == nil {
		http.Error(w, "webhook receiver is not configured", http.StatusServiceUnavailable)
		return
	}
	body, ok := s.readWebhookBody(w, r)
	if !ok {
		return
	}
	if len(body) == 0 || !webhookEventMayBePullRequest(r) {
		acceptedWebhook(w)
		return
	}

	event, err := webhook.ParsePullRequestEvent(body)
	if err != nil {
		acceptedWebhook(w)
		return
	}
	repo, found, err := s.cfg.WebhookRepositoryStore.FindActiveByRemote(r.Context(), repository.RemoteParams{Forge: event.Forge, BaseURL: event.BaseURL, Owner: event.Owner, Name: event.RepositoryName})
	if err != nil {
		internalServerError(w)
		return
	}
	if !found {
		acceptedWebhook(w)
		return
	}

	secret, found, err := s.cfg.WebhookRepositoryStore.WebhookSecret(r.Context(), repo.ID)
	if err != nil {
		if repositorysetup.IsConfigurationError(err) {
			acceptedWebhook(w)
			return
		}
		internalServerError(w)
		return
	}
	if !found || !webhook.VerifyHMACSHA256(secret, body, webhookSignatureHeader(r)) {
		acceptedWebhook(w)
		return
	}

	delivery, err := s.cfg.WebhookDeliveryStore.Record(r.Context(), webhook.DeliveryRecordParams{RepositoryID: repo.ID, DeliveryID: webhookDeliveryID(r, repo.ID, body), Event: "pull_request", Action: event.Action, Verified: true})
	if err != nil {
		if webhook.IsValidationError(err) {
			if delivery.ID != 0 && shouldRetryWebhookDelivery(delivery) {
				s.processVerifiedPullRequestWebhook(w, r, delivery, repo.ID, event.Action, body)
				return
			}
			acceptedWebhook(w)
			return
		}
		internalServerError(w)
		return
	}
	s.processVerifiedPullRequestWebhook(w, r, delivery, repo.ID, event.Action, body)
}

func (s *Server) processVerifiedPullRequestWebhook(w http.ResponseWriter, r *http.Request, delivery webhook.Delivery, repositoryID int64, action string, body []byte) {
	if !supportedPullRequestAction(action) {
		s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, "unsupported pull_request action")
		return
	}

	_, processErr := s.cfg.PullRequestWebhookProcessor.Process(r.Context(), body)
	if processErr != nil {
		deliveryError := sanitizedWebhookProcessError(processErr)
		if !s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, deliveryError) {
			return
		}
		if webhook.IsValidationError(processErr) {
			acceptedWebhook(w)
			return
		}
		internalServerError(w)
		return
	}
	_ = s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, "")
}

func (s *Server) readWebhookBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	limit := s.cfg.WebhookMaxBodyBytes
	if limit <= 0 {
		limit = defaultWebhookMaxBodyBytes
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "webhook payload too large", http.StatusRequestEntityTooLarge)
			return nil, false
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	return body, true
}

func (s *Server) markWebhookProcessed(w http.ResponseWriter, r *http.Request, deliveryID int64, repositoryID int64, action string, deliveryError string) bool {
	if _, err := s.cfg.WebhookDeliveryStore.MarkProcessed(r.Context(), deliveryID, webhook.DeliveryProcessParams{RepositoryID: repositoryID, Action: action, Error: deliveryError}); err != nil {
		internalServerError(w)
		return false
	}
	if deliveryError == "" || deliveryError == "unsupported pull_request action" {
		acceptedWebhook(w)
	}
	return true
}

func webhookEventMayBePullRequest(r *http.Request) bool {
	event := strings.ToLower(firstHeader(r, "X-Gitea-Event", "X-Forgejo-Event", "X-Gogs-Event"))
	return event == "" || event == "pull_request"
}

func webhookSignatureHeader(r *http.Request) string {
	return firstHeader(r, "X-Gitea-Signature", "X-Forgejo-Signature", "X-Hub-Signature-256")
}

func webhookDeliveryID(r *http.Request, repositoryID int64, body []byte) string {
	if deliveryID := firstHeader(r, "X-Gitea-Delivery", "X-Forgejo-Delivery", "X-Gogs-Delivery", "X-GitHub-Delivery"); deliveryID != "" {
		if validWebhookDeliveryID(deliveryID) {
			return deliveryID
		}
	}
	sum := sha256.Sum256(body)
	return "repo:" + strconv.FormatInt(repositoryID, 10) + ":sha256:" + hex.EncodeToString(sum[:])
}

func validWebhookDeliveryID(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func firstHeader(r *http.Request, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(r.Header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func supportedPullRequestAction(action string) bool {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "opened", "reopened", "synchronized", "synchronize", "edited", "closed":
		return true
	default:
		return false
	}
}

func shouldRetryWebhookDelivery(delivery webhook.Delivery) bool {
	return delivery.ProcessedAt == nil || delivery.Error == "webhook processing failed"
}

func sanitizedWebhookProcessError(err error) string {
	if webhook.IsValidationError(err) {
		return "webhook validation failed"
	}
	return "webhook processing failed"
}

func acceptedWebhook(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted\n"))
}

func (s *Server) handleRepositories(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}

	repositories, err := s.repositories(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	views, err := s.repositoryViews(r.Context(), repositories)
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderRepositories(w, views, "", session.CSRFToken)
}

func (s *Server) handleCreateRepository(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}

	_, err := s.cfg.RepositoryStore.Create(r.Context(), repository.CreateParams{
		Forge:         r.PostFormValue("forge"),
		BaseURL:       r.PostFormValue("base_url"),
		Owner:         r.PostFormValue("owner"),
		Name:          r.PostFormValue("name"),
		DefaultBranch: r.PostFormValue("default_branch"),
	}, session.auditActor())
	if err != nil {
		if !repository.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, listErr := s.repositories(r.Context())
		if listErr != nil {
			internalServerError(w)
			return
		}
		views, viewErr := s.repositoryViews(r.Context(), repositories)
		if viewErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderRepositories(w, views, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleSetRepositoryWebhookSecret(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.cfg.RepositorySecretEncryptionConfigured {
		http.Error(w, "webhook secret encryption is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	_, err = s.cfg.RepositoryStore.SetWebhookSecret(r.Context(), repositoryID, r.PostFormValue("webhook_secret"), session.auditActor())
	if err != nil {
		if repositorysetup.IsConfigurationError(err) {
			http.Error(w, "webhook secret encryption is not configured", http.StatusServiceUnavailable)
			return
		}
		if !repositorysetup.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, listErr := s.repositories(r.Context())
		if listErr != nil {
			internalServerError(w)
			return
		}
		views, viewErr := s.repositoryViews(r.Context(), repositories)
		if viewErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderRepositories(w, views, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleFreezes(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}
	repositories, freezes, auditEvents, err := s.freezePageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, "", session.CSRFToken)
}

func (s *Server) handleCreateFreeze(w http.ResponseWriter, r *http.Request) {
	if s.cfg.FreezeStore == nil {
		http.Error(w, "freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}

	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	_, err = s.cfg.FreezeStore.CreateActive(r.Context(), freeze.CreateParams{
		RepositoryID: repositoryID,
		Branch:       r.PostFormValue("branch"),
		Reason:       r.PostFormValue("reason"),
	}, session.auditActor())
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, freezes, auditEvents, dataErr := s.freezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/freezes", http.StatusSeeOther)
}

func (s *Server) handleEndFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.endFreeze)
}

func (s *Server) handleCancelFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.cancelFreeze)
}

func (s *Server) handleCloseFreeze(w http.ResponseWriter, r *http.Request, closeFreeze func(context.Context, int64, domain.Actor) error) {
	if s.cfg.FreezeStore == nil {
		http.Error(w, "freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}

	freezeID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("freeze_id")), 10, 64)
	if err != nil {
		freezeID = 0
	}
	if err := closeFreeze(r.Context(), freezeID, session.auditActor()); err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, freezes, auditEvents, dataErr := s.freezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/freezes", http.StatusSeeOther)
}

func (s *Server) endFreeze(ctx context.Context, id int64, actor domain.Actor) error {
	_, err := s.cfg.FreezeStore.End(ctx, id, actor)
	return err
}

func (s *Server) cancelFreeze(ctx context.Context, id int64, actor domain.Actor) error {
	_, err := s.cfg.FreezeStore.Cancel(ctx, id, actor)
	return err
}

func (s *Server) handleRunRepositorySetupCheck(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SetupCheckRunner == nil {
		http.Error(w, "setup check runner is not configured", http.StatusServiceUnavailable)
		return
	}
	_, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}

	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil || repositoryID <= 0 {
		http.Error(w, "invalid repository id", http.StatusBadRequest)
		return
	}
	repo, found, err := s.repositoryByID(r.Context(), repositoryID)
	if err != nil {
		internalServerError(w)
		return
	}
	if !found {
		http.Error(w, "repository not found", http.StatusNotFound)
		return
	}

	if _, err := s.cfg.SetupCheckRunner.Run(r.Context(), repo); err != nil {
		http.Error(w, "setup check failed", http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) requireRepositoryManagerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	session, ok := s.sessions.get(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if !session.Role.CanManageRepositories() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return sessionState{}, false
	}
	if !constantTimeTokenEqual(r.PostForm.Get(csrfFormField), session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	return session, true
}

func (s *Server) requireFreezerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	session, ok := s.sessions.get(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if !session.Role.CanFreeze() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return sessionState{}, false
	}
	if !constantTimeTokenEqual(r.PostForm.Get(csrfFormField), session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	return session, true
}

func (s *Server) repositories(ctx context.Context) ([]domain.Repository, error) {
	if s.cfg.RepositoryStore == nil {
		return nil, nil
	}
	return s.cfg.RepositoryStore.List(ctx)
}

func (s *Server) statusResults(ctx context.Context) ([]statusresult.Result, error) {
	if s.cfg.StatusDecisionStore == nil {
		return nil, nil
	}
	return s.cfg.StatusDecisionStore.ListRecent(ctx, 25)
}

func (s *Server) statusPublications(ctx context.Context) ([]statuspublication.Publication, error) {
	if s.cfg.StatusPublicationStore == nil {
		return nil, nil
	}
	return s.cfg.StatusPublicationStore.ListRecent(ctx, 25)
}

func (s *Server) publicationPageData(ctx context.Context) ([]domain.Repository, []statuspublication.Publication, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, err
	}
	publications, err := s.statusPublications(ctx)
	if err != nil {
		return nil, nil, err
	}
	return repositories, publications, nil
}

func (s *Server) decisionPageData(ctx context.Context) ([]domain.Repository, []statusresult.Result, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, err
	}
	results, err := s.statusResults(ctx)
	if err != nil {
		return nil, nil, err
	}
	return repositories, results, nil
}

func (s *Server) statusResultViews(repositories []domain.Repository, results []statusresult.Result) []statusResultView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusResultView, 0, len(results))
	for _, result := range results {
		views = append(views, statusResultView{Result: result, Repository: repositoriesByID[result.RepositoryID], CreatedAt: result.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func (s *Server) statusPublicationViews(repositories []domain.Repository, publications []statuspublication.Publication) []statusPublicationView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusPublicationView, 0, len(publications))
	for _, publication := range publications {
		views = append(views, statusPublicationView{Publication: publication, Repository: repositoriesByID[publication.RepositoryID], CreatedAt: publication.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func (s *Server) activeFreezes(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s.cfg.FreezeStore == nil {
		return nil, nil
	}
	return s.cfg.FreezeStore.ListActive(ctx)
}

func (s *Server) freezePageData(ctx context.Context) ([]domain.Repository, []domain.BranchFreeze, []freezeAuditView, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	freezes, err := s.activeFreezes(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	auditEvents, err := s.freezeAuditViews(ctx, repositories)
	if err != nil {
		return nil, nil, nil, err
	}
	return repositories, freezes, auditEvents, nil
}

func (s *Server) freezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze) []freezeView {
	repositoriesByID := make(map[int64]domain.Repository, len(repositories))
	for _, repo := range repositories {
		repositoriesByID[repo.ID] = repo
	}
	views := make([]freezeView, 0, len(freezes))
	for _, freeze := range freezes {
		views = append(views, freezeView{Freeze: freeze, Repository: repositoriesByID[freeze.RepositoryID]})
	}
	return views
}

func (s *Server) freezeAuditViews(ctx context.Context, repositories []domain.Repository) ([]freezeAuditView, error) {
	if s.cfg.AuditStore == nil {
		return nil, nil
	}
	events, err := s.cfg.AuditStore.ListBySubjectType(ctx, audit.SubjectTypeBranchFreeze, 50)
	if err != nil {
		return nil, err
	}
	repositoriesByID := repositoriesByID(repositories)
	views := make([]freezeAuditView, 0, len(events))
	for _, event := range events {
		if !isFreezeAuditAction(event.Action) {
			continue
		}
		view := freezeAuditView{
			Action:    event.Action,
			SubjectID: event.SubjectID,
			CreatedAt: event.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		}
		var details map[string]string
		if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err == nil {
			view.RepositoryID = details["repository_id"]
			view.Branch = details["branch"]
			view.Status = details["status"]
			view.Reason = details["reason"]
			view.Actor = actorLabel(details["actor_kind"], details["actor_role"])
			if repositoryID, err := strconv.ParseInt(details["repository_id"], 10, 64); err == nil {
				view.Repository = repositoriesByID[repositoryID]
			}
		}
		views = append(views, view)
	}
	return views, nil
}

func isFreezeAuditAction(action string) bool {
	switch action {
	case audit.ActionBranchFreezeCreated, audit.ActionBranchFreezeEnded, audit.ActionBranchFreezeCancelled:
		return true
	default:
		return false
	}
}

func repositoriesByID(repositories []domain.Repository) map[int64]domain.Repository {
	byID := make(map[int64]domain.Repository, len(repositories))
	for _, repo := range repositories {
		byID[repo.ID] = repo
	}
	return byID
}

func actorLabel(kind string, role string) string {
	kind = strings.TrimSpace(kind)
	role = strings.TrimSpace(role)
	if kind == "" && role == "" {
		return "unknown"
	}
	if role == "" {
		return kind
	}
	if kind == "" {
		return role
	}
	return kind + " (" + role + ")"
}

func (s *Server) repositoryByID(ctx context.Context, id int64) (domain.Repository, bool, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return domain.Repository{}, false, err
	}
	for _, repo := range repositories {
		if repo.ID == id {
			return repo, true, nil
		}
	}
	return domain.Repository{}, false, nil
}

func (s *Server) repositoryViews(ctx context.Context, repositories []domain.Repository) ([]repositoryView, error) {
	views := make([]repositoryView, 0, len(repositories))
	for _, repo := range repositories {
		view := repositoryView{Repository: repo}
		if s.cfg.SetupCheckStore != nil {
			checks, err := s.cfg.SetupCheckStore.ListByRepository(ctx, repo.ID)
			if err != nil {
				return nil, err
			}
			view.SetupChecks = latestSetupChecks(checks)
		}
		views = append(views, view)
	}
	return views, nil
}

func latestSetupChecks(checks []setupcheck.Check) []setupcheck.Check {
	if len(checks) == 0 {
		return nil
	}
	checkedAt := checks[0].CheckedAt
	latest := make([]setupcheck.Check, 0, len(checks))
	for _, check := range checks {
		if !check.CheckedAt.Equal(checkedAt) {
			break
		}
		latest = append(latest, check)
	}
	return latest
}

func (s *Server) renderRepositories(w http.ResponseWriter, views []repositoryView, formError string, csrfToken string) {
	s.render(w, repositoriesTemplate, map[string]any{
		"AppName":                           s.cfg.AppName,
		"RepositoryViews":                   views,
		"FormError":                         formError,
		"CSRFToken":                         csrfToken,
		"RequiredContext":                   domain.RequiredStatusContext,
		"SetupSteps":                        setupcheck.ManualSetupSteps(),
		"WebhookSecretEncryptionConfigured": s.cfg.RepositorySecretEncryptionConfigured,
	})
}

func (s *Server) renderFreezes(w http.ResponseWriter, repositories []domain.Repository, freezes []freezeView, auditEvents []freezeAuditView, formError string, csrfToken string) {
	s.render(w, freezesTemplate, map[string]any{
		"AppName":      s.cfg.AppName,
		"Repositories": repositories,
		"Freezes":      freezes,
		"AuditEvents":  auditEvents,
		"FormError":    formError,
		"CSRFToken":    csrfToken,
	})
}

func (s *Server) renderDecisions(w http.ResponseWriter, repositories []domain.Repository, results []statusResultView, formError string, csrfToken string) {
	s.render(w, decisionsTemplate, map[string]any{
		"AppName":         s.cfg.AppName,
		"Repositories":    repositories,
		"Results":         results,
		"FormError":       formError,
		"CSRFToken":       csrfToken,
		"RequiredContext": domain.RequiredStatusContext,
	})
}

func (s *Server) renderPublications(w http.ResponseWriter, publications []statusPublicationView) {
	s.render(w, publicationsTemplate, map[string]any{
		"AppName":      s.cfg.AppName,
		"Publications": publications,
	})
}

func (s *Server) render(w http.ResponseWriter, source string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, err := template.New("page").Parse(source)
	if err != nil {
		internalServerError(w)
		return
	}
	_ = tpl.Execute(w, data)
}

func internalServerError(w http.ResponseWriter) {
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

const pageHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .AppName }}</title>
  <link rel="stylesheet" href="/static/thawguard.css">
</head>
<body>`

const pageFoot = `</body></html>`

const dashboardTemplate = pageHead + `
  <main class="shell">
    <section class="hero">
      <div class="pixel-shield" aria-hidden="true"></div>
      <p class="eyebrow">Freeze branches. Thaw exceptions.</p>
      <h1>{{ .AppName }} foundation is running</h1>
      <p>{{ .RepositoryCount }} repositories are configured. {{ .ActiveFreezeCount }} active branch freezes are recorded locally.</p>
      <p class="actions"><a class="button" href="/repositories">Manage repositories</a> <a class="button" href="/freezes">Manage freezes</a> <a class="button" href="/decisions">Preview decisions</a> <a class="button" href="/publications">Publication intents</a></p>
    </section>
  </main>` + pageFoot

const publicationsTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Local publication intents</p>
      <h1>Status publication intents</h1>
      <p class="warning">These are local records of statuses Thawguard would publish later. No status has been posted to Forgejo/Codeberg from this page or from the current local publisher.</p>
      <p class="warning">Bootstrap sessions are for local development only. Do not expose publication-intent visibility on a network until real local auth is configured.</p>
      <p>Use this page to inspect the status context, state, head SHA, and description generated by the local recomputation pipeline before live status posting is wired.</p>
    </section>

    <section class="panel">
      <h2>Recent local publication intents</h2>
      {{ if .Publications }}
      <table>
        <thead><tr><th>When</th><th>Repository</th><th>PR</th><th>Target branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Mode</th><th>Description</th></tr></thead>
        <tbody>
        {{ range .Publications }}
          <tr>
            <td>{{ .CreatedAt }}</td>
            <td>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Publication.RepositoryID }}{{ end }}</td>
            <td>#{{ .Publication.PullRequestIndex }}</td>
            <td>{{ .Publication.TargetBranch }}</td>
            <td><code>{{ .Publication.HeadSHA }}</code></td>
            <td><code>{{ .Publication.Context }}</code></td>
            <td><span class="status status-{{ .Publication.State }}">{{ .Publication.State }}</span></td>
            <td><code>{{ .Publication.DeliveryMode }}</code></td>
            <td>{{ .Publication.Description }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No local publication intents yet.</p>
      {{ end }}
    </section>
  </main>` + pageFoot

const repositoriesTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
	    <section class="panel">
	      <p class="eyebrow">Repositories</p>
	      <h1>Add repository</h1>
	      <p class="warning">Bootstrap sessions are for local development only. Do not expose this server on a network until real local auth is configured.</p>
	      <p>Start with Forgejo/Codeberg repositories. Manual setup must require the exact status context <code>{{ .RequiredContext }}</code>. The signed webhook receiver is <code>/webhooks/forgejo</code>; current delivery handling recomputes local records and does not post live forge statuses.</p>
        {{ if not .WebhookSecretEncryptionConfigured }}<p class="warning">Webhook secret storage is disabled until <code>THAWGUARD_SECRET_KEY</code> is configured. Existing repository setup and local freeze flows remain available.</p>{{ end }}
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      <form method="post" action="/repositories" class="form-grid">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label>Forge <input name="forge" value="forgejo"></label>
        <label>Base URL <input name="base_url" value="https://codeberg.org"></label>
        <label>Owner <input name="owner" required></label>
        <label>Repository <input name="name" required></label>
        <label>Default branch <input name="default_branch" value="main"></label>
        <button type="submit">Add repository</button>
      </form>
    </section>

	    <section class="panel">
	      <h2>Configured repositories</h2>
	      <p class="muted">Local setup checks are placeholders until live Forgejo/Codeberg verification is configured. They support setup workflow visibility, not hard enforcement.</p>
	      {{ if .RepositoryViews }}
      <table>
	        <thead><tr><th>Repository</th><th>Forge</th><th>Default branch</th><th>Required context</th><th>Webhook secret</th><th>Setup health</th><th>Actions</th></tr></thead>
        <tbody>
        {{ range .RepositoryViews }}
          <tr>
            <td>{{ .Repository.FullName }}</td>
            <td>{{ .Repository.Forge }}</td>
             <td>{{ .Repository.DefaultBranch }}</td>
             <td><code>` + domain.RequiredStatusContext + `</code></td>
             <td>{{ if .Repository.HasWebhookSecret }}<span class="status status-ok">configured</span>{{ else }}<span class="status status-warning">not configured</span>{{ end }}</td>
             <td>
              {{ if .SetupChecks }}
                <ul class="setup-checks">
                {{ range .SetupChecks }}
                  <li><strong>{{ .Result.Name }}</strong>: <span class="status status-{{ .Result.Status }}">{{ .Result.Status }}</span><br><small>{{ .Result.Description }}{{ if .Result.Remediation }} {{ .Result.Remediation }}{{ end }}</small></li>
                {{ end }}
                </ul>
              {{ else }}
                <span class="muted">No setup checks yet.</span>
              {{ end }}
            </td>
             <td>
              {{ if $.WebhookSecretEncryptionConfigured }}
              <form method="post" action="/repositories/webhook-secret">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
                <label>Set or rotate webhook secret for signed delivery <input type="password" name="webhook_secret" minlength="16" maxlength="512" autocomplete="new-password" required></label>
                <button type="submit">Save webhook secret</button>
              </form>
              {{ else }}
              <p class="muted">Set <code>THAWGUARD_SECRET_KEY</code> to save webhook secrets.</p>
              {{ end }}
              <form method="post" action="/repositories/setup-check">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
				<button type="submit">Record local setup placeholder</button>
			  </form>
            </td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No repositories configured yet.</p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Manual setup checklist</h2>
      <ol>{{ range .SetupSteps }}<li>{{ . }}</li>{{ end }}</ol>
    </section>
  </main>` + pageFoot

const freezesTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Branch freezes</p>
      <h1>Create active freeze</h1>
      <p class="warning">Bootstrap sessions are for local development only. Do not expose freeze controls on a network until real local auth is configured.</p>
      <p>Record a cooperative branch freeze locally. Signed webhook recomputation updates local records; live forge status posting will be wired in a later slice.</p>
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      {{ if .Repositories }}
      <form method="post" action="/freezes" class="form-grid">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label>Repository
          <select name="repository_id" required>
          {{ range .Repositories }}<option value="{{ .ID }}">{{ .FullName }} — default {{ .DefaultBranch }}</option>{{ end }}
          </select>
        </label>
        <label>Branch <input name="branch" placeholder="main" required></label>
        <label>Reason <input name="reason" placeholder="QA freeze, release window, incident response" required></label>
        <button type="submit">Freeze branch</button>
      </form>
      {{ else }}
      <p>No repositories configured yet. Add a repository before creating a freeze.</p>
      <p><a class="button" href="/repositories">Add repository</a></p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Active freezes</h2>
      {{ if .Freezes }}
      <table>
        <thead><tr><th>Repository</th><th>Branch</th><th>Status</th><th>Reason</th><th>Actions</th></tr></thead>
        <tbody>
        {{ range .Freezes }}
          <tr>
            <td>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</td>
            <td>{{ .Freeze.Branch }}</td>
            <td><span class="status status-frozen">{{ .Freeze.Status }}</span></td>
            <td>{{ .Freeze.Reason }}</td>
            <td class="actions">
              <form method="post" action="/freezes/end">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                <button type="submit">End freeze</button>
              </form>
              <form method="post" action="/freezes/cancel">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                <button type="submit" class="secondary">Cancel</button>
              </form>
            </td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No active freezes yet.</p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Recent freeze audit events</h2>
      {{ if .AuditEvents }}
      <table>
        <thead><tr><th>When</th><th>Action</th><th>Repository</th><th>Branch</th><th>Status</th><th>Actor</th><th>Reason</th></tr></thead>
        <tbody>
        {{ range .AuditEvents }}
          <tr>
            <td>{{ .CreatedAt }}</td>
            <td><code>{{ .Action }}</code></td>
            <td>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .RepositoryID }}{{ end }}</td>
            <td>{{ .Branch }}</td>
            <td>{{ .Status }}</td>
            <td>{{ .Actor }}</td>
            <td>{{ .Reason }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No freeze audit events yet.</p>
      {{ end }}
    </section>
  </main>` + pageFoot

const decisionsTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Local status preview</p>
      <h1>Compute PR decision</h1>
      <p class="warning">This is a local preview only. Thawguard records the computed status result locally and does not post to Forgejo/Codeberg.</p>
      <p class="warning">Bootstrap sessions are for local development only. Do not expose decision previews on a network until real local auth is configured.</p>
      <p>Use this to verify the policy result for the required status context <code>{{ .RequiredContext }}</code> before live status posting is wired.</p>
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      {{ if .Repositories }}
      <form method="post" action="/decisions" class="form-grid">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label>Repository
          <select name="repository_id" required>
          {{ range .Repositories }}<option value="{{ .ID }}">{{ .FullName }}</option>{{ end }}
          </select>
        </label>
        <label>PR number <input name="pull_request_index" inputmode="numeric" placeholder="42" required></label>
        <label>Target branch <input name="target_branch" placeholder="main" required></label>
        <label>Head SHA <input name="head_sha" placeholder="abc123" required></label>
        <button type="submit">Compute local decision</button>
      </form>
      {{ else }}
      <p>No repositories configured yet. Add a repository before computing decisions.</p>
      <p><a class="button" href="/repositories">Add repository</a></p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Recent local status results</h2>
      {{ if .Results }}
      <table>
        <thead><tr><th>When</th><th>Repository</th><th>PR</th><th>Target branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Description</th></tr></thead>
        <tbody>
        {{ range .Results }}
          <tr>
            <td>{{ .CreatedAt }}</td>
            <td>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Result.RepositoryID }}{{ end }}</td>
            <td>#{{ .Result.PullRequestIndex }}</td>
            <td>{{ .Result.TargetBranch }}</td>
            <td><code>{{ .Result.HeadSHA }}</code></td>
            <td><code>{{ .Result.Context }}</code></td>
            <td><span class="status status-{{ .Result.State }}">{{ .Result.State }}</span></td>
            <td>{{ .Result.Description }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No local status results yet.</p>
      {{ end }}
    </section>
  </main>` + pageFoot
