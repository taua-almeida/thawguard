package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/freeze"
	"github.com/taua-almeida/thawguard/internal/jobs"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/repositorysetup"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/webhook"
	webassets "github.com/taua-almeida/thawguard/web"
)

const defaultWebhookMaxBodyBytes int64 = 1 << 20
const defaultAuditLogLimit = 25
const maxAuditLogLimit = 500
const scheduledFreezeReasonMaxLength = 500

type Config struct {
	AppName                              string
	RepositoryStore                      RepositoryStore
	RepositorySecretEncryptionConfigured bool
	SetupCheckStore                      SetupCheckStore
	SetupCheckRunner                     SetupCheckRunner
	FreezeStore                          FreezeStore
	ScheduledFreezeStore                 ScheduledFreezeStore
	AuditStore                           AuditStore
	// ThawExceptionStore feeds the dashboard's active-thaws stat; optional
	// (the stat degrades to zero when absent).
	ThawExceptionStore          ThawExceptionStore
	StatusDecisionStore         StatusDecisionStore
	StatusPublicationStore      StatusPublicationStore
	WebhookRepositoryStore      WebhookRepositoryStore
	WebhookDeliveryStore        WebhookDeliveryStore
	PullRequestWebhookProcessor PullRequestWebhookProcessor
	WebhookMaxBodyBytes         int64
	AuthService                 AuthService
	// PullRequestStore feeds the freeze-impact preview from the
	// webhook-synced local cache; optional (the preview degrades to the
	// zero state when absent).
	PullRequestStore       PullRequestStore
	EnforcementService     EnforcementService
	ReconciliationJobStore ReconciliationJobStore
	// DevMode registers development-only routes (the component gallery
	// under /dev/preview). Must stay false in production.
	DevMode bool
}

// EnforcementService performs the explicit admin transitions of the
// repository enforcement lifecycle. Every transition re-runs the read-only
// readiness checks instead of trusting stored evidence; verification,
// activation, and recovery additionally post the controlled thawguard/setup
// status, while reconciliation proves posting by republishing the real
// policy statuses.
type EnforcementService interface {
	VerifyStatusPosting(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error)
	ActivateEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error)
	DeactivateEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error)
	ReconcileEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error)
	RecoverEnforcement(ctx context.Context, repositoryID int64, actor domain.Actor) (domain.Repository, error)
}

type ReconciliationJobStore interface {
	ListReconciliations(ctx context.Context) ([]jobs.Job, error)
}

type AuthService interface {
	HasUsers(ctx context.Context) (bool, error)
	CreateFirstAdmin(ctx context.Context, params auth.CreateFirstAdminParams) (auth.Session, error)
	Login(ctx context.Context, params auth.LoginParams) (auth.Session, error)
	SessionByID(ctx context.Context, id string) (auth.Session, bool, error)
	Logout(ctx context.Context, id string) error
	ListUsers(ctx context.Context) ([]auth.User, error)
	CreateUser(ctx context.Context, params auth.CreateUserParams) (auth.User, error)
	UpdateUserRoles(ctx context.Context, params auth.UpdateUserRolesParams) (auth.User, error)
	DisableUser(ctx context.Context, actorUserID int64, userID int64) (auth.User, error)
	EnableUser(ctx context.Context, actorUserID int64, userID int64) (auth.User, error)
	ChangePassword(ctx context.Context, params auth.ChangePasswordParams) (auth.Session, error)
	ResetPassword(ctx context.Context, params auth.ResetPasswordParams) error
}

type RepositoryStore interface {
	List(ctx context.Context) ([]domain.Repository, error)
	Create(ctx context.Context, params repository.CreateParams, actor domain.Actor) (domain.Repository, error)
	SetWebhookSecret(ctx context.Context, repositoryID int64, secret string, actor domain.Actor) (domain.Repository, error)
	SetStatusToken(ctx context.Context, repositoryID int64, token string, actor domain.Actor) (domain.Repository, error)
	ListBranches(ctx context.Context, repositoryID int64) ([]domain.RepositoryBranch, error)
	AddBranch(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) (domain.RepositoryBranch, error)
	RemoveBranch(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error
}

type SetupCheckStore interface {
	ListByRepository(ctx context.Context, repositoryID int64) ([]setupcheck.Check, error)
}

type SetupCheckRunner interface {
	Run(ctx context.Context, repo domain.Repository, actor domain.Actor) ([]setupcheck.Result, error)
}

// PullRequestStore reads the webhook-synced pull request cache for the
// freeze-impact preview. It is a local lookup, never a live forge call.
type PullRequestStore interface {
	ListOpenByTargetBranch(ctx context.Context, repositoryID int64, targetBranch string) ([]domain.PullRequest, error)
	// Get and ListOpenByHead read the webhook-synced local cache, never the
	// live forge; the eligibility preview depends on that.
	Get(ctx context.Context, repositoryID int64, index int) (domain.PullRequest, error)
	ListOpenByHead(ctx context.Context, repositoryID int64, headSHA string) ([]domain.PullRequest, error)
}

type FreezeStore interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
	CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error)
	End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type ScheduledFreezeStore interface {
	ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	ListScheduledPage(ctx context.Context, status domain.BranchFreezeStatus, offset, limit int) ([]domain.BranchFreeze, int, error)
	CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error)
	EditScheduled(ctx context.Context, params freeze.EditScheduleParams, actor domain.Actor) (domain.BranchFreeze, error)
	CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	StartScheduledNow(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type AuditStore interface {
	List(ctx context.Context, limit int) ([]audit.Event, error)
	ListPage(ctx context.Context, actions []string, offset, limit int) ([]audit.Event, int, error)
}

type ThawExceptionStore interface {
	CountActive(ctx context.Context) (int, error)
}

type StatusDecisionStore interface {
	ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error)
	ListDecisionsPage(ctx context.Context, state domain.CommitStatusState, repositoryID int64, offset, limit int) ([]statusresult.Result, int, error)
	ApproveThaw(ctx context.Context, params statusresult.ThawApprovalParams, actor domain.Actor) (statusresult.ThawApprovalOutcome, error)
}

type StatusPublicationStore interface {
	ListRecent(ctx context.Context, limit int) ([]statuspublication.Publication, error)
	ListRecentAttempts(ctx context.Context, limit int) ([]statuspublication.Attempt, error)
}

type WebhookRepositoryStore interface {
	FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error)
	WebhookSecret(ctx context.Context, repositoryID int64) (string, bool, error)
}

type WebhookDeliveryStore interface {
	ListRecent(ctx context.Context, limit int) ([]webhook.Delivery, error)
	Record(ctx context.Context, params webhook.DeliveryRecordParams) (webhook.Delivery, error)
	ClaimForProcessing(ctx context.Context, id int64) (webhook.Delivery, bool, error)
	MarkProcessed(ctx context.Context, id int64, params webhook.DeliveryProcessParams) (webhook.Delivery, error)
	MarkProcessingFailed(ctx context.Context, id int64, message string, processingStartedAt time.Time) (webhook.Delivery, error)
}

type PullRequestWebhookProcessor interface {
	Process(ctx context.Context, body []byte) (webhook.PullRequestProcessResult, error)
}

// managedBranchOption is one (repository, exact branch) choice for the freeze
// and scheduled-freeze forms; POST validation stays authoritative.
type managedBranchOption struct {
	RepositoryID int64
	Name         string
}

type scheduledFreezeView struct {
	Freeze           domain.BranchFreeze
	Repository       domain.Repository
	StartsAt         string
	StartsAtUTC      string
	PlannedEndsAt    string
	PlannedEndsAtUTC string
	EndedAt          string
	StatusLabel      string
	StateClass       string
	// StatusText/BadgeTone/BadgeIcon drive the /scheduled-freezes status
	// badge (Upcoming=scheduled, Active=frozen, Completed/Cancelled=neutral);
	// StatusLabel/StateClass remain for the dashboard's legacy tone mapping.
	StatusText string
	BadgeTone  string
	BadgeIcon  string
	// SubLine* render the muted "Ended {t}" / "Cancelled {t}" line under the
	// badge for closed windows; empty otherwise.
	SubLineLabel          string
	SubLineTime           string
	SubLineUTC            string
	CanCancel             bool
	CanEdit               bool
	CanStartNow           bool
	StartNowBlockedReason string
	EditOpen              bool
	EditSubmitted         bool
	EditReason            string
	EditStartsAt          string
	EditPlannedEndsAt     string
}

// scheduledFreezePageState carries /scheduled-freezes request state across
// renders: form/action errors, PRG notices, the submitted create form, the
// filter/page selection, and an in-flight edit panel's submitted values.
type scheduledFreezePageState struct {
	FormError         string
	ActionError       string
	Notice            string
	NoticeTone        string
	ScheduleForm      scheduledFreezeFormState
	Query             scheduledFreezesQuery
	EditScheduleID    int64
	EditReason        string
	EditStartsAt      string
	EditPlannedEndsAt string
}

type statusPublicationView struct {
	Publication statuspublication.Publication
	Repository  domain.Repository
	CreatedAt   string
	UpdatedAt   string
}

type statusPublicationAttemptView struct {
	Attempt     statuspublication.Attempt
	Repository  domain.Repository
	AttemptedAt string
}

type webhookDeliveryView struct {
	Delivery               webhook.Delivery
	Repository             domain.Repository
	ReceivedAt             string
	ProcessingStartedAt    string
	ProcessedAt            string
	ProcessingState        string
	ProcessingStateClass   string
	VerificationState      string
	VerificationStateClass string
}

type activityEventView struct {
	CreatedAt    string
	Actor        string
	ActionLabel  string
	Target       string
	Outcome      string
	OutcomeClass string
	Detail       string
}

type currentUserView struct {
	Email                 string
	DisplayName           string
	RoleLabel             string
	CanChangePassword     bool
	IsAdmin               bool
	CanManageRepositories bool
	CanFreeze             bool
	CanThaw               bool
}

type userView struct {
	User          auth.User
	RoleLabel     string
	CreatedAt     string
	IsSelf        bool
	RoleOptions   []roleOption
	ResetFormOpen bool
}

// usersPageState carries users-page form state across validation re-renders.
// RoleFormUserID/RoleFormRoles preserve a submitted per-user role edit and
// ResetFormUserID keeps a failed reset form expanded on its row; password
// values are intentionally never part of this state.
type usersPageState struct {
	FormError       string
	CreateRoles     auth.RoleSet
	RoleFormUserID  int64
	RoleFormRoles   auth.RoleSet
	ResetFormUserID int64
}

type roleOption struct {
	Value    string
	Label    string
	Selected bool
}

type auditLogControls struct {
	Limit           int
	Sort            string
	Direction       string
	RepositoryID    int64
	ProcessingState string
	Event           string
}

type auditLogView struct {
	Deliveries              []webhookDeliveryView
	Filters                 auditLogFilterView
	RepositoryFilterOptions []auditLogOption
	EventFilterOptions      []auditLogOption
	ProcessingFilterOptions []auditLogOption
	SortOptions             []auditLogOption
	DirectionOptions        []auditLogOption
	LimitOptions            []auditLogLimitOption
}

type auditLogFilterView struct {
	Limit                  int
	Sort                   string
	Direction              string
	RepositoryID           int64
	ProcessingState        string
	Event                  string
	TotalRows              int
	FilteredRows           int
	ShowingRows            int
	HasActiveFilters       bool
	SortReceivedURL        string
	SortProcessedURL       string
	SortReceivedAria       string
	SortProcessedAria      string
	SortReceivedIndicator  string
	SortProcessedIndicator string
}

type auditLogOption struct {
	Value    string
	Label    string
	Selected bool
}

type auditLogLimitOption struct {
	Value    int
	Label    string
	Selected bool
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	sessions *sessionStore
	csrfKey  []byte
}

func NewServer(cfg Config) *Server {
	if cfg.AppName == "" {
		cfg.AppName = "Thawguard"
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), sessions: newSessionStore(), csrfKey: newCSRFSigningKey()}
	s.routes()
	return s
}

func (s *Server) Routes() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /setup", s.handleSetup)
	s.mux.HandleFunc("POST /setup", s.handleCreateFirstAdmin)
	s.mux.HandleFunc("GET /login", s.handleLogin)
	s.mux.HandleFunc("POST /login", s.handleLoginPost)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /repositories", s.handleRepositories)
	s.mux.HandleFunc("POST /repositories", s.handleCreateRepository)
	s.mux.HandleFunc("POST /repositories/branches", s.handleAddRepositoryBranch)
	s.mux.HandleFunc("POST /repositories/branches/remove", s.handleRemoveRepositoryBranch)
	s.mux.HandleFunc("POST /repositories/webhook-secret", s.handleSetRepositoryWebhookSecret)
	s.mux.HandleFunc("POST /repositories/status-token", s.handleSetRepositoryStatusToken)
	s.mux.HandleFunc("POST /repositories/setup-check", s.handleRunRepositorySetupCheck)
	s.mux.HandleFunc("POST /repositories/status-verification", s.handleVerifyStatusPosting)
	s.mux.HandleFunc("POST /repositories/activate", s.handleActivateEnforcement)
	s.mux.HandleFunc("POST /repositories/deactivate", s.handleDeactivateEnforcement)
	s.mux.HandleFunc("POST /repositories/reconcile", s.handleReconcileEnforcement)
	s.mux.HandleFunc("POST /repositories/recover", s.handleRecoverEnforcement)
	s.mux.HandleFunc("GET /freezes", s.handleFreezes)
	s.mux.HandleFunc("GET /freezes/impact", s.handleFreezeImpact)
	s.mux.HandleFunc("POST /freezes", s.handleCreateFreeze)
	s.mux.HandleFunc("POST /freezes/end", s.handleEndFreeze)
	s.mux.HandleFunc("POST /freezes/cancel", s.handleCancelFreeze)
	s.mux.HandleFunc("GET /scheduled-freezes", s.handleScheduledFreezes)
	s.mux.HandleFunc("POST /scheduled-freezes", s.handleCreateScheduledFreeze)
	s.mux.HandleFunc("POST /scheduled-freezes/edit", s.handleEditScheduledFreeze)
	s.mux.HandleFunc("POST /scheduled-freezes/start-now", s.handleStartScheduledFreezeNow)
	s.mux.HandleFunc("POST /scheduled-freezes/cancel", s.handleCancelScheduledFreeze)
	s.mux.HandleFunc("GET /decisions", s.handleDecisions)
	s.mux.HandleFunc("GET /decisions/eligibility", s.handleThawEligibility)
	s.mux.HandleFunc("POST /decisions", s.handleCreateDecision)
	s.mux.HandleFunc("GET /activity", s.handleActivity)
	s.mux.HandleFunc("GET /publications", s.handlePublications)
	s.mux.HandleFunc("GET /webhooks", s.handleWebhooks)
	s.mux.HandleFunc("POST /webhooks/forgejo", s.handleForgejoWebhook)
	s.mux.HandleFunc("GET /users", s.handleUsers)
	s.mux.HandleFunc("POST /users", s.handleCreateUser)
	s.mux.HandleFunc("POST /users/roles", s.handleUpdateUserRoles)
	s.mux.HandleFunc("POST /users/disable", s.handleDisableUser)
	s.mux.HandleFunc("POST /users/enable", s.handleEnableUser)
	s.mux.HandleFunc("POST /users/reset-password", s.handleResetUserPassword)
	s.mux.HandleFunc("GET /account/password", s.handleAccountPassword)
	s.mux.HandleFunc("POST /account/password", s.handleAccountPasswordPost)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(webassets.StaticFS()))))
	if s.cfg.DevMode {
		s.mux.HandleFunc("GET /dev/preview", s.handleDevPreview)
		s.mux.HandleFunc("GET /dev/preview/auth", s.handleDevPreviewAuth)
		s.mux.HandleFunc("GET /dev/preview/repositories", s.handleDevPreviewRepositories)
		s.mux.HandleFunc("GET /dev/preview/freezes", s.handleDevPreviewFreezes)
		s.mux.HandleFunc("GET /dev/preview/dashboard", s.handleDevPreviewDashboard)
		s.mux.HandleFunc("GET /dev/preview/decisions", s.handleDevPreviewDecisions)
		s.mux.HandleFunc("GET /dev/preview/activity", s.handleDevPreviewActivity)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	hasUsers, err := s.cfg.AuthService.HasUsers(r.Context())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	}
	if hasUsers {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderSetupStatus(w, r, "", "", "", http.StatusOK)
}

func (s *Server) handleCreateFirstAdmin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	hasUsers, err := s.cfg.AuthService.HasUsers(r.Context())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	}
	if hasUsers {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email, displayName := r.PostFormValue("email"), r.PostFormValue("display_name")
	if !sameOriginRequest(r) {
		s.renderSetupStatus(w, r, email, displayName, "Setup form expired. Please try again.", http.StatusForbidden)
		return
	}
	if !s.validSetupCSRFToken(r) {
		s.renderSetupStatus(w, r, email, displayName, "Setup form expired. Please try again.", http.StatusForbidden)
		return
	}
	session, err := s.cfg.AuthService.CreateFirstAdmin(r.Context(), auth.CreateFirstAdminParams{
		Email:       email,
		DisplayName: displayName,
		Password:    r.PostFormValue("password"),
	})
	if err != nil {
		if !auth.IsValidationError(err) {
			s.renderErrorPage(w, http.StatusInternalServerError, true)
			return
		}
		s.renderSetupStatus(w, r, email, displayName, err.Error(), http.StatusBadRequest)
		return
	}
	clearSetupCSRFCookie(w, r)
	setSessionCookie(w, r, sessionStateFromAuth(session))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	hasUsers, err := s.cfg.AuthService.HasUsers(r.Context())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	}
	if !hasUsers {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if session, ok, err := s.currentSession(r); err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	} else if ok {
		http.Redirect(w, r, postLoginPath(session.MustChangePassword), http.StatusSeeOther)
		return
	}
	s.renderLoginStatus(w, r, "", "", http.StatusOK)
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.PostFormValue("email")
	if !sameOriginRequest(r) {
		s.renderLoginStatus(w, r, email, "Your sign-in form expired. Please try again.", http.StatusForbidden)
		return
	}
	if !s.validLoginCSRFToken(r) {
		s.renderLoginStatus(w, r, email, "Your sign-in form expired. Please try again.", http.StatusForbidden)
		return
	}
	session, err := s.cfg.AuthService.Login(r.Context(), auth.LoginParams{Email: email, Password: r.PostFormValue("password")})
	if err != nil {
		if !auth.IsAuthenticationError(err) {
			s.renderErrorPage(w, http.StatusInternalServerError, true)
			return
		}
		s.renderLoginStatus(w, r, email, err.Error(), http.StatusUnauthorized)
		return
	}
	clearLoginCSRFCookie(w, r)
	setSessionCookie(w, r, sessionStateFromAuth(session))
	http.Redirect(w, r, postLoginPath(session.User.MustChangePassword), http.StatusSeeOther)
}

func postLoginPath(mustChangePassword bool) string {
	if mustChangePassword {
		return "/account/password"
	}
	return "/"
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAuthenticatedForm(w, r)
	if !ok {
		return
	}
	if s.cfg.AuthService != nil {
		if err := s.cfg.AuthService.Logout(r.Context(), session.ID); err != nil {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
			return
		}
	} else {
		s.sessions.delete(session.ID)
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	data, err := s.dashboardPageData(r.Context(), session)
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderPage(w, "layouts/dashboard", data)
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	// The same URL serves the full page and the #decisions-live fragment.
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	state := decisionsPageState{Query: decisionsQueryFromValues(r.URL.Query())}
	switch r.URL.Query().Get("notice") {
	case "thaw-approved":
		state.Notice = "Thaw approved."
	case "thaw-approved-shared":
		state.Notice = "Thaw approved for all pull requests sharing the confirmed head commit."
	}
	if isHXRequest(r) {
		// Filter chips, the repository filter, and pagination links enhance to
		// hx-get swaps of the live region; the full page handles everything else.
		s.renderDecisionsFragment(w, r, http.StatusOK, state, session, nil)
		return
	}
	s.renderDecisionsPage(w, r, http.StatusOK, state, session)
}

func (s *Server) handleCreateDecision(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireThawApproverForm(w, r)
	if !ok {
		return
	}
	query := decisionsQueryFromValues(r.PostForm)
	form := decisionFormStateFromRequest(r)
	pullRequestIndex, err := strconv.Atoi(form.PullRequestIndex)
	if err != nil {
		pullRequestIndex = 0
	}
	confirmation := thawApprovalConfirmationFromForm(r)
	outcome, err := s.cfg.StatusDecisionStore.ApproveThaw(r.Context(), statusresult.ThawApprovalParams{
		RepositoryID:     form.RepositoryID,
		PullRequestIndex: pullRequestIndex,
		TargetBranch:     r.PostFormValue("target_branch"),
		HeadSHA:          r.PostFormValue("head_sha"),
		Reason:           r.PostFormValue("reason"),
		Confirmation:     confirmation,
	}, session.auditActor())
	if err != nil {
		if !statusresult.IsValidationError(err) {
			internalServerError(w)
			return
		}
		state := decisionsPageState{FormError: err.Error(), DecisionForm: form, Query: query}
		if isHXRequest(r) {
			// main.js only swaps 2xx/5xx (plus the shared-head 409), so validation
			// errors come back as 200 fragments re-rendering the live region with
			// the error and the submitted values preserved.
			s.renderDecisionsFragment(w, r, http.StatusOK, state, session, nil)
			return
		}
		s.renderDecisionsPage(w, r, http.StatusBadRequest, state, session)
		return
	}
	if outcome.ConfirmationRequired {
		view := sharedHeadConfirmationViewFrom(outcome, form.RepositoryID, pullRequestIndex, strings.TrimSpace(r.PostFormValue("target_branch")), strings.TrimSpace(r.PostFormValue("reason")))
		// ApproveThaw re-checks the shared head on every attempt and never
		// trusts a stale confirmation, so a posted confirmation landing back
		// here means the forge state changed since the approver last saw the
		// affected set.
		view.Stale = confirmation != nil
		state := decisionsPageState{DecisionForm: form, Query: query, Confirmation: &view}
		if isHXRequest(r) {
			s.renderDecisionsFragment(w, r, http.StatusConflict, state, session, nil)
			return
		}
		s.renderDecisionsPage(w, r, http.StatusConflict, state, session)
		return
	}
	if isHXRequest(r) {
		toast := s.decisionApprovalToast(r.Context(), form.RepositoryID, pullRequestIndex, confirmation)
		s.renderDecisionsFragment(w, r, http.StatusOK, decisionsPageState{Query: query}, session, &toast)
		return
	}
	notice := "thaw-approved"
	if confirmation != nil {
		notice = "thaw-approved-shared"
	}
	http.Redirect(w, r, decisionsNoticeURL(query, notice), http.StatusSeeOther)
}

// decisionApprovalToast phrases the success toast. Approval defers status
// publication to convergence, so the copy never claims a status was published.
// On a confirmed shared-head approval the affected count is recomputed from
// the webhook cache ApproveThaw just re-synced; if that lookup is unavailable
// the toast falls back to a countless phrasing rather than guessing.
func (s *Server) decisionApprovalToast(ctx context.Context, repositoryID int64, pullRequestIndex int, confirmation *statusresult.ThawApprovalConfirmation) toastView {
	if confirmation == nil {
		return toastView{Message: fmt.Sprintf("Thaw approved for pull request #%d.", pullRequestIndex)}
	}
	short := shortHeadSHA(confirmation.HeadSHA)
	if s.cfg.PullRequestStore != nil {
		if prs, err := s.cfg.PullRequestStore.ListOpenByHead(ctx, repositoryID, confirmation.HeadSHA); err == nil && len(prs) > 1 {
			return toastView{Message: fmt.Sprintf("Thaw approved for all %d pull requests sharing %s.", len(prs), short)}
		}
	}
	return toastView{Message: fmt.Sprintf("Thaw approved for all pull requests sharing %s.", short)}
}

func thawApprovalConfirmationFromForm(r *http.Request) *statusresult.ThawApprovalConfirmation {
	if r.PostFormValue("confirm_shared_head") != "true" {
		return nil
	}
	return &statusresult.ThawApprovalConfirmation{HeadSHA: r.PostFormValue("confirmed_head_sha"), AffectedSignature: r.PostFormValue("confirmed_affected_signature")}
}

type sharedHeadAffectedPullRequestView struct {
	Index        int
	Title        string
	TargetBranch string
	ShortHeadSHA string
	URL          string
}

type sharedHeadConfirmationView struct {
	RepositoryID         int64
	PullRequestIndex     int
	TargetBranch         string
	Reason               string
	HeadSHA              string
	ShortHeadSHA         string
	AffectedSignature    string
	AffectedCount        int
	AffectedPullRequests []sharedHeadAffectedPullRequestView
	// Stale is true when this confirmation replaced one the approver already
	// posted: the fail-closed re-check found the forge state changed, so the
	// interstitial flags that the affected set below was refreshed.
	Stale bool
}

func sharedHeadConfirmationViewFrom(outcome statusresult.ThawApprovalOutcome, repositoryID int64, pullRequestIndex int, targetBranch, reason string) sharedHeadConfirmationView {
	view := sharedHeadConfirmationView{
		RepositoryID:     repositoryID,
		PullRequestIndex: pullRequestIndex,
		TargetBranch:     targetBranch,
		Reason:           reason,
		AffectedCount:    len(outcome.AffectedPullRequests),
	}
	if outcome.Confirmation != nil {
		view.HeadSHA = outcome.Confirmation.HeadSHA
		view.AffectedSignature = outcome.Confirmation.AffectedSignature
	}
	view.ShortHeadSHA = shortHeadSHA(view.HeadSHA)
	for _, pr := range outcome.AffectedPullRequests {
		view.AffectedPullRequests = append(view.AffectedPullRequests, sharedHeadAffectedPullRequestView{Index: pr.Index, Title: pr.Title, TargetBranch: pr.TargetBranch, ShortHeadSHA: shortHeadSHA(pr.HeadSHA), URL: pr.URL})
	}
	return view
}

func shortHeadSHA(sha string) string {
	if len(sha) > 10 {
		return sha[:10]
	}
	return sha
}

func (s *Server) handlePublications(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusPublicationStore == nil {
		http.Error(w, "status publication store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	repositories, publications, attempts, err := s.publicationPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderPublications(w, s.statusPublicationViews(repositories, publications), statusPublicationAttemptViews(repositories, attempts), session)
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.AuditStore == nil {
		http.Error(w, "audit store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	query := activityQueryFromValues(r.URL.Query())
	data, ok := s.loadActivityPageData(w, r, query, session)
	if !ok {
		return
	}
	if isHXRequest(r) {
		s.renderPage(w, "components/activity-live", data)
		return
	}
	s.renderPage(w, "layouts/activity", data)
}

func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	if s.cfg.WebhookDeliveryStore == nil {
		http.Error(w, "webhook delivery store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	controls := parseAuditLogControls(r)
	repositories, deliveries, err := s.webhookDeliveryPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderWebhookDeliveries(w, auditLogViewData(controls, repositories, deliveries), session)
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
			s.claimAndProcessVerifiedPullRequestWebhook(w, r, delivery, repo.ID, event.Action, body)
			return
		}
		internalServerError(w)
		return
	}
	s.claimAndProcessVerifiedPullRequestWebhook(w, r, delivery, repo.ID, event.Action, body)
}

func (s *Server) claimAndProcessVerifiedPullRequestWebhook(w http.ResponseWriter, r *http.Request, delivery webhook.Delivery, repositoryID int64, action string, body []byte) {
	if delivery.ID == 0 {
		acceptedWebhook(w)
		return
	}
	claimedDelivery, claimed, err := s.cfg.WebhookDeliveryStore.ClaimForProcessing(r.Context(), delivery.ID)
	if err != nil {
		internalServerError(w)
		return
	}
	if !claimed {
		acceptedWebhook(w)
		return
	}
	s.processVerifiedPullRequestWebhook(w, r, claimedDelivery, repositoryID, action, body)
}

func (s *Server) processVerifiedPullRequestWebhook(w http.ResponseWriter, r *http.Request, delivery webhook.Delivery, repositoryID int64, action string, body []byte) {
	if delivery.ProcessingStartedAt == nil {
		internalServerError(w)
		return
	}
	if !supportedPullRequestAction(action) {
		s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, "unsupported pull_request action", delivery.ProcessingStartedAt)
		return
	}

	_, processErr := s.cfg.PullRequestWebhookProcessor.Process(r.Context(), body)
	if processErr != nil {
		deliveryError := sanitizedWebhookProcessError(processErr)
		if webhook.IsValidationError(processErr) {
			if !s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, deliveryError, delivery.ProcessingStartedAt) {
				return
			}
			acceptedWebhook(w)
			return
		}
		if _, err := s.cfg.WebhookDeliveryStore.MarkProcessingFailed(r.Context(), delivery.ID, deliveryError, *delivery.ProcessingStartedAt); err != nil {
			internalServerError(w)
			return
		}
		internalServerError(w)
		return
	}
	_ = s.markWebhookProcessed(w, r, delivery.ID, repositoryID, action, "", delivery.ProcessingStartedAt)
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

func (s *Server) markWebhookProcessed(w http.ResponseWriter, r *http.Request, deliveryID int64, repositoryID int64, action string, deliveryError string, processingStartedAt *time.Time) bool {
	if _, err := s.cfg.WebhookDeliveryStore.MarkProcessed(r.Context(), deliveryID, webhook.DeliveryProcessParams{RepositoryID: repositoryID, Action: action, Error: deliveryError, ProcessingStartedAt: processingStartedAt}); err != nil {
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
	session, ok := s.requireView(w, r)
	if !ok {
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
	notice := ""
	if r.URL.Query().Get("notice") == "enforcement-deactivated" {
		notice = "Repository enforcement is inactive. The repository is ready for status-token or managed-branch maintenance."
	}
	s.renderRepositoriesPage(w, views, "", notice, session, parseRepositoryListFilter(r.URL.Query()))
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
		s.renderRepositories(w, views, err.Error(), session)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleAddRepositoryBranch(w http.ResponseWriter, r *http.Request) {
	s.handleRepositoryBranchMutation(w, r, "Managed branch added.", func(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error {
		_, err := s.cfg.RepositoryStore.AddBranch(ctx, repositoryID, branch, actor)
		return err
	})
}

func (s *Server) handleRemoveRepositoryBranch(w http.ResponseWriter, r *http.Request) {
	s.handleRepositoryBranchMutation(w, r, "Managed branch removed.", func(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error {
		return s.cfg.RepositoryStore.RemoveBranch(ctx, repositoryID, branch, actor)
	})
}

func (s *Server) handleRepositoryBranchMutation(w http.ResponseWriter, r *http.Request, toastMessage string, mutate func(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}
	repositoryID := repositoryIDFromForm(r)
	if err := mutate(r.Context(), repositoryID, r.PostFormValue("branch"), session.auditActor()); err != nil {
		s.renderRepositoriesValidationError(w, r, err, session, repositoryID)
		return
	}
	s.completeRepositoryMutation(w, r, session, repositoryID, toastMessage, "/repositories")
}

// isHXRequest reports whether the request came from htmx and expects an HTML
// fragment instead of a full page or redirect.
func isHXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// repositoryIDFromForm parses the posted repository_id, treating malformed
// values as 0 so the store/service rejects them with a typed not-found error.
func repositoryIDFromForm(r *http.Request) int64 {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		return 0
	}
	return repositoryID
}

// completeRepositoryMutation finishes a successful repository POST. htmx
// requests receive the refreshed card fragment plus an out-of-band success
// toast; regular browsers keep the existing redirect-after-POST flow.
func (s *Server) completeRepositoryMutation(w http.ResponseWriter, r *http.Request, session sessionState, repositoryID int64, toastMessage, successLocation string) {
	if !isHXRequest(r) {
		http.Redirect(w, r, successLocation, http.StatusSeeOther)
		return
	}
	card, found, err := s.repositoryCardByID(r.Context(), repositoryID, session)
	if err != nil {
		internalServerError(w)
		return
	}
	if !found {
		// The repository disappeared mid-request; let htmx reload the page.
		w.Header().Set("HX-Redirect", successLocation)
		return
	}
	s.renderPage(w, "components/repository-card-fragment", repositoryCardFragment{
		Card:  card,
		Toast: &toastView{Message: toastMessage, Tone: "success"},
	})
}

// renderRepositoryMutationError renders a typed validation failure for a
// repository POST. htmx requests get a 200 card fragment carrying the message
// (the client does not swap 4xx responses); browsers keep the 400 full-page
// re-render of the unfiltered list.
func (s *Server) renderRepositoryMutationError(w http.ResponseWriter, r *http.Request, session sessionState, repositoryID int64, message string) {
	if isHXRequest(r) {
		card, found, err := s.repositoryCardByID(r.Context(), repositoryID, session)
		if err != nil {
			internalServerError(w)
			return
		}
		if !found {
			w.Header().Set("HX-Redirect", "/repositories")
			return
		}
		card.ActionError = message
		s.renderPage(w, "components/repository-card-fragment", repositoryCardFragment{Card: card})
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
	s.renderRepositories(w, views, message, session)
}

// renderRepositoriesValidationError re-renders for a typed validation error
// and hides internal error details.
func (s *Server) renderRepositoriesValidationError(w http.ResponseWriter, r *http.Request, err error, session sessionState, repositoryID int64) {
	message, ok := repositoryValidationMessage(err)
	if !ok {
		internalServerError(w)
		return
	}
	s.renderRepositoryMutationError(w, r, session, repositoryID, message)
}

func repositoryValidationMessage(err error) (string, bool) {
	var repositoryErr repository.ValidationError
	if errors.As(err, &repositoryErr) {
		return repositoryErr.Message, true
	}
	var setupErr repositorysetup.ValidationError
	if errors.As(err, &setupErr) {
		return setupErr.Message, true
	}
	return "", false
}

func (s *Server) handleSetRepositoryWebhookSecret(w http.ResponseWriter, r *http.Request) {
	s.handleSetRepositoryCredential(w, r, "webhook secret encryption is not configured", "webhook_secret", "Webhook secret saved.",
		func(ctx context.Context, repositoryID int64, value string, actor domain.Actor) error {
			_, err := s.cfg.RepositoryStore.SetWebhookSecret(ctx, repositoryID, value, actor)
			return err
		})
}

func (s *Server) handleSetRepositoryStatusToken(w http.ResponseWriter, r *http.Request) {
	s.handleSetRepositoryCredential(w, r, "status token encryption is not configured", "status_token", "Status token saved.",
		func(ctx context.Context, repositoryID int64, value string, actor domain.Actor) error {
			_, err := s.cfg.RepositoryStore.SetStatusToken(ctx, repositoryID, value, actor)
			return err
		})
}

// handleSetRepositoryCredential is the shared admin-only CSRF-protected flow
// for the write-only repository credentials (webhook secret, status token).
func (s *Server) handleSetRepositoryCredential(w http.ResponseWriter, r *http.Request, encryptionMessage, field, toastMessage string, save func(ctx context.Context, repositoryID int64, value string, actor domain.Actor) error) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.cfg.RepositorySecretEncryptionConfigured {
		http.Error(w, encryptionMessage, http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}
	repositoryID := repositoryIDFromForm(r)
	if err := save(r.Context(), repositoryID, r.PostFormValue(field), session.auditActor()); err != nil {
		if repositorysetup.IsConfigurationError(err) {
			http.Error(w, encryptionMessage, http.StatusServiceUnavailable)
			return
		}
		if !repositorysetup.IsValidationError(err) {
			internalServerError(w)
			return
		}
		s.renderRepositoryMutationError(w, r, session, repositoryID, err.Error())
		return
	}
	s.completeRepositoryMutation(w, r, session, repositoryID, toastMessage, "/repositories")
}

func (s *Server) handleVerifyStatusPosting(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, "Status posting verified.", func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.VerifyStatusPosting(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleActivateEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, "Enforcement activated.", func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.ActivateEnforcement(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleDeactivateEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransitionTo(w, r, "Repository enforcement is inactive. The repository is ready for status-token or managed-branch maintenance.", "/repositories?notice=enforcement-deactivated", func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.DeactivateEnforcement(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleReconcileEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, "Reconciliation completed.", func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.ReconcileEnforcement(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleRecoverEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, "Enforcement recovery succeeded.", func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.RecoverEnforcement(ctx, repositoryID, actor)
		return err
	})
}

// handleEnforcementTransition guards the admin-only CSRF-protected enforcement
// actions and re-renders the repositories page with the typed validation
// message when the service rejects or reports a sanitized failure.
func (s *Server) handleEnforcementTransition(w http.ResponseWriter, r *http.Request, toastMessage string, transition func(ctx context.Context, repositoryID int64, actor domain.Actor) error) {
	s.handleEnforcementTransitionTo(w, r, toastMessage, "/repositories", transition)
}

func (s *Server) handleEnforcementTransitionTo(w http.ResponseWriter, r *http.Request, toastMessage, successLocation string, transition func(ctx context.Context, repositoryID int64, actor domain.Actor) error) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.EnforcementService == nil {
		http.Error(w, "enforcement service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}
	repositoryID := repositoryIDFromForm(r)
	if err := transition(r.Context(), repositoryID, session.auditActor()); err != nil {
		s.renderRepositoriesValidationError(w, r, err, session, repositoryID)
		return
	}
	s.completeRepositoryMutation(w, r, session, repositoryID, toastMessage, successLocation)
}

func (s *Server) handleFreezes(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	state := freezesPageState{}
	switch r.URL.Query().Get("notice") {
	case "freeze-started":
		state.Notice = "Freeze started."
	case "freeze-lifted":
		state.Notice = "Freeze lifted."
	case "freeze-cancelled":
		state.Notice, state.NoticeTone = "Freeze cancelled.", "info"
	}
	s.renderFreezes(w, r, http.StatusOK, state, session)
}

func (s *Server) handleCreateFreeze(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.FreezeStore == nil {
		http.Error(w, "freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}

	params, err := freezeCreateParamsFromForm(r)
	if err == nil {
		_, err = s.cfg.FreezeStore.CreateActive(r.Context(), params, session.auditActor())
	}
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		state := freezesPageState{
			FormError:  err.Error(),
			FreezeForm: freezeFormStateFromRequest(r),
		}
		if isHXRequest(r) {
			// main.js only swaps 2xx/5xx, so validation errors come back as
			// 200 fragments re-rendering the live region with the error and
			// the submitted values preserved.
			s.renderFreezesFragment(w, r, "components/freezes-live-fragment", state, session, nil)
			return
		}
		s.renderFreezes(w, r, http.StatusBadRequest, state, session)
		return
	}
	if isHXRequest(r) {
		s.renderFreezesFragment(w, r, "components/freezes-live-fragment", freezesPageState{}, session, &toastView{Message: "Freeze started.", Tone: "success"})
		return
	}
	http.Redirect(w, r, "/freezes?notice=freeze-started", http.StatusSeeOther)
}

// closeFreezeOutcome carries the lift-vs-cancel success messaging so the two
// semantically different actions stay distinguishable in toasts and notices.
type closeFreezeOutcome struct {
	notice string
	toast  toastView
}

func (s *Server) handleEndFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.endFreeze, closeFreezeOutcome{
		notice: "freeze-lifted",
		toast:  toastView{Message: "Freeze lifted.", Tone: "success"},
	})
}

func (s *Server) handleCancelFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.cancelFreeze, closeFreezeOutcome{
		notice: "freeze-cancelled",
		toast:  toastView{Message: "Freeze cancelled.", Tone: "info"},
	})
}

func (s *Server) handleCloseFreeze(w http.ResponseWriter, r *http.Request, closeFreeze func(context.Context, int64, domain.Actor) error, outcome closeFreezeOutcome) {
	w.Header().Add("Vary", "HX-Request")
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
		if isHXRequest(r) {
			// 200 fragment for the same main.js swap policy as create; the
			// error renders inside the re-rendered active-freezes section.
			s.renderFreezesFragment(w, r, "components/active-freezes-fragment", freezesPageState{ActionError: err.Error()}, session, nil)
			return
		}
		s.renderFreezes(w, r, http.StatusBadRequest, freezesPageState{FormError: err.Error()}, session)
		return
	}
	if isHXRequest(r) {
		toast := outcome.toast
		s.renderFreezesFragment(w, r, "components/active-freezes-fragment", freezesPageState{}, session, &toast)
		return
	}
	http.Redirect(w, r, "/freezes?notice="+outcome.notice, http.StatusSeeOther)
}

func (s *Server) endFreeze(ctx context.Context, id int64, actor domain.Actor) error {
	_, err := s.cfg.FreezeStore.End(ctx, id, actor)
	return err
}

func (s *Server) cancelFreeze(ctx context.Context, id int64, actor domain.Actor) error {
	_, err := s.cfg.FreezeStore.Cancel(ctx, id, actor)
	return err
}

func (s *Server) handleScheduledFreezes(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	state := scheduledFreezePageState{Query: scheduledFreezesQueryFromValues(r.URL.Query())}
	switch r.URL.Query().Get("notice") {
	case "schedule-created":
		state.Notice = "Freeze scheduled."
	case "schedule-updated":
		state.Notice = "Schedule updated."
	case "schedule-started":
		state.Notice = "Freeze started."
	case "schedule-cancelled":
		state.Notice, state.NoticeTone = "Scheduled freeze cancelled.", "info"
	}
	if isHXRequest(r) {
		// Filter chips and pagination links enhance to hx-get swaps of the
		// windows region; the full page handles everything else.
		s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", state, session, nil)
		return
	}
	s.renderScheduledFreezes(w, r, http.StatusOK, state, session)
}

func (s *Server) handleCreateScheduledFreeze(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}
	query := scheduledFreezesQueryFromValues(r.PostForm)
	params, err := scheduledFreezeParamsFromForm(r)
	var created domain.BranchFreeze
	if err == nil {
		created, err = s.cfg.ScheduledFreezeStore.CreateScheduled(r.Context(), params, session.auditActor())
	}
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		state := scheduledFreezePageState{
			FormError:    err.Error(),
			ScheduleForm: scheduledFreezeFormStateFromRequest(r),
			Query:        query,
		}
		if isHXRequest(r) {
			// main.js only swaps 2xx/5xx, so validation errors come back as
			// 200 fragments re-rendering the live region with the error and
			// the submitted values preserved.
			s.renderScheduledFreezesFragment(w, r, "components/scheduled-live-fragment", state, session, nil)
			return
		}
		s.renderScheduledFreezes(w, r, http.StatusBadRequest, state, session)
		return
	}
	if isHXRequest(r) {
		toast := toastView{Message: s.scheduledFreezeToastMessage(r.Context(), "Freeze scheduled", created), Tone: "success"}
		s.renderScheduledFreezesFragment(w, r, "components/scheduled-live-fragment", scheduledFreezePageState{Query: query}, session, &toast)
		return
	}
	http.Redirect(w, r, scheduledFreezesNoticeURL(query, "schedule-created"), http.StatusSeeOther)
}

func (s *Server) handleEditScheduledFreeze(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireScheduleManagerForm(w, r)
	if !ok {
		return
	}
	state := scheduledFreezePageState{
		Query:             scheduledFreezesQueryFromValues(r.PostForm),
		EditScheduleID:    scheduledFreezeIDFromForm(r),
		EditReason:        strings.TrimSpace(r.PostFormValue("reason")),
		EditStartsAt:      strings.TrimSpace(r.PostFormValue("starts_at")),
		EditPlannedEndsAt: strings.TrimSpace(r.PostFormValue("planned_ends_at")),
	}
	params, err := scheduledFreezeEditParamsFromForm(r)
	if err == nil {
		_, err = s.cfg.ScheduledFreezeStore.EditScheduled(r.Context(), params, session.auditActor())
	}
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		state.ActionError = err.Error()
		if isHXRequest(r) {
			s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", state, session, nil)
			return
		}
		s.renderScheduledFreezes(w, r, http.StatusBadRequest, state, session)
		return
	}
	if isHXRequest(r) {
		toast := toastView{Message: "Schedule updated.", Tone: "success"}
		s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", scheduledFreezePageState{Query: state.Query}, session, &toast)
		return
	}
	http.Redirect(w, r, scheduledFreezesNoticeURL(state.Query, "schedule-updated"), http.StatusSeeOther)
}

func (s *Server) handleStartScheduledFreezeNow(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireScheduleManagerForm(w, r)
	if !ok {
		return
	}
	query := scheduledFreezesQueryFromValues(r.PostForm)
	started, err := s.cfg.ScheduledFreezeStore.StartScheduledNow(r.Context(), scheduledFreezeIDFromForm(r), session.auditActor())
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		state := scheduledFreezePageState{ActionError: err.Error(), Query: query}
		if isHXRequest(r) {
			s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", state, session, nil)
			return
		}
		s.renderScheduledFreezes(w, r, http.StatusBadRequest, state, session)
		return
	}
	if isHXRequest(r) {
		toast := toastView{Message: s.scheduledFreezeToastMessage(r.Context(), "Freeze started", started), Tone: "success"}
		s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", scheduledFreezePageState{Query: query}, session, &toast)
		return
	}
	http.Redirect(w, r, scheduledFreezesNoticeURL(query, "schedule-started"), http.StatusSeeOther)
}

func (s *Server) handleCancelScheduledFreeze(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}
	query := scheduledFreezesQueryFromValues(r.PostForm)
	freezeID := scheduledFreezeIDFromForm(r)
	_, err := s.cfg.ScheduledFreezeStore.CancelScheduled(r.Context(), freezeID, session.auditActor())
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		state := scheduledFreezePageState{ActionError: err.Error(), Query: query}
		if isHXRequest(r) {
			s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", state, session, nil)
			return
		}
		s.renderScheduledFreezes(w, r, http.StatusBadRequest, state, session)
		return
	}
	if isHXRequest(r) {
		toast := toastView{Message: "Scheduled freeze cancelled.", Tone: "info"}
		s.renderScheduledFreezesFragment(w, r, "components/scheduled-windows-fragment", scheduledFreezePageState{Query: query}, session, &toast)
		return
	}
	http.Redirect(w, r, scheduledFreezesNoticeURL(query, "schedule-cancelled"), http.StatusSeeOther)
}

func scheduledFreezeIDFromForm(r *http.Request) int64 {
	id, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("freeze_id")), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func scheduledFreezeParamsFromForm(r *http.Request) (freeze.ScheduleParams, error) {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	timezoneOffsetMinutes, err := parseBrowserTimezoneOffsetMinutes(r.PostFormValue("timezone_offset_minutes"))
	if err != nil {
		return freeze.ScheduleParams{}, err
	}
	startsAt, err := parseScheduledFreezeFormTime(r.PostFormValue("starts_at"), timezoneOffsetMinutes)
	if err != nil {
		return freeze.ScheduleParams{}, err
	}
	plannedEndsAt, err := parseOptionalPlannedUnfreeze(r.PostFormValue("planned_ends_at"), timezoneOffsetMinutes)
	if err != nil {
		return freeze.ScheduleParams{}, err
	}
	return freeze.ScheduleParams{RepositoryID: repositoryID, Branch: r.PostFormValue("branch"), Reason: r.PostFormValue("reason"), StartsAt: startsAt, PlannedEndsAt: plannedEndsAt}, nil
}

func scheduledFreezeEditParamsFromForm(r *http.Request) (freeze.EditScheduleParams, error) {
	timezoneOffsetMinutes, err := parseBrowserTimezoneOffsetMinutes(r.PostFormValue("timezone_offset_minutes"))
	if err != nil {
		return freeze.EditScheduleParams{}, err
	}
	startsAt, err := parseScheduledFreezeFormTime(r.PostFormValue("starts_at"), timezoneOffsetMinutes)
	if err != nil {
		return freeze.EditScheduleParams{}, err
	}
	plannedEndsAt, err := parseOptionalPlannedUnfreeze(r.PostFormValue("planned_ends_at"), timezoneOffsetMinutes)
	if err != nil {
		return freeze.EditScheduleParams{}, err
	}
	return freeze.EditScheduleParams{
		ID:            scheduledFreezeIDFromForm(r),
		Reason:        r.PostFormValue("reason"),
		StartsAt:      startsAt,
		PlannedEndsAt: plannedEndsAt,
	}, nil
}

func freezeCreateParamsFromForm(r *http.Request) (freeze.CreateParams, error) {
	repositoryID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("repository_id")), 10, 64)
	if err != nil {
		repositoryID = 0
	}
	timezoneOffsetMinutes, err := parseBrowserTimezoneOffsetMinutes(r.PostFormValue("timezone_offset_minutes"))
	if err != nil {
		return freeze.CreateParams{}, err
	}
	plannedEndsAt, err := parseOptionalPlannedUnfreeze(r.PostFormValue("planned_ends_at"), timezoneOffsetMinutes)
	if err != nil {
		return freeze.CreateParams{}, err
	}
	return freeze.CreateParams{RepositoryID: repositoryID, Branch: r.PostFormValue("branch"), Reason: r.PostFormValue("reason"), PlannedEndsAt: plannedEndsAt}, nil
}

func parseBrowserTimezoneOffsetMinutes(raw string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(value)
	if err != nil || offset < -14*60 || offset > 14*60 {
		return 0, freeze.ValidationError{Message: "browser timezone offset is invalid"}
	}
	return offset, nil
}

func parseOptionalPlannedUnfreeze(raw string, timezoneOffsetMinutes int) (*time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, nil
	}
	plannedEndsAt, err := parseScheduledFreezeFormTime(value, timezoneOffsetMinutes)
	if err != nil {
		return nil, freeze.ValidationError{Message: "planned unfreeze time is invalid"}
	}
	return &plannedEndsAt, nil
}

func parseScheduledFreezeFormTime(raw string, timezoneOffsetMinutes int) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, freeze.ValidationError{Message: "scheduled freeze start time is required"}
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		_, offsetSeconds := parsed.Zone()
		if offsetSeconds < -14*60*60 || offsetSeconds > 14*60*60 {
			return time.Time{}, freeze.ValidationError{Message: "scheduled freeze time has an invalid timezone offset"}
		}
		return parsed.UTC(), nil
	}
	location := time.FixedZone("browser", -timezoneOffsetMinutes*60)
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02 15:04"} {
		parsed, err := time.ParseInLocation(layout, value, location)
		if err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, freeze.ValidationError{Message: "scheduled freeze start time is invalid"}
}

func (s *Server) handleRunRepositorySetupCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.SetupCheckRunner == nil {
		http.Error(w, "setup check runner is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}

	repositoryID := repositoryIDFromForm(r)
	if repositoryID <= 0 {
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

	if _, err := s.cfg.SetupCheckRunner.Run(r.Context(), repo, session.auditActor()); err != nil {
		http.Error(w, "setup check failed", http.StatusBadGateway)
		return
	}
	s.completeRepositoryMutation(w, r, session, repositoryID, "Readiness checks completed.", "/repositories")
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	if !session.Roles.CanManageRepositories() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	users, err := s.cfg.AuthService.ListUsers(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderUsers(w, users, defaultUsersPageState(), session)
}

// defaultUsersPageState seeds the create-user form with the least-privileged
// role preselected.
func defaultUsersPageState() usersPageState {
	return usersPageState{CreateRoles: auth.RoleSet{auth.RoleViewer}}
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok {
		return
	}
	roles := rolesFromForm(r)
	_, err := s.cfg.AuthService.CreateUser(r.Context(), auth.CreateUserParams{
		Email:       r.PostFormValue("email"),
		DisplayName: r.PostFormValue("display_name"),
		Password:    r.PostFormValue("password"),
		Roles:       roles,
	})
	if err != nil {
		s.renderUsersValidationError(w, r, err, usersPageState{CreateRoles: auth.RoleSet(roles)}, session)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleUpdateUserRoles(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	userID := formUserID(r)
	roles := rolesFromForm(r)
	_, err := s.cfg.AuthService.UpdateUserRoles(r.Context(), auth.UpdateUserRolesParams{
		ActorUserID: *session.UserID,
		UserID:      userID,
		Roles:       roles,
	})
	if err != nil {
		state := defaultUsersPageState()
		state.RoleFormUserID = userID
		state.RoleFormRoles, _ = auth.NormalizeRoleSet(roles)
		s.renderUsersValidationError(w, r, err, state, session)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	userID := formUserID(r)
	if _, err := s.cfg.AuthService.DisableUser(r.Context(), *session.UserID, userID); err != nil {
		s.renderUsersValidationError(w, r, err, defaultUsersPageState(), session)
		return
	}
	if *session.UserID == userID {
		clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	if _, err := s.cfg.AuthService.EnableUser(r.Context(), *session.UserID, formUserID(r)); err != nil {
		s.renderUsersValidationError(w, r, err, defaultUsersPageState(), session)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireRepositoryManagerForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	userID := formUserID(r)
	state := defaultUsersPageState()
	state.ResetFormUserID = userID
	if r.PostFormValue("temporary_password") != r.PostFormValue("temporary_password_confirmation") {
		s.renderUsersValidationError(w, r, auth.ValidationError{Message: "temporary passwords do not match"}, state, session)
		return
	}
	err := s.cfg.AuthService.ResetPassword(r.Context(), auth.ResetPasswordParams{
		ActorUserID:       *session.UserID,
		UserID:            userID,
		TemporaryPassword: r.PostFormValue("temporary_password"),
	})
	if err != nil {
		s.renderUsersValidationError(w, r, err, state, session)
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// renderUsersValidationError re-renders the users page for a typed validation
// error and hides internal error details. Password values are never echoed.
func (s *Server) renderUsersValidationError(w http.ResponseWriter, r *http.Request, err error, state usersPageState, session sessionState) {
	if !auth.IsValidationError(err) {
		internalServerError(w)
		return
	}
	users, listErr := s.cfg.AuthService.ListUsers(r.Context())
	if listErr != nil {
		internalServerError(w)
		return
	}
	state.FormError = err.Error()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	s.renderUsers(w, users, state, session)
}

func formUserID(r *http.Request) int64 {
	userID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("user_id")), 10, 64)
	if err != nil {
		return 0
	}
	return userID
}

func (s *Server) handleAccountPassword(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	session, ok := s.requireViewWithGate(w, r, true)
	if !ok {
		return
	}
	s.renderAccountPassword(w, "", http.StatusOK, session)
}

func (s *Server) handleAccountPasswordPost(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	session, ok := s.requireAuthenticatedForm(w, r)
	if !ok {
		return
	}
	if session.UserID == nil {
		s.renderErrorPage(w, http.StatusForbidden, true)
		return
	}
	if r.PostFormValue("new_password") != r.PostFormValue("new_password_confirmation") {
		s.renderAccountPassword(w, "new passwords do not match", http.StatusBadRequest, session)
		return
	}
	newSession, err := s.cfg.AuthService.ChangePassword(r.Context(), auth.ChangePasswordParams{
		UserID:          *session.UserID,
		CurrentPassword: r.PostFormValue("current_password"),
		NewPassword:     r.PostFormValue("new_password"),
	})
	if err != nil {
		if !auth.IsValidationError(err) {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
			return
		}
		s.renderAccountPassword(w, err.Error(), http.StatusBadRequest, session)
		return
	}
	setSessionCookie(w, r, sessionStateFromAuth(newSession))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderAccountPassword(w http.ResponseWriter, formError string, status int, session sessionState) {
	s.renderPageStatus(w, status, "layouts/account-password", authAccountPasswordData{
		AppName:            s.cfg.AppName,
		PageTitle:          "Change password",
		CSRFField:          csrfFormField,
		CSRFToken:          session.CSRFToken,
		FormError:          formError,
		MustChangePassword: session.MustChangePassword,
	})
}

func (s *Server) requireRepositoryManagerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleForm(w, r, func(roles auth.RoleSet) bool { return roles.CanManageRepositories() })
}

func (s *Server) requireFreezerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleForm(w, r, func(roles auth.RoleSet) bool { return roles.CanFreeze() })
}

func (s *Server) requireScheduleManagerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleForm(w, r, func(roles auth.RoleSet) bool {
		return roles.CanManageRepositories() || roles.CanFreeze()
	})
}

func (s *Server) requireThawApproverForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleForm(w, r, func(roles auth.RoleSet) bool { return roles.CanThaw() })
}

func (s *Server) requireAuthenticatedForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleFormWithGate(w, r, func(roles auth.RoleSet) bool { return roles.CanView() }, true)
}

func (s *Server) requireRoleForm(w http.ResponseWriter, r *http.Request, allowed func(auth.RoleSet) bool) (sessionState, bool) {
	return s.requireRoleFormWithGate(w, r, allowed, false)
}

// requireRoleFormWithGate guards authenticated POST mutations. Unless
// allowForced is set, a session in forced password-change state is redirected
// to /account/password before role authorization or any domain work.
func (s *Server) requireRoleFormWithGate(w http.ResponseWriter, r *http.Request, allowed func(auth.RoleSet) bool, allowForced bool) (sessionState, bool) {
	session, ok, err := s.currentSession(r)
	if err != nil {
		internalServerError(w)
		return sessionState{}, false
	}
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if !allowForced && session.MustChangePassword {
		http.Redirect(w, r, "/account/password", http.StatusSeeOther)
		return sessionState{}, false
	}
	if !allowed(session.Roles) {
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

func (s *Server) requireView(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireViewWithGate(w, r, false)
}

func (s *Server) requireViewWithGate(w http.ResponseWriter, r *http.Request, allowForced bool) (sessionState, bool) {
	if s.cfg.AuthService == nil {
		session, err := s.sessions.getOrCreate(w, r)
		if err != nil {
			http.Error(w, "create session", http.StatusInternalServerError)
			return sessionState{}, false
		}
		return session, true
	}

	session, ok, err := s.currentSession(r)
	if err != nil {
		internalServerError(w)
		return sessionState{}, false
	}
	if ok && !allowForced && session.MustChangePassword {
		http.Redirect(w, r, "/account/password", http.StatusSeeOther)
		return sessionState{}, false
	}
	if ok && session.Roles.CanView() {
		setSessionCookie(w, r, session)
		return session, true
	}
	if ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	hasUsers, err := s.cfg.AuthService.HasUsers(r.Context())
	if err != nil {
		internalServerError(w)
		return sessionState{}, false
	}
	if !hasUsers {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return sessionState{}, false
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return sessionState{}, false
}

func (s *Server) currentSession(r *http.Request) (sessionState, bool, error) {
	if s.cfg.AuthService == nil {
		session, ok := s.sessions.get(r)
		return session, ok, nil
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionCookieName || cookie.Value == "" {
			continue
		}
		session, ok, err := s.cfg.AuthService.SessionByID(r.Context(), cookie.Value)
		if err != nil {
			return sessionState{}, false, err
		}
		if ok {
			return sessionStateFromAuth(session), true, nil
		}
	}
	return sessionState{}, false, nil
}

func sessionStateFromAuth(session auth.Session) sessionState {
	userID := session.User.ID
	return sessionState{
		ID:                 session.ID,
		CSRFToken:          session.CSRFToken,
		UserID:             &userID,
		Email:              session.User.Email,
		DisplayName:        session.User.DisplayName,
		Role:               session.User.Role,
		Roles:              session.User.Roles,
		MustChangePassword: session.User.MustChangePassword,
		ExpiresAt:          session.ExpiresAt,
	}
}

func currentUserFromSession(session sessionState) currentUserView {
	roles := session.Roles
	if len(roles) == 0 && session.Role.Valid() {
		roles = auth.RoleSet{session.Role}
	}
	return currentUserView{
		Email:                 session.Email,
		DisplayName:           session.DisplayName,
		RoleLabel:             roles.Label(),
		CanChangePassword:     session.UserID != nil,
		IsAdmin:               session.UserID != nil && roles.CanManageRepositories(),
		CanManageRepositories: roles.CanManageRepositories(),
		CanFreeze:             roles.CanFreeze(),
		CanThaw:               roles.CanThaw(),
	}
}

func (s *Server) repositories(ctx context.Context) ([]domain.Repository, error) {
	if s.cfg.RepositoryStore == nil {
		return nil, nil
	}
	return s.cfg.RepositoryStore.List(ctx)
}

func (s *Server) statusPublications(ctx context.Context) ([]statuspublication.Publication, error) {
	if s.cfg.StatusPublicationStore == nil {
		return nil, nil
	}
	return s.cfg.StatusPublicationStore.ListRecent(ctx, 25)
}

func (s *Server) statusPublicationAttempts(ctx context.Context) ([]statuspublication.Attempt, error) {
	if s.cfg.StatusPublicationStore == nil {
		return nil, nil
	}
	return s.cfg.StatusPublicationStore.ListRecentAttempts(ctx, 25)
}

func (s *Server) webhookDeliveries(ctx context.Context) ([]webhook.Delivery, error) {
	if s.cfg.WebhookDeliveryStore == nil {
		return nil, nil
	}
	return s.cfg.WebhookDeliveryStore.ListRecent(ctx, maxAuditLogLimit)
}

func (s *Server) webhookDeliveryPageData(ctx context.Context) ([]domain.Repository, []webhook.Delivery, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, err
	}
	deliveries, err := s.webhookDeliveries(ctx)
	if err != nil {
		return nil, nil, err
	}
	return repositories, deliveries, nil
}

func parseAuditLogControls(r *http.Request) auditLogControls {
	values := r.URL.Query()
	controls := auditLogControls{
		Limit:     defaultAuditLogLimit,
		Sort:      "received",
		Direction: "desc",
		Event:     strings.TrimSpace(values.Get("event")),
	}
	if limit, err := strconv.Atoi(strings.TrimSpace(values.Get("limit"))); err == nil {
		switch limit {
		case 25, 50, 100:
			controls.Limit = limit
		}
	}
	if sortField := strings.TrimSpace(values.Get("sort")); sortField == "processed" || sortField == "received" {
		controls.Sort = sortField
	}
	if direction := strings.TrimSpace(values.Get("direction")); direction == "asc" || direction == "desc" {
		controls.Direction = direction
	}
	if repositoryID, err := strconv.ParseInt(strings.TrimSpace(values.Get("repository_id")), 10, 64); err == nil && repositoryID > 0 {
		controls.RepositoryID = repositoryID
	}
	if state := strings.TrimSpace(values.Get("processing")); isAuditLogProcessingFilter(state) {
		controls.ProcessingState = state
	}
	return controls
}

func auditLogViewData(controls auditLogControls, repositories []domain.Repository, deliveries []webhook.Delivery) auditLogView {
	filtered := filterAuditLogDeliveries(deliveries, controls)
	sortAuditLogDeliveries(filtered, controls)
	limited := filtered
	if len(limited) > controls.Limit {
		limited = limited[:controls.Limit]
	}
	filterView := auditLogFilterView{
		Limit:                  controls.Limit,
		Sort:                   controls.Sort,
		Direction:              controls.Direction,
		RepositoryID:           controls.RepositoryID,
		ProcessingState:        controls.ProcessingState,
		Event:                  controls.Event,
		TotalRows:              len(deliveries),
		FilteredRows:           len(filtered),
		ShowingRows:            len(limited),
		HasActiveFilters:       controls.RepositoryID > 0 || controls.ProcessingState != "" || controls.Event != "",
		SortReceivedURL:        auditLogSortURL(controls, "received"),
		SortProcessedURL:       auditLogSortURL(controls, "processed"),
		SortReceivedAria:       auditLogSortAria(controls, "received"),
		SortProcessedAria:      auditLogSortAria(controls, "processed"),
		SortReceivedIndicator:  auditLogSortIndicator(controls, "received"),
		SortProcessedIndicator: auditLogSortIndicator(controls, "processed"),
	}
	return auditLogView{
		Deliveries:              webhookDeliveryViews(repositories, limited),
		Filters:                 filterView,
		RepositoryFilterOptions: auditLogRepositoryOptions(repositories, controls.RepositoryID),
		EventFilterOptions:      auditLogEventOptions(deliveries, controls.Event),
		ProcessingFilterOptions: auditLogProcessingOptions(controls.ProcessingState),
		SortOptions:             auditLogSortOptions(controls.Sort),
		DirectionOptions:        auditLogDirectionOptions(controls.Direction),
		LimitOptions:            auditLogLimitOptions(controls.Limit),
	}
}

func filterAuditLogDeliveries(deliveries []webhook.Delivery, controls auditLogControls) []webhook.Delivery {
	filtered := make([]webhook.Delivery, 0, len(deliveries))
	for _, delivery := range deliveries {
		if controls.RepositoryID > 0 && delivery.RepositoryID != controls.RepositoryID {
			continue
		}
		if controls.Event != "" && delivery.Event != controls.Event {
			continue
		}
		if controls.ProcessingState != "" && webhookDeliveryProcessingFilterState(delivery) != controls.ProcessingState {
			continue
		}
		filtered = append(filtered, delivery)
	}
	return filtered
}

func sortAuditLogDeliveries(deliveries []webhook.Delivery, controls auditLogControls) {
	sort.SliceStable(deliveries, func(i, j int) bool {
		left := deliveries[i]
		right := deliveries[j]
		if controls.Sort == "processed" {
			return compareOptionalAuditLogTimes(left.ProcessedAt, right.ProcessedAt, controls.Direction)
		}
		if left.ReceivedAt.Equal(right.ReceivedAt) {
			if controls.Direction == "asc" {
				return left.ID < right.ID
			}
			return left.ID > right.ID
		}
		if controls.Direction == "asc" {
			return left.ReceivedAt.Before(right.ReceivedAt)
		}
		return left.ReceivedAt.After(right.ReceivedAt)
	})
}

func compareOptionalAuditLogTimes(left *time.Time, right *time.Time, direction string) bool {
	if left == nil && right == nil {
		return false
	}
	if left == nil {
		return false
	}
	if right == nil {
		return true
	}
	if left.Equal(*right) {
		return false
	}
	if direction == "asc" {
		return left.Before(*right)
	}
	return left.After(*right)
}

func webhookDeliveryProcessingFilterState(delivery webhook.Delivery) string {
	if delivery.ProcessedAt != nil {
		if delivery.Error != "" {
			return "processed_with_error"
		}
		return "processed"
	}
	if delivery.ProcessingStartedAt != nil {
		return "processing"
	}
	if delivery.Error != "" {
		return "retryable_failure"
	}
	return "received"
}

func isAuditLogProcessingFilter(state string) bool {
	switch state {
	case "", "received", "processing", "processed", "processed_with_error", "retryable_failure":
		return true
	default:
		return false
	}
}

func auditLogRepositoryOptions(repositories []domain.Repository, selectedID int64) []auditLogOption {
	options := []auditLogOption{{Label: "All repositories", Selected: selectedID == 0}}
	for _, repo := range repositories {
		options = append(options, auditLogOption{Value: strconv.FormatInt(repo.ID, 10), Label: repo.FullName(), Selected: repo.ID == selectedID})
	}
	return options
}

func auditLogEventOptions(deliveries []webhook.Delivery, selected string) []auditLogOption {
	events := make(map[string]bool)
	for _, delivery := range deliveries {
		if delivery.Event != "" {
			events[delivery.Event] = true
		}
	}
	if selected != "" {
		events[selected] = true
	}
	labels := make([]string, 0, len(events))
	for event := range events {
		labels = append(labels, event)
	}
	sort.Strings(labels)
	options := []auditLogOption{{Label: "All events", Selected: selected == ""}}
	for _, event := range labels {
		options = append(options, auditLogOption{Value: event, Label: event, Selected: event == selected})
	}
	return options
}

func auditLogProcessingOptions(selected string) []auditLogOption {
	return []auditLogOption{
		{Label: "All processing states", Selected: selected == ""},
		{Value: "received", Label: "Received", Selected: selected == "received"},
		{Value: "processing", Label: "Processing", Selected: selected == "processing"},
		{Value: "processed", Label: "Processed", Selected: selected == "processed"},
		{Value: "processed_with_error", Label: "Processed with error", Selected: selected == "processed_with_error"},
		{Value: "retryable_failure", Label: "Retryable failure", Selected: selected == "retryable_failure"},
	}
}

func auditLogSortOptions(selected string) []auditLogOption {
	return []auditLogOption{
		{Value: "received", Label: "Received time", Selected: selected == "received"},
		{Value: "processed", Label: "Processed time", Selected: selected == "processed"},
	}
}

func auditLogDirectionOptions(selected string) []auditLogOption {
	return []auditLogOption{
		{Value: "desc", Label: "Newest first", Selected: selected == "desc"},
		{Value: "asc", Label: "Oldest first", Selected: selected == "asc"},
	}
}

func auditLogLimitOptions(selected int) []auditLogLimitOption {
	return []auditLogLimitOption{
		{Value: 25, Label: "25", Selected: selected == 25},
		{Value: 50, Label: "50", Selected: selected == 50},
		{Value: 100, Label: "100", Selected: selected == 100},
	}
}

func auditLogSortURL(controls auditLogControls, field string) string {
	next := controls
	next.Sort = field
	next.Direction = "desc"
	if controls.Sort == field && controls.Direction == "desc" {
		next.Direction = "asc"
	}
	return auditLogURL(next)
}

func auditLogURL(controls auditLogControls) string {
	values := url.Values{}
	values.Set("limit", strconv.Itoa(controls.Limit))
	values.Set("sort", controls.Sort)
	values.Set("direction", controls.Direction)
	if controls.RepositoryID > 0 {
		values.Set("repository_id", strconv.FormatInt(controls.RepositoryID, 10))
	}
	if controls.ProcessingState != "" {
		values.Set("processing", controls.ProcessingState)
	}
	if controls.Event != "" {
		values.Set("event", controls.Event)
	}
	return "/webhooks?" + values.Encode()
}

func auditLogSortAria(controls auditLogControls, field string) string {
	if controls.Sort != field {
		return "none"
	}
	if controls.Direction == "asc" {
		return "ascending"
	}
	return "descending"
}

func auditLogSortIndicator(controls auditLogControls, field string) string {
	if controls.Sort != field {
		return ""
	}
	if controls.Direction == "asc" {
		return "↑"
	}
	return "↓"
}

func (s *Server) publicationPageData(ctx context.Context) ([]domain.Repository, []statuspublication.Publication, []statuspublication.Attempt, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	publications, err := s.statusPublications(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	attempts, err := s.statusPublicationAttempts(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return repositories, publications, attempts, nil
}

func (s *Server) statusPublicationViews(repositories []domain.Repository, publications []statuspublication.Publication) []statusPublicationView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusPublicationView, 0, len(publications))
	for _, publication := range publications {
		updatedAt := publication.UpdatedAt
		if updatedAt.IsZero() {
			updatedAt = publication.CreatedAt
		}
		views = append(views, statusPublicationView{Publication: publication, Repository: repositoriesByID[publication.RepositoryID], CreatedAt: publication.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), UpdatedAt: updatedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func statusPublicationAttemptViews(repositories []domain.Repository, attempts []statuspublication.Attempt) []statusPublicationAttemptView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]statusPublicationAttemptView, 0, len(attempts))
	for _, attempt := range attempts {
		views = append(views, statusPublicationAttemptView{Attempt: attempt, Repository: repositoriesByID[attempt.RepositoryID], AttemptedAt: attempt.AttemptedAt.UTC().Format("2006-01-02 15:04 UTC")})
	}
	return views
}

func webhookDeliveryViews(repositories []domain.Repository, deliveries []webhook.Delivery) []webhookDeliveryView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]webhookDeliveryView, 0, len(deliveries))
	for _, delivery := range deliveries {
		state, stateClass := webhookDeliveryProcessingState(delivery)
		verified, verifiedClass := webhookDeliveryVerificationState(delivery)
		views = append(views, webhookDeliveryView{
			Delivery:               delivery,
			Repository:             repositoriesByID[delivery.RepositoryID],
			ReceivedAt:             delivery.ReceivedAt.UTC().Format("2006-01-02 15:04 UTC"),
			ProcessingStartedAt:    optionalWebhookDeliveryTime(delivery.ProcessingStartedAt),
			ProcessedAt:            optionalWebhookDeliveryTime(delivery.ProcessedAt),
			ProcessingState:        state,
			ProcessingStateClass:   stateClass,
			VerificationState:      verified,
			VerificationStateClass: verifiedClass,
		})
	}
	return views
}

type activityDetails map[string]json.RawMessage

type activityActionDefinition struct {
	Label        string
	Outcome      string
	OutcomeClass string
}

var activityActionDefinitions = map[string]activityActionDefinition{
	audit.ActionRepositoryCreated:                  {Label: "Repository added", Outcome: "Added", OutcomeClass: "ok"},
	audit.ActionRepositoryWebhookSecretConfigured:  {Label: "Webhook secret configuration", Outcome: "Configured", OutcomeClass: "ok"},
	audit.ActionRepositoryStatusTokenConfigured:    {Label: "Status token configuration", Outcome: "Configured", OutcomeClass: "ok"},
	audit.ActionRepositoryOpenPullRequestsSynced:   {Label: "Open pull request sync", Outcome: "Succeeded", OutcomeClass: "ok"},
	audit.ActionRepositoryBranchAdded:              {Label: "Managed branch addition", Outcome: "Added", OutcomeClass: "ok"},
	audit.ActionRepositoryBranchRemoved:            {Label: "Managed branch removal", Outcome: "Removed", OutcomeClass: "warning"},
	audit.ActionRepositorySetupCheckRun:            {Label: "Readiness check", Outcome: "Checked", OutcomeClass: "ok"},
	audit.ActionRepositorySetupDriftDetected:       {Label: "Setup drift", Outcome: "Detected", OutcomeClass: "warning"},
	audit.ActionRepositoryStatusPostVerified:       {Label: "Status-post verification", Outcome: "Succeeded", OutcomeClass: "ok"},
	audit.ActionRepositoryStatusPostVerifyFailed:   {Label: "Status-post verification", Outcome: "Failed", OutcomeClass: "failed"},
	audit.ActionRepositoryEnforcementActivated:     {Label: "Enforcement activation", Outcome: "Succeeded", OutcomeClass: "ok"},
	audit.ActionRepositoryEnforcementDeactivated:   {Label: "Enforcement deactivation", Outcome: "Succeeded", OutcomeClass: "warning"},
	audit.ActionRepositoryEnforcementActivateFail:  {Label: "Enforcement activation", Outcome: "Failed", OutcomeClass: "failed"},
	audit.ActionRepositoryEnforcementReconciled:    {Label: "Enforcement reconciliation", Outcome: "Succeeded", OutcomeClass: "ok"},
	audit.ActionRepositoryEnforcementReconcileFail: {Label: "Enforcement reconciliation", Outcome: "Failed", OutcomeClass: "failed"},
	audit.ActionRepositoryEnforcementRecovered:     {Label: "Enforcement recovery", Outcome: "Succeeded", OutcomeClass: "ok"},
	audit.ActionRepositoryEnforcementRecoverFail:   {Label: "Enforcement recovery", Outcome: "Failed", OutcomeClass: "failed"},
	audit.ActionRepositoryRuntimeConvergenceFail:   {Label: "Runtime convergence", Outcome: "Failed", OutcomeClass: "failed"},
	audit.ActionBranchFreezeCreated:                {Label: "Branch freeze", Outcome: "Frozen", OutcomeClass: "frozen"},
	audit.ActionBranchFreezeEnded:                  {Label: "Branch freeze", Outcome: "Lifted", OutcomeClass: "ok"},
	audit.ActionBranchFreezeCancelled:              {Label: "Branch freeze", Outcome: "Cancelled", OutcomeClass: "warning"},
	audit.ActionBranchFreezePlannedUnfreeze:        {Label: "Planned unfreeze", Outcome: "Lifted", OutcomeClass: "ok"},
	audit.ActionFreezeScheduleCreated:              {Label: "Freeze schedule", Outcome: "Scheduled", OutcomeClass: "pending"},
	audit.ActionFreezeScheduleUpdated:              {Label: "Freeze schedule", Outcome: "Changed", OutcomeClass: "frozen"},
	audit.ActionFreezeScheduleCancelled:            {Label: "Freeze schedule", Outcome: "Cancelled", OutcomeClass: "warning"},
	audit.ActionFreezeScheduleActivated:            {Label: "Scheduled freeze", Outcome: "Started", OutcomeClass: "frozen"},
	audit.ActionFreezeScheduleStartedNow:           {Label: "Scheduled freeze Start Now", Outcome: "Started", OutcomeClass: "frozen"},
	audit.ActionFreezeSchedulePlannedUnfreeze:      {Label: "Scheduled planned unfreeze", Outcome: "Completed", OutcomeClass: "ok"},
	audit.ActionThawExceptionApproved:              {Label: "Single-PR thaw", Outcome: "Approved", OutcomeClass: "ok"},
	audit.ActionThawExceptionSharedHeadApproved:    {Label: "Shared-head thaw", Outcome: "Approved", OutcomeClass: "ok"},
	audit.ActionUserRolesUpdated:                   {Label: "User roles", Outcome: "Changed", OutcomeClass: "frozen"},
	audit.ActionUserDisabled:                       {Label: "User access", Outcome: "Disabled", OutcomeClass: "warning"},
	audit.ActionUserEnabled:                        {Label: "User access", Outcome: "Enabled", OutcomeClass: "ok"},
	audit.ActionUserPasswordChanged:                {Label: "User password", Outcome: "Changed", OutcomeClass: "ok"},
	audit.ActionUserPasswordReset:                  {Label: "User password", Outcome: "Reset", OutcomeClass: "warning"},
}

func activityEventViews(repositories []domain.Repository, users []auth.User, events []audit.Event) []activityEventView {
	usersByID := make(map[int64]auth.User, len(users))
	for _, user := range users {
		usersByID[user.ID] = user
	}
	repositoriesByID := repositoriesByID(repositories)
	views := make([]activityEventView, 0, len(events))
	for _, event := range events {
		views = append(views, activityEventViewForEvent(repositoriesByID, usersByID, event))
	}
	return views
}

func activityEventViewForEvent(repositories map[int64]domain.Repository, users map[int64]auth.User, event audit.Event) activityEventView {
	details, detailsOK := parseActivityDetails(event.DetailsJSON)
	definition, actionOK := activityActionDefinitions[event.Action]
	if !detailsOK || !actionOK {
		return fallbackActivityEventView(users, event, details, detailsOK)
	}

	view := activityEventView{
		CreatedAt:    activityCreatedAt(event.CreatedAt),
		Actor:        activityActor(users, event, details),
		ActionLabel:  definition.Label,
		Outcome:      definition.Outcome,
		OutcomeClass: definition.OutcomeClass,
	}

	switch event.Action {
	case audit.ActionRepositoryCreated:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = "Default branch " + activityTextOrUnavailable(details, "default_branch", 255) + "."
	case audit.ActionRepositoryWebhookSecretConfigured:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activityCredentialDetail(details, "webhook_secret_was_configured", "Webhook secret")
	case audit.ActionRepositoryStatusTokenConfigured:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activityCredentialDetail(details, "status_token_was_configured", "Status token")
	case audit.ActionRepositoryOpenPullRequestsSynced:
		view.Target = activityRepositoryTarget(repositories, event, details, "target_branch")
		view.Detail = activityCountOrUnknown(details, "open_count") + " open PRs synchronized; " + activityCountOrUnknown(details, "closed_absent_count") + " cached PRs marked closed."
	case audit.ActionRepositoryBranchAdded:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Exact managed branch added."
	case audit.ActionRepositoryBranchRemoved:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Exact managed branch removed."
	case audit.ActionRepositorySetupCheckRun:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activitySetupCheckDetail(details)
	case audit.ActionRepositorySetupDriftDetected:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activityCountOrUnknown(details, "drifted_branches") + " managed branches reported setup drift."
	case audit.ActionRepositoryStatusPostVerified:
		view.Target = activityRepositoryTarget(repositories, event, details, "default_branch")
		view.Detail = "Controlled " + domain.SetupStatusContext + " post verified at head " + activityHeadOrUnavailable(details, "head_sha") + "."
	case audit.ActionRepositoryStatusPostVerifyFailed:
		view.Target = activityRepositoryTarget(repositories, event, details, "default_branch")
		view.Detail = activityFailureDetail(details)
	case audit.ActionRepositoryEnforcementActivated, audit.ActionRepositoryEnforcementReconciled, audit.ActionRepositoryEnforcementRecovered:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activityEnforcementSuccessDetail(details)
	case audit.ActionRepositoryEnforcementDeactivated:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = "Current freeze policy converged to success; enforcement is inactive and the repository is ready for maintenance."
	case audit.ActionRepositoryEnforcementActivateFail, audit.ActionRepositoryEnforcementReconcileFail, audit.ActionRepositoryEnforcementRecoverFail:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activityFailureDetail(details)
	case audit.ActionRepositoryRuntimeConvergenceFail:
		view.Target = activityRepositoryTarget(repositories, event, details, "")
		view.Detail = activityFailureDetail(details) + " Automatic recovery remains pending."
	case audit.ActionBranchFreezeCreated, audit.ActionBranchFreezeEnded, audit.ActionBranchFreezeCancelled:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Reason: " + activityTextOrUnavailable(details, "reason", scheduledFreezeReasonMaxLength) + "."
	case audit.ActionBranchFreezePlannedUnfreeze, audit.ActionFreezeSchedulePlannedUnfreeze:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at", false) + ". Reason: " + activityTextOrUnavailable(details, "reason", scheduledFreezeReasonMaxLength) + "."
	case audit.ActionFreezeScheduleCreated:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Starts " + activityTimeOrUnavailable(details, "starts_at", false) + "; planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at", true) + ". Reason: " + activityTextOrUnavailable(details, "reason", scheduledFreezeReasonMaxLength) + "."
	case audit.ActionFreezeScheduleUpdated:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = activityScheduleUpdateDetail(details)
	case audit.ActionFreezeScheduleCancelled:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Reason: " + activityTextOrUnavailable(details, "reason", scheduledFreezeReasonMaxLength) + "."
	case audit.ActionFreezeScheduleActivated, audit.ActionFreezeScheduleStartedNow:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Started " + activityTimeOrUnavailable(details, "starts_at", false) + "; planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at", true) + ". Reason: " + activityTextOrUnavailable(details, "reason", scheduledFreezeReasonMaxLength) + "."
	case audit.ActionThawExceptionApproved:
		view.Target = activityPullRequestTarget(repositories, event, details)
		view.Detail = "Branch " + activityTextOrUnavailable(details, "target_branch", 255) + "; head " + activityHeadOrUnavailable(details, "head_sha") + ". Reason: " + activityTextOrUnavailable(details, "reason", 500) + "."
	case audit.ActionThawExceptionSharedHeadApproved:
		view.Target = activitySharedHeadTarget(repositories, event, details)
		view.Detail = activitySharedHeadDetail(details)
	case audit.ActionUserRolesUpdated:
		view.Target = activityUserTarget(users, event.SubjectID)
		view.Detail = "Roles " + activityRolesOrUnavailable(details, "roles_before") + " → " + activityRolesOrUnavailable(details, "roles_after") + "."
	case audit.ActionUserDisabled:
		view.Target = activityUserTarget(users, event.SubjectID)
		view.Detail = "Login blocked and all sessions revoked."
	case audit.ActionUserEnabled:
		view.Target = activityUserTarget(users, event.SubjectID)
		view.Detail = "Login allowed again; previous sessions were not restored."
	case audit.ActionUserPasswordChanged:
		view.Target = activityUserTarget(users, event.SubjectID)
		view.Detail = "Self-service password change; previous sessions revoked."
	case audit.ActionUserPasswordReset:
		view.Target = activityUserTarget(users, event.SubjectID)
		view.Detail = "Temporary password set by an admin; all sessions revoked and a new password is required at next login."
	default:
		return fallbackActivityEventView(users, event, details, true)
	}
	return view
}

func fallbackActivityEventView(users map[int64]auth.User, event audit.Event, details activityDetails, detailsOK bool) activityEventView {
	if !detailsOK {
		details = activityDetails{}
	}
	return activityEventView{
		CreatedAt:    activityCreatedAt(event.CreatedAt),
		Actor:        activityActor(users, event, details),
		ActionLabel:  "Unrecognized activity",
		Target:       activityFallbackTarget(event),
		Outcome:      "Unknown",
		OutcomeClass: "warning",
		Detail:       "Stored audit details could not be displayed safely.",
	}
}

func parseActivityDetails(raw string) (activityDetails, bool) {
	if strings.TrimSpace(raw) == "" {
		return activityDetails{}, true
	}
	var details activityDetails
	if err := json.Unmarshal([]byte(raw), &details); err != nil || details == nil {
		return nil, false
	}
	return details, true
}

func activityCreatedAt(createdAt time.Time) string {
	if createdAt.IsZero() {
		return "Time unavailable"
	}
	return createdAt.UTC().Format("2006-01-02 15:04 UTC")
}

func activityActor(users map[int64]auth.User, event audit.Event, details activityDetails) string {
	if event.ActorUserID != nil && *event.ActorUserID > 0 {
		if user, ok := users[*event.ActorUserID]; ok {
			if displayName, ok := safeActivityText(user.DisplayName, 120); ok {
				return displayName
			}
		}
		return "User #" + strconv.FormatInt(*event.ActorUserID, 10)
	}
	kind, _ := activityTextDetail(details, "actor_kind", 64)
	role, _ := activityTextDetail(details, "actor_role", 64)
	switch kind {
	case domain.ActorKindBootstrapAdmin:
		return "Bootstrap admin"
	case domain.ActorKindSystem:
		switch role {
		case "scheduler":
			return "Scheduler"
		case "reconciliation_runner":
			return "Reconciliation runner"
		case "runtime":
			return "Runtime process"
		case "":
			return "System process"
		default:
			return "Unknown system actor"
		}
	default:
		return "Unknown system actor"
	}
}

func activityRepositoryTarget(repositories map[int64]domain.Repository, event audit.Event, details activityDetails, branchKey string) string {
	repositoryID, ok := activityRepositoryID(event, details)
	label := "Repository unavailable"
	if ok {
		if repo, found := repositories[repositoryID]; found {
			label = repo.FullName()
		} else {
			label = "Repository #" + strconv.FormatInt(repositoryID, 10)
		}
	}
	if branchKey == "" {
		return label
	}
	branch, branchOK := activityTextDetail(details, branchKey, 255)
	if !branchOK {
		return label + " → branch unavailable"
	}
	if branch == "all" {
		return label + " → all managed branches"
	}
	return label + " → " + branch
}

func activityRepositoryID(event audit.Event, details activityDetails) (int64, bool) {
	if repositoryID, ok := activityPositiveInt64Detail(details, "repository_id"); ok {
		return repositoryID, true
	}
	if event.SubjectType == audit.SubjectTypeRepository {
		repositoryID, err := strconv.ParseInt(strings.TrimSpace(event.SubjectID), 10, 64)
		return repositoryID, err == nil && repositoryID > 0
	}
	return 0, false
}

func activityPullRequestTarget(repositories map[int64]domain.Repository, event audit.Event, details activityDetails) string {
	target := activityRepositoryTarget(repositories, event, details, "")
	if index, ok := activityPositiveInt64Detail(details, "pull_request_index"); ok && index <= 1_000_000 {
		return target + " → PR #" + strconv.FormatInt(index, 10)
	}
	return target + " → PR unavailable"
}

func activitySharedHeadTarget(repositories map[int64]domain.Repository, event audit.Event, details activityDetails) string {
	target := activityRepositoryTarget(repositories, event, details, "")
	if head, ok := activityHeadDetail(details, "head_sha"); ok {
		return target + " → shared head " + head
	}
	return target + " → shared head unavailable"
}

func activityUserTarget(users map[int64]auth.User, subjectID string) string {
	userID, err := strconv.ParseInt(strings.TrimSpace(subjectID), 10, 64)
	if err != nil || userID <= 0 {
		return "User unavailable"
	}
	if user, ok := users[userID]; ok {
		if displayName, ok := safeActivityText(user.DisplayName, 120); ok {
			return displayName + " (User #" + strconv.FormatInt(userID, 10) + ")"
		}
	}
	return "User #" + strconv.FormatInt(userID, 10)
}

func activityFallbackTarget(event audit.Event) string {
	id, err := strconv.ParseInt(strings.TrimSpace(event.SubjectID), 10, 64)
	if err != nil || id <= 0 {
		switch event.SubjectType {
		case audit.SubjectTypeRepository:
			return "Repository unavailable"
		case audit.SubjectTypeBranchFreeze:
			return "Freeze unavailable"
		case audit.SubjectTypeThawException:
			return "Thaw exception unavailable"
		case audit.SubjectTypeUser:
			return "User unavailable"
		default:
			return "Other target"
		}
	}
	switch event.SubjectType {
	case audit.SubjectTypeRepository:
		return "Repository #" + strconv.FormatInt(id, 10)
	case audit.SubjectTypeBranchFreeze:
		return "Freeze #" + strconv.FormatInt(id, 10)
	case audit.SubjectTypeThawException:
		return "Thaw exception #" + strconv.FormatInt(id, 10)
	case audit.SubjectTypeUser:
		return "User #" + strconv.FormatInt(id, 10)
	default:
		return "Other target"
	}
}

func activityTextDetail(details activityDetails, key string, maxLength int) (string, bool) {
	raw, ok := details[key]
	if !ok {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return safeActivityText(value, maxLength)
}

func safeActivityText(value string, maxLength int) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxLength {
		return "", false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return value, true
}

func activityPositiveInt64Detail(details activityDetails, key string) (int64, bool) {
	value, ok := activityInt64Detail(details, key)
	return value, ok && value > 0
}

func activityNonnegativeInt64Detail(details activityDetails, key string) (int64, bool) {
	value, ok := activityInt64Detail(details, key)
	return value, ok && value >= 0 && value <= 1_000_000_000
}

func activityInt64Detail(details activityDetails, key string) (int64, bool) {
	raw, ok := details[key]
	if !ok {
		return 0, false
	}
	var number int64
	if err := json.Unmarshal(raw, &number); err == nil {
		return number, true
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, false
	}
	number, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return number, err == nil
}

func activityBoolDetail(details activityDetails, key string) (bool, bool) {
	raw, ok := details[key]
	if !ok {
		return false, false
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err == nil {
		return value, true
	}
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return false, false
	}
	value, err := strconv.ParseBool(strings.TrimSpace(text))
	return value, err == nil
}

func activityTextOrUnavailable(details activityDetails, key string, maxLength int) string {
	if value, ok := activityTextDetail(details, key, maxLength); ok {
		return value
	}
	return "unavailable"
}

func activityCountOrUnknown(details activityDetails, key string) string {
	if value, ok := activityNonnegativeInt64Detail(details, key); ok {
		return strconv.FormatInt(value, 10)
	}
	return "unknown"
}

func activityCredentialDetail(details activityDetails, key, credential string) string {
	if replaced, ok := activityBoolDetail(details, key); ok {
		if replaced {
			return credential + " rotated; the value remains hidden."
		}
		return credential + " set; the value remains hidden."
	}
	return credential + " configuration recorded; the value remains hidden."
}

func activitySetupCheckDetail(details activityDetails) string {
	webhook := "webhook evidence unavailable"
	if fresh, ok := activityBoolDetail(details, "webhook_evidence_fresh"); ok {
		if fresh {
			webhook = "webhook evidence fresh"
		} else {
			webhook = "webhook evidence not fresh"
		}
	}
	return activityCountOrUnknown(details, "ok_count") + " passed, " + activityCountOrUnknown(details, "warning_count") + " warnings, " + activityCountOrUnknown(details, "failed_count") + " failed across " + activityCountOrUnknown(details, "managed_branch_count") + " managed branches; " + webhook + "."
}

func activityFailureDetail(details activityDetails) string {
	reason := "failure category unavailable"
	if value, ok := activityTextDetail(details, "reason", 120); ok && domain.ValidEnforcementFailureReason(value) {
		reason = value
	}
	state := "state unavailable"
	if value, ok := activityTextDetail(details, "enforcement_state", 32); ok && domain.EnforcementState(value).Valid() {
		state = "state " + strings.ReplaceAll(value, "_", " ")
	}
	return reason + "; " + state + "."
}

func activityEnforcementSuccessDetail(details activityDetails) string {
	return activityCountOrUnknown(details, "open_pull_request_count") + " open PRs evaluated; " + activityCountOrUnknown(details, "statuses_posted") + " statuses posted and " + activityCountOrUnknown(details, "statuses_failed") + " failed."
}

func activityTimeOrUnavailable(details activityDetails, key string, optional bool) string {
	value, ok := activityTextDetail(details, key, 64)
	if !ok {
		if optional {
			return "none"
		}
		return "time unavailable"
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return "time unavailable"
	}
	return parsed.UTC().Format("2006-01-02 15:04 UTC")
}

func activityScheduleUpdateDetail(details activityDetails) string {
	return "Reason " + activityTextOrUnavailable(details, "reason_before", scheduledFreezeReasonMaxLength) + " → " + activityTextOrUnavailable(details, "reason_after", scheduledFreezeReasonMaxLength) + "; starts " + activityTimeOrUnavailable(details, "starts_at_before", false) + " → " + activityTimeOrUnavailable(details, "starts_at_after", false) + "; planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at_before", true) + " → " + activityTimeOrUnavailable(details, "planned_ends_at_after", true) + "."
}

func activityHeadDetail(details activityDetails, key string) (string, bool) {
	value, ok := activityTextDetail(details, key, 64)
	if !ok || len(value) < 6 {
		return "", false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return "", false
		}
	}
	if len(value) > 12 {
		value = value[:12]
	}
	return strings.ToLower(value), true
}

func activityHeadOrUnavailable(details activityDetails, key string) string {
	if value, ok := activityHeadDetail(details, key); ok {
		return value
	}
	return "unavailable"
}

func activityPullRequestIndexList(details activityDetails, key string) (string, int, bool) {
	encoded, exists := details[key]
	if !exists {
		return "", 0, false
	}
	var raw string
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return "", 0, false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "none", 0, true
	}
	if _, ok := safeActivityText(raw, 512); !ok {
		return "", 0, false
	}
	parts := strings.Split(raw, ",")
	labels := make([]string, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		index, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || index <= 0 || index > 1_000_000 {
			return "", 0, false
		}
		if _, ok := seen[index]; ok {
			return "", 0, false
		}
		seen[index] = struct{}{}
		labels = append(labels, "#"+strconv.Itoa(index))
	}
	return strings.Join(labels, ", "), len(labels), true
}

func activitySharedHeadDetail(details activityDetails) string {
	created, createdCount, createdOK := activityPullRequestIndexList(details, "created_pull_request_indexes")
	covered, coveredCount, coveredOK := activityPullRequestIndexList(details, "already_covered_pull_request_indexes")
	declaredCreated, declaredCreatedOK := activityNonnegativeInt64Detail(details, "created_pull_request_count")
	declaredCovered, declaredCoveredOK := activityNonnegativeInt64Detail(details, "already_covered_pull_request_count")
	reason, reasonOK := activityTextDetail(details, "reason", 500)
	if !createdOK || !coveredOK || !declaredCreatedOK || !declaredCoveredOK || !reasonOK || int64(createdCount) != declaredCreated || int64(coveredCount) != declaredCovered || createdCount+coveredCount == 0 {
		return "Shared-head approval details unavailable."
	}
	return "New exceptions: " + created + "; already covered: " + covered + ". Confirmation reason: " + reason + "."
}

func activityRolesOrUnavailable(details activityDetails, key string) string {
	value, ok := activityTextDetail(details, key, 128)
	if !ok {
		return "unavailable"
	}
	parts := strings.Split(value, ",")
	rawRoles := make([]auth.Role, 0, len(parts))
	for _, part := range parts {
		rawRoles = append(rawRoles, auth.Role(strings.TrimSpace(part)))
	}
	roles, valid := auth.NormalizeRoleSet(rawRoles)
	if !valid || len(roles) == 0 {
		return "unavailable"
	}
	return roles.Label()
}

func webhookDeliveryProcessingState(delivery webhook.Delivery) (string, string) {
	if delivery.ProcessedAt != nil {
		if delivery.Error != "" {
			return "processed with error", "warning"
		}
		return "processed", "ok"
	}
	if delivery.ProcessingStartedAt != nil {
		return "processing", "pending"
	}
	if delivery.Error != "" {
		return "retryable failure", "failed"
	}
	return "received", "warning"
}

func webhookDeliveryVerificationState(delivery webhook.Delivery) (string, string) {
	if delivery.Verified {
		return "verified", "ok"
	}
	return "not verified", "warning"
}

func optionalWebhookDeliveryTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "—"
	}
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func (s *Server) activeFreezes(ctx context.Context) ([]domain.BranchFreeze, error) {
	if s.cfg.FreezeStore == nil {
		return nil, nil
	}
	return s.cfg.FreezeStore.ListActive(ctx)
}

func (s *Server) scheduledFreezes(ctx context.Context, limit int) ([]domain.BranchFreeze, error) {
	if s.cfg.ScheduledFreezeStore == nil {
		return nil, nil
	}
	return s.cfg.ScheduledFreezeStore.ListScheduled(ctx, limit)
}

func scheduledFreezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze, state scheduledFreezePageState) []scheduledFreezeView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]scheduledFreezeView, 0, len(freezes))
	now := time.Now().UTC()
	for _, scheduled := range freezes {
		label, stateClass := scheduledFreezeStatus(scheduled.Status)
		repo := repositoriesByID[scheduled.RepositoryID]
		pending := scheduled.Scheduled && scheduled.Status == domain.BranchFreezeStatusScheduled
		view := scheduledFreezeView{
			Freeze:           scheduled,
			Repository:       repo,
			StartsAt:         optionalScheduleTime(scheduled.StartsAt),
			StartsAtUTC:      optionalScheduleRFC3339(scheduled.StartsAt),
			PlannedEndsAt:    optionalScheduleTime(scheduled.PlannedEndsAt),
			PlannedEndsAtUTC: optionalScheduleRFC3339(scheduled.PlannedEndsAt),
			EndedAt:          optionalScheduleTime(scheduled.EndsAt),
			StatusLabel:      label,
			StateClass:       stateClass,
			CanCancel:        pending,
			CanEdit:          pending,
			EditReason:       scheduled.Reason,
		}
		// Badge fields for /scheduled-freezes: a scheduled window is not a
		// live freeze, so only Active gets the frozen tone.
		switch scheduled.Status {
		case domain.BranchFreezeStatusScheduled:
			view.StatusText, view.BadgeTone, view.BadgeIcon = "Upcoming", "scheduled", "tg-i-schedule"
		case domain.BranchFreezeStatusActive:
			view.StatusText, view.BadgeTone, view.BadgeIcon = "Active", "frozen", "tg-i-lock"
		case domain.BranchFreezeStatusEnded:
			view.StatusText, view.BadgeTone = "Completed", "neutral"
			view.SubLineLabel = "Ended"
		case domain.BranchFreezeStatusCancelled:
			view.StatusText, view.BadgeTone = "Cancelled", "neutral"
			view.SubLineLabel = "Cancelled"
		default:
			view.StatusText, view.BadgeTone = string(scheduled.Status), "neutral"
		}
		if view.SubLineLabel != "" {
			at := scheduled.EndsAt
			if at == nil || at.IsZero() {
				if !scheduled.UpdatedAt.IsZero() {
					updated := scheduled.UpdatedAt
					at = &updated
				}
			}
			if at != nil && !at.IsZero() {
				view.SubLineTime = optionalScheduleTime(at)
				view.SubLineUTC = optionalScheduleRFC3339(at)
			} else {
				view.SubLineLabel = ""
			}
		}
		if pending {
			switch {
			case !repo.EnforcementActive():
				view.StartNowBlockedReason = "Start Now unavailable: activate repository enforcement first."
			case scheduled.StartsAt == nil || !scheduled.StartsAt.After(now):
				view.StartNowBlockedReason = "Start Now unavailable: the scheduled start has arrived."
			case scheduled.PlannedEndsAt != nil && !scheduled.PlannedEndsAt.After(now):
				view.StartNowBlockedReason = "Edit the planned unfreeze before using Start Now."
			default:
				view.CanStartNow = true
			}
		}
		if pending && state.EditScheduleID == scheduled.ID {
			view.EditOpen = true
			view.EditSubmitted = true
			view.EditReason = state.EditReason
			view.EditStartsAt = state.EditStartsAt
			view.EditPlannedEndsAt = state.EditPlannedEndsAt
		}
		views = append(views, view)
	}
	return views
}

func userViews(users []auth.User, state usersPageState, session sessionState) []userView {
	views := make([]userView, 0, len(users))
	for _, user := range users {
		roleLabel := user.Roles.Label()
		if roleLabel == "" {
			roleLabel = user.Role.Label()
		}
		roleFormRoles := user.Roles
		if state.RoleFormUserID != 0 && state.RoleFormUserID == user.ID {
			roleFormRoles = state.RoleFormRoles
		}
		isSelf := session.UserID != nil && *session.UserID == user.ID
		views = append(views, userView{
			User:          user,
			RoleLabel:     roleLabel,
			CreatedAt:     user.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			IsSelf:        isSelf,
			RoleOptions:   roleOptionsFor(roleFormRoles),
			ResetFormOpen: !isSelf && state.ResetFormUserID != 0 && state.ResetFormUserID == user.ID,
		})
	}
	return views
}

func roleOptionsFor(selected auth.RoleSet) []roleOption {
	roles := auth.Roles()
	options := make([]roleOption, 0, len(roles))
	for _, role := range roles {
		options = append(options, roleOption{Value: string(role), Label: role.Label(), Selected: selected.Contains(role)})
	}
	return options
}

func rolesFromForm(r *http.Request) []auth.Role {
	roles := make([]auth.Role, 0, len(r.PostForm["roles"]))
	for _, role := range r.PostForm["roles"] {
		roles = append(roles, auth.Role(strings.TrimSpace(role)))
	}
	return roles
}

func scheduledFreezeStatus(status domain.BranchFreezeStatus) (string, string) {
	switch status {
	case domain.BranchFreezeStatusScheduled:
		return "upcoming", "pending"
	case domain.BranchFreezeStatusActive:
		return "active", "failed"
	case domain.BranchFreezeStatusEnded:
		return "completed", "ok"
	case domain.BranchFreezeStatusCancelled:
		return "cancelled", "warning"
	default:
		return string(status), "info"
	}
}

func optionalScheduleTime(value *time.Time) string {
	if value == nil || value.IsZero() {
		return "—"
	}
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func optionalScheduleRFC3339(value *time.Time) string {
	if value == nil || value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func repositoriesByID(repositories []domain.Repository) map[int64]domain.Repository {
	byID := make(map[int64]domain.Repository, len(repositories))
	for _, repo := range repositories {
		byID[repo.ID] = repo
	}
	return byID
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

func (s *Server) managedBranches(ctx context.Context, repositoryID int64) ([]domain.RepositoryBranch, error) {
	if s.cfg.RepositoryStore == nil {
		return nil, nil
	}
	return s.cfg.RepositoryStore.ListBranches(ctx, repositoryID)
}

// managedBranchOptions lists the exact managed branches of every
// enforcement-active repository for the freeze and schedule forms.
func (s *Server) managedBranchOptions(ctx context.Context, repositories []domain.Repository) ([]managedBranchOption, error) {
	options := make([]managedBranchOption, 0)
	for _, repo := range repositories {
		if !repo.EnforcementActive() {
			continue
		}
		branches, err := s.managedBranches(ctx, repo.ID)
		if err != nil {
			return nil, err
		}
		for _, branch := range branches {
			options = append(options, managedBranchOption{RepositoryID: repo.ID, Name: branch.Name})
		}
	}
	return options, nil
}

// enforcementActiveRepositories keeps mutation forms scoped to repositories
// that may enforce freezes; server-side gating remains authoritative.
func enforcementActiveRepositories(repositories []domain.Repository) []domain.Repository {
	enforceable := make([]domain.Repository, 0, len(repositories))
	for _, repo := range repositories {
		if repo.EnforcementActive() {
			enforceable = append(enforceable, repo)
		}
	}
	return enforceable
}

func (s *Server) renderUsers(w http.ResponseWriter, users []auth.User, state usersPageState, session sessionState) {
	s.render(w, usersTemplate, map[string]any{
		"AppName":     s.cfg.AppName,
		"ActivePage":  "users",
		"CurrentUser": currentUserFromSession(session),
		"CSRFToken":   session.CSRFToken,
		"Users":       userViews(users, state, session),
		"UserCount":   len(users),
		"FormError":   state.FormError,
		"RoleOptions": roleOptionsFor(state.CreateRoles),
	})
}

func (s *Server) renderPublications(w http.ResponseWriter, publications []statusPublicationView, attempts []statusPublicationAttemptView, session sessionState) {
	s.render(w, publicationsTemplate, map[string]any{
		"AppName":      s.cfg.AppName,
		"ActivePage":   "",
		"CurrentUser":  currentUserFromSession(session),
		"CSRFToken":    session.CSRFToken,
		"Publications": publications,
		"Attempts":     attempts,
	})
}

func (s *Server) renderWebhookDeliveries(w http.ResponseWriter, auditLog auditLogView, session sessionState) {
	s.render(w, webhookDeliveriesTemplate, map[string]any{
		"AppName":                 s.cfg.AppName,
		"ActivePage":              "",
		"CurrentUser":             currentUserFromSession(session),
		"CSRFToken":               session.CSRFToken,
		"Deliveries":              auditLog.Deliveries,
		"Filters":                 auditLog.Filters,
		"RepositoryFilterOptions": auditLog.RepositoryFilterOptions,
		"EventFilterOptions":      auditLog.EventFilterOptions,
		"ProcessingFilterOptions": auditLog.ProcessingFilterOptions,
		"SortOptions":             auditLog.SortOptions,
		"DirectionOptions":        auditLog.DirectionOptions,
		"LimitOptions":            auditLog.LimitOptions,
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

func (s *Server) renderSetupStatus(w http.ResponseWriter, r *http.Request, email, displayName, formError string, status int) {
	csrfToken, err := s.newSetupCSRFToken(w, r)
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	}
	s.renderPageStatus(w, status, "layouts/setup", authSetupData{
		AppName:     s.cfg.AppName,
		PageTitle:   "Set up",
		CSRFField:   csrfFormField,
		CSRFToken:   csrfToken,
		FormError:   formError,
		Email:       email,
		DisplayName: displayName,
	})
}

func (s *Server) renderLoginStatus(w http.ResponseWriter, r *http.Request, email, formError string, status int) {
	csrfToken, err := s.newLoginCSRFToken(w, r)
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, true)
		return
	}
	s.renderPageStatus(w, status, "layouts/login", authLoginData{
		AppName:   s.cfg.AppName,
		PageTitle: "Sign in",
		CSRFField: csrfFormField,
		CSRFToken: csrfToken,
		FormError: formError,
		Email:     email,
	})
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
<body>
  <svg class="tg-icon-sprite" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg">
    <symbol id="tg-i-icy-shield" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 21.7c4.5-2.2 7-5.7 7-9.7V5.3L12 2.6 5 5.3V12c0 4 2.5 7.5 7 9.7z M12 8v8 M8.5 10l7 4 M15.5 10l-7 4"/></symbol>
    <symbol id="tg-i-freeze-branch" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M6 3v12 M9 18a3 3 0 1 1-6 0 3 3 0 0 1 6 0z M18 9a9 9 0 0 1-9 9 M18 3v6 M15.4 4.5l5.2 3 M20.6 4.5l-5.2 3"/></symbol>
    <symbol id="tg-i-thaw-drop" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 3v6 M9.4 4.5l5.2 3 M14.6 4.5l-5.2 3 M12 13c-2 3-3 4.2-3 5.8a3 3 0 0 0 6 0c0-1.6-1-2.8-3-5.8z"/></symbol>
    <symbol id="tg-i-dashboard" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M10 3H4a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1z M20 3h-6a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4a1 1 0 0 0-1-1z M20 11h-6a1 1 0 0 0-1 1v6a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-6a1 1 0 0 0-1-1z M10 15H4a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-2a1 1 0 0 0-1-1z"/></symbol>
    <symbol id="tg-i-repositories" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20 M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z M9 7h7"/></symbol>
    <symbol id="tg-i-schedule" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4.5 M16 2v4 M8 2v4 M3 10h6 M17.5 22a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11z M17.5 14v2.5l1.5 1"/></symbol>
    <symbol id="tg-i-activity" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M22 12h-4l-3 9L9 3l-3 9H2"/></symbol>
    <symbol id="tg-i-audit" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z M14 2v6h6 M8 13h8 M8 17h5"/></symbol>
    <symbol id="tg-i-users" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75"/></symbol>
    <symbol id="tg-i-warning" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M21.73 18l-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3z M12 9v4 M12 17h.01"/></symbol>
    <symbol id="tg-i-check" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M20 6L9 17l-5-5"/></symbol>
    <symbol id="tg-i-play" viewBox="0 0 24 24"><path fill="currentColor" stroke="none" d="M7 4.5v15l12-7.5z"/></symbol>
    <symbol id="tg-i-close" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M18 6L6 18 M6 6l12 12"/></symbol>
    <symbol id="tg-i-plus" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 5v14 M5 12h14"/></symbol>
    <symbol id="tg-i-key" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M7.5 14.5a4.5 4.5 0 1 1 3.18-7.68A4.5 4.5 0 0 1 12 10l8-8 M15.5 6.5l2 2 M17.5 4.5l2 2"/></symbol>
    <symbol id="tg-i-git-branch" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M6 4v10 M18 6a6 6 0 0 1-6 6H6 M8 18a2 2 0 1 1-4 0 2 2 0 0 1 4 0z M20 6a2 2 0 1 1-4 0 2 2 0 0 1 4 0z"/></symbol>
    <symbol id="tg-i-health-check" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 21a9 9 0 1 1 0-18 9 9 0 0 1 0 18z M5.8 12h3l1.4-3.8 2.7 7.6 1.5-3.8h3.8 M15.8 8.2l1.2 1.2 2.2-2.4"/></symbol>
    <symbol id="tg-i-lock" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M6 11h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1z M8 11V7a4 4 0 0 1 8 0v4 M12 15v2.5"/></symbol>
    <symbol id="tg-i-search" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z M21 21l-4.35-4.35"/></symbol>
    <symbol id="tg-i-branch-impact" viewBox="0 0 12 16"><path fill="currentColor" fill-rule="evenodd" d="M11 11.28V5c-.03-.78-.34-1.47-.94-2.06C9.46 2.35 8.78 2.03 8 2H7V0L4 3l3 3V4h1c.27.02.48.11.69.31.21.2.3.42.31.69v6.28A1.993 1.993 0 0 0 10 15a1.993 1.993 0 0 0 1-3.72zm-1 2.92c-.66 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2zM4 3c0-1.11-.89-2-2-2a1.993 1.993 0 0 0-1 3.72v6.56A1.993 1.993 0 0 0 2 15a1.993 1.993 0 0 0 1-3.72V4.72c.59-.34 1-.98 1-1.72zm-.8 10c0 .66-.55 1.2-1.2 1.2-.65 0-1.2-.55-1.2-1.2 0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2zM2 4.2C1.34 4.2.8 3.65.8 3c0-.65.55-1.2 1.2-1.2.65 0 1.2.55 1.2 1.2 0 .65-.55 1.2-1.2 1.2z"/></symbol>
  </svg>
  <div class="tg-app">
    <aside class="tg-sidebar" aria-label="Primary navigation">
      <a class="tg-logo" href="/" aria-label="{{ .AppName }} dashboard">
        <span class="tg-logo-mark" aria-hidden="true"><svg class="tg-brand-icon"><use href="#tg-i-icy-shield"></use></svg></span>
        <span>{{ .AppName }}</span>
      </a>
      <nav class="tg-nav">
        <a class="tg-nav-item{{ if eq .ActivePage "dashboard" }} is-active{{ end }}" href="/"><svg class="tg-icon"><use href="#tg-i-dashboard"></use></svg>Dashboard</a>
        <a class="tg-nav-item{{ if eq .ActivePage "repositories" }} is-active{{ end }}" href="/repositories"><svg class="tg-icon"><use href="#tg-i-repositories"></use></svg>Repositories</a>
        <a class="tg-nav-item{{ if eq .ActivePage "freezes" }} is-active{{ end }}" href="/freezes"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg>Freezes</a>
        <a class="tg-nav-item{{ if eq .ActivePage "scheduled" }} is-active{{ end }}" href="/scheduled-freezes"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg>Scheduled Freezes</a>
        <a class="tg-nav-item{{ if eq .ActivePage "thaws" }} is-active{{ end }}" href="/decisions"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Thaw Requests</a>
        <a class="tg-nav-item{{ if eq .ActivePage "activity" }} is-active{{ end }}" href="/activity"><svg class="tg-icon"><use href="#tg-i-activity"></use></svg>Activity</a>
        {{ if .CurrentUser.IsAdmin }}<a class="tg-nav-item{{ if eq .ActivePage "users" }} is-active{{ end }}" href="/users"><svg class="tg-icon"><use href="#tg-i-users"></use></svg>Users & Roles</a>{{ end }}
      </nav>
      {{ if .CurrentUser.Email }}
      <div class="tg-sidebar-user">
        <strong>{{ .CurrentUser.DisplayName }}</strong>
        <span>{{ .CurrentUser.Email }}</span>
        <span class="tg-badge tg-badge-info">{{ .CurrentUser.RoleLabel }}</span>
        {{ if .CurrentUser.CanChangePassword }}<a class="tg-btn tg-btn-secondary tg-btn-sm" href="/account/password">Change password</a>{{ end }}
        <form method="post" action="/logout">
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Log out</button>
        </form>
      </div>
      {{ end }}
      <div class="tg-sidebar-note">
        <span class="tg-status-dot"></span>
        <span>Cooperative enforcement</span>
      </div>
    </aside>
    <div class="tg-content">`

const pageFoot = `
    <div class="tg-alert-dialog" data-alert-dialog hidden role="dialog" aria-modal="true" aria-labelledby="tg-confirm-title" aria-describedby="tg-confirm-message">
      <button type="button" class="tg-alert-backdrop" data-alert-cancel aria-label="Close confirmation"></button>
      <div class="tg-alert-card">
        <h2 id="tg-confirm-title" data-alert-title>Confirm action</h2>
        <p id="tg-confirm-message" data-alert-message>Continue?</p>
        <div class="tg-alert-actions">
          <button type="button" class="tg-btn tg-btn-secondary" data-alert-cancel>Cancel</button>
          <button type="button" class="tg-btn tg-btn-primary" data-alert-confirm>Continue</button>
        </div>
      </div>
    </div>
  </div></div>
  <script>
    (() => {
      const dialog = document.querySelector('[data-alert-dialog]');
      if (!dialog) return;
      const title = dialog.querySelector('[data-alert-title]');
      const message = dialog.querySelector('[data-alert-message]');
      const confirm = dialog.querySelector('[data-alert-confirm]');
      let pendingConfirm = null;

      const closeDialog = () => {
        dialog.hidden = true;
        pendingConfirm = null;
      };

      const openDialog = (trigger, onConfirm) => {
        pendingConfirm = onConfirm;
        title.textContent = trigger.getAttribute('data-confirm-title') || 'Confirm action';
        message.textContent = trigger.getAttribute('data-confirm-message') || 'Continue?';
        confirm.textContent = trigger.getAttribute('data-confirm-action') || 'Continue';
        dialog.hidden = false;
        confirm.focus();
      };

      document.querySelectorAll('[data-alert-cancel]').forEach((button) => {
        button.addEventListener('click', closeDialog);
      });

      document.querySelectorAll('[data-confirm-submit]').forEach((form) => {
        form.addEventListener('submit', (event) => {
          if (form.dataset.confirmed === 'true') {
            delete form.dataset.confirmed;
            return;
          }
          event.preventDefault();
          openDialog(form, () => {
            form.dataset.confirmed = 'true';
            if (typeof form.requestSubmit === 'function') {
              form.requestSubmit();
              return;
            }
            form.submit();
          });
        });
      });

      document.querySelectorAll('[data-credential-reveal]').forEach((button) => {
        button.addEventListener('click', () => {
          openDialog(button, () => {
            const target = document.getElementById(button.getAttribute('data-credential-target'));
            if (target) {
              target.hidden = false;
              target.querySelectorAll('[data-credential-input]').forEach((input) => { input.disabled = false; });
              target.querySelector('[data-credential-input]')?.focus();
            }
            button.hidden = true;
            button.setAttribute('aria-expanded', 'true');
          });
        });
      });

      document.querySelectorAll('[data-credential-cancel]').forEach((button) => {
        button.addEventListener('click', () => {
          const form = button.closest('[data-credential-form]');
          const block = button.closest('[data-credential-block]');
          const trigger = block?.querySelector('[data-credential-reveal]');
          if (form) {
            form.reset();
            form.hidden = true;
            form.querySelectorAll('[data-credential-input]').forEach((input) => { input.disabled = true; });
          }
          if (trigger) {
            trigger.hidden = false;
            trigger.setAttribute('aria-expanded', 'false');
            trigger.focus();
          }
        });
      });

      confirm.addEventListener('click', () => {
        const callback = pendingConfirm;
        closeDialog();
        if (callback) callback();
      });

      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && !dialog.hidden) closeDialog();
      });
    })();
  </script>
</body></html>`

const usersTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-users-page">
    <header class="tg-header">
      <div>
        <p class="eyebrow">Local access control</p>
        <h1 class="tg-title">Users & Roles</h1>
        <p class="tg-subtitle">Create local users and assign one or more narrow MVP roles used by Thawguard route gates.</p>
      </div>
      <span class="tg-badge tg-badge-info">{{ .UserCount }} users</span>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
    <section class="tg-panel tg-users-panel">
      <div class="tg-panel-head tg-panel-head-stacked">
        <div>
          <h2>Add user</h2>
          <p class="tg-panel-subtitle">Admins manage repositories, users, roles, tokens, and webhook secrets. Freezers create and end freezes. Thaw approvers approve PR exceptions. Viewers can read dashboards and audit history. Add action roles explicitly; admin alone does not freeze or approve thaws.</p>
        </div>
      </div>
      <form method="post" action="/users" class="tg-setup-form tg-users-form">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label>Email <input type="email" name="email" autocomplete="email" required></label>
        <label>Display name <input name="display_name" autocomplete="name" required></label>
        <label>Password <input type="password" name="password" autocomplete="new-password" minlength="12" required></label>
        <fieldset class="tg-role-fieldset">
          <legend>Roles</legend>
          {{ range .RoleOptions }}
          <label class="tg-role-check"><input type="checkbox" name="roles" value="{{ .Value }}"{{ if .Selected }} checked{{ end }}> {{ .Label }}</label>
          {{ end }}
        </fieldset>
        <div class="tg-form-submit tg-field-wide"><button type="submit" class="tg-btn tg-btn-primary">Create user</button></div>
      </form>
    </section>

    <section class="tg-panel tg-data-panel tg-users-panel">
      <div class="tg-panel-head"><h2>Configured users</h2><span class="tg-badge tg-badge-info">local auth</span></div>
      <p class="tg-panel-subtitle">Thawguard never commits a state without an enabled admin: the final enabled admin cannot be disabled or lose the admin role. Disabling a user revokes all of their sessions; re-enabling does not restore old sessions. Password resets sign the user out everywhere and force a new password on their next login.</p>
      {{ if .Users }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-users-table">
          <caption class="tg-sr-only">Configured Thawguard users</caption>
          <thead><tr><th>Name</th><th>Email</th><th>Status</th><th>Roles</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody>
          {{ range .Users }}
            <tr>
              <td data-label="Name">{{ .User.DisplayName }}{{ if .IsSelf }} <span class="tg-muted">(you)</span>{{ end }}</td>
              <td data-label="Email"><code>{{ .User.Email }}</code></td>
              <td data-label="Status">{{ if .User.Disabled }}<span class="status status-warning">Disabled</span>{{ else }}<span class="status status-ok">Enabled</span>{{ end }}</td>
              <td data-label="Roles">
                <form method="post" action="/users/roles" class="tg-user-roles-form">
                  <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="user_id" value="{{ .User.ID }}">
                  {{ $userID := .User.ID }}
                  {{ range .RoleOptions }}
                  <label class="tg-role-check"><input type="checkbox" id="user-roles-{{ $userID }}-{{ .Value }}" name="roles" value="{{ .Value }}"{{ if .Selected }} checked{{ end }}> {{ .Label }}</label>
                  {{ end }}
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Save roles</button>
                </form>
              </td>
              <td data-label="Created">{{ .CreatedAt }}</td>
              <td data-label="Actions">
                <div class="tg-user-actions">
                  {{ if .User.Disabled }}
                  <form method="post" action="/users/enable">
                    <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                    <input type="hidden" name="user_id" value="{{ .User.ID }}">
                    <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Re-enable</button>
                  </form>
                  <p class="tg-muted">Re-enabling does not restore old sessions.</p>
                  {{ else }}
                  <form method="post" action="/users/disable" data-confirm-submit data-confirm-title="Disable user?" data-confirm-message="{{ if .IsSelf }}Disabling your own account revokes all of your sessions and signs you out immediately. The final enabled admin cannot be disabled.{{ else }}The user can no longer log in and all of their sessions are revoked. Their password and roles are kept for later re-enabling. The final enabled admin cannot be disabled.{{ end }}" data-confirm-action="Disable user">
                    <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                    <input type="hidden" name="user_id" value="{{ .User.ID }}">
                    <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Disable</button>
                  </form>
                  {{ end }}
                  {{ if .IsSelf }}
                  <p class="tg-muted">Use “Change password” for your own account.</p>
                  {{ else }}
                  <div data-credential-block>
                    <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm"{{ if .ResetFormOpen }} hidden{{ end }} data-credential-reveal data-credential-target="reset-password-{{ .User.ID }}" data-confirm-title="Reset password?" data-confirm-message="This sets an admin-entered temporary password, revokes every session for the user, and forces them to choose a new password on their next login. It does not re-enable a disabled account." data-confirm-action="Open reset form" aria-controls="reset-password-{{ .User.ID }}" aria-expanded="{{ if .ResetFormOpen }}true{{ else }}false{{ end }}"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>Reset password</button>
                    <form id="reset-password-{{ .User.ID }}"{{ if not .ResetFormOpen }} hidden{{ end }} method="post" action="/users/reset-password" class="tg-user-reset-form" data-credential-form>
                      {{ if and .ResetFormOpen $.FormError }}<p class="error">{{ $.FormError }}</p>{{ end }}
                      <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                      <input type="hidden" name="user_id" value="{{ .User.ID }}">
                      <label>Temporary password <input type="password" name="temporary_password" data-credential-input{{ if not .ResetFormOpen }} disabled{{ end }} minlength="12" autocomplete="new-password" required></label>
                      <label>Confirm temporary password <input type="password" name="temporary_password_confirmation" data-credential-input{{ if not .ResetFormOpen }} disabled{{ end }} minlength="12" autocomplete="new-password" required></label>
                      <div class="tg-credential-form-actions">
                        <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm">Set temporary password</button>
                        <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm" data-credential-cancel>Cancel</button>
                      </div>
                    </form>
                  </div>
                  {{ end }}
                </div>
              </td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      <div class="tg-mobile-card-list" aria-label="Configured users mobile cards">
        {{ range .Users }}
        <article class="tg-mobile-card">
          <div class="tg-mobile-card-head">
            <div>
              <span class="tg-mobile-card-kicker">Created {{ .CreatedAt }}</span>
              <h3>{{ .User.DisplayName }}{{ if .IsSelf }} <span class="tg-muted">(you)</span>{{ end }}</h3>
            </div>
            {{ if .User.Disabled }}<span class="status status-warning">Disabled</span>{{ else }}<span class="status status-ok">Enabled</span>{{ end }}
          </div>
          <p class="tg-mobile-card-meta"><code>{{ .User.Email }}</code></p>
          <form method="post" action="/users/roles" class="tg-user-roles-form">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="user_id" value="{{ .User.ID }}">
            {{ $userID := .User.ID }}
            {{ range .RoleOptions }}
            <label class="tg-role-check"><input type="checkbox" id="user-roles-m-{{ $userID }}-{{ .Value }}" name="roles" value="{{ .Value }}"{{ if .Selected }} checked{{ end }}> {{ .Label }}</label>
            {{ end }}
            <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Save roles</button>
          </form>
          <div class="tg-user-actions">
            {{ if .User.Disabled }}
            <form method="post" action="/users/enable">
              <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
              <input type="hidden" name="user_id" value="{{ .User.ID }}">
              <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Re-enable</button>
            </form>
            <p class="tg-muted">Re-enabling does not restore old sessions.</p>
            {{ else }}
            <form method="post" action="/users/disable" data-confirm-submit data-confirm-title="Disable user?" data-confirm-message="{{ if .IsSelf }}Disabling your own account revokes all of your sessions and signs you out immediately. The final enabled admin cannot be disabled.{{ else }}The user can no longer log in and all of their sessions are revoked. Their password and roles are kept for later re-enabling. The final enabled admin cannot be disabled.{{ end }}" data-confirm-action="Disable user">
              <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
              <input type="hidden" name="user_id" value="{{ .User.ID }}">
              <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Disable</button>
            </form>
            {{ end }}
            {{ if .IsSelf }}
            <p class="tg-muted">Use “Change password” for your own account.</p>
            {{ else }}
            <div data-credential-block>
              <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm"{{ if .ResetFormOpen }} hidden{{ end }} data-credential-reveal data-credential-target="reset-password-m-{{ .User.ID }}" data-confirm-title="Reset password?" data-confirm-message="This sets an admin-entered temporary password, revokes every session for the user, and forces them to choose a new password on their next login. It does not re-enable a disabled account." data-confirm-action="Open reset form" aria-controls="reset-password-m-{{ .User.ID }}" aria-expanded="{{ if .ResetFormOpen }}true{{ else }}false{{ end }}"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>Reset password</button>
              <form id="reset-password-m-{{ .User.ID }}"{{ if not .ResetFormOpen }} hidden{{ end }} method="post" action="/users/reset-password" class="tg-user-reset-form" data-credential-form>
                {{ if and .ResetFormOpen $.FormError }}<p class="error">{{ $.FormError }}</p>{{ end }}
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="user_id" value="{{ .User.ID }}">
                <label>Temporary password <input type="password" name="temporary_password" data-credential-input{{ if not .ResetFormOpen }} disabled{{ end }} minlength="12" autocomplete="new-password" required></label>
                <label>Confirm temporary password <input type="password" name="temporary_password_confirmation" data-credential-input{{ if not .ResetFormOpen }} disabled{{ end }} minlength="12" autocomplete="new-password" required></label>
                <div class="tg-credential-form-actions">
                  <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm">Set temporary password</button>
                  <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm" data-credential-cancel>Cancel</button>
                </div>
              </form>
            </div>
            {{ end }}
          </div>
        </article>
        {{ end }}
      </div>
      {{ else }}
        <div class="tg-empty-row tg-data-empty"><strong>No users yet</strong><span>Create the first admin from setup.</span></div>
      {{ end }}
    </section>
  </main>` + pageFoot

const webhookDeliveriesTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-audit-page">
    <header class="tg-header">
      <div>
        <p class="eyebrow">Secondary operational diagnostics</p>
        <h1 class="tg-title">Webhook diagnostics</h1>
        <p class="tg-subtitle">Inspect recent signed webhook deliveries, verification state, and sanitized local processing outcomes.</p>
      </div>
      <div class="tg-header-actions">
        <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/activity">Back to activity</a>
        <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>Sanitized delivery metadata</span>
      </div>
    </header>

    <section class="tg-warning-callout">
      <span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
      <span>This troubleshooting page does not store or render raw webhook payloads, request headers, signatures, webhook secrets, status tokens, or session IDs.</span>
    </section>

    <section class="tg-panel tg-data-panel tg-audit-log-panel">
      <div class="tg-table-toolbar" aria-label="Webhook diagnostic controls">
        <div class="tg-toolbar-main">
          <h2>Signed webhook deliveries</h2>
          <p>Latest signed pull request webhook receipts and local recomputation processing states.</p>
        </div>
        <div class="tg-toolbar-controls" aria-label="Webhook delivery table controls">
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="#audit-filters">Filters{{ if .Filters.HasActiveFilters }} active{{ end }}</a>
        </div>
      </div>

      <section id="audit-filters" class="tg-modal tg-filter-modal" aria-labelledby="audit-filters-title">
        <a class="tg-modal-backdrop" href="#" aria-label="Close audit filters"></a>
        <div class="tg-modal-card" role="dialog" aria-modal="true">
          <div class="tg-modal-head">
            <h2 id="audit-filters-title">Filter webhook deliveries</h2>
            <a href="#" class="tg-modal-close" aria-label="Close"><svg class="tg-icon"><use href="#tg-i-close"></use></svg></a>
          </div>
          <form class="tg-setup-form tg-filter-form" method="get" action="/webhooks">
            <input type="hidden" name="sort" value="{{ .Filters.Sort }}">
            <input type="hidden" name="direction" value="{{ .Filters.Direction }}">
            <input type="hidden" name="limit" value="{{ .Filters.Limit }}">
            <label>Repository
              <select name="repository_id">
                {{ range .RepositoryFilterOptions }}<option value="{{ .Value }}"{{ if .Selected }} selected{{ end }}>{{ .Label }}</option>{{ end }}
              </select>
            </label>
            <label>Processing status
              <select name="processing">
                {{ range .ProcessingFilterOptions }}<option value="{{ .Value }}"{{ if .Selected }} selected{{ end }}>{{ .Label }}</option>{{ end }}
              </select>
            </label>
            <label>Event
              <select name="event">
                {{ range .EventFilterOptions }}<option value="{{ .Value }}"{{ if .Selected }} selected{{ end }}>{{ .Label }}</option>{{ end }}
              </select>
            </label>
            <div class="tg-form-actions tg-field-wide">
              <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/webhooks">Reset filters</a>
              <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm">Apply filters</button>
            </div>
          </form>
        </div>
      </section>

      {{ if .Deliveries }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-audit-table">
          <caption class="tg-sr-only">Recent webhook deliveries</caption>
          <thead>
            <tr>
              <th scope="col" aria-sort="{{ .Filters.SortReceivedAria }}"><a class="tg-sort-link{{ if eq .Filters.Sort "received" }} is-sorted{{ end }}" href="{{ .Filters.SortReceivedURL }}">Received{{ if .Filters.SortReceivedIndicator }} <span class="tg-sort-indicator" aria-hidden="true">{{ .Filters.SortReceivedIndicator }}</span>{{ end }}</a></th>
              <th scope="col">Repository</th>
              <th scope="col">Delivery ID</th>
              <th scope="col">Event</th>
              <th scope="col">Verification</th>
              <th scope="col">Processing</th>
              <th scope="col" aria-sort="{{ .Filters.SortProcessedAria }}"><a class="tg-sort-link{{ if eq .Filters.Sort "processed" }} is-sorted{{ end }}" href="{{ .Filters.SortProcessedURL }}">Processed{{ if .Filters.SortProcessedIndicator }} <span class="tg-sort-indicator" aria-hidden="true">{{ .Filters.SortProcessedIndicator }}</span>{{ end }}</a></th>
              <th scope="col">Details</th>
            </tr>
          </thead>
          <tbody>
          {{ range .Deliveries }}
            <tr id="delivery-{{ .Delivery.ID }}">
              <td data-label="Received">{{ .ReceivedAt }}</td>
              <td data-label="Repository"><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-repositories"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else if .Delivery.RepositoryID }}Repository #{{ .Delivery.RepositoryID }}{{ else }}Unknown repository{{ end }}</code></span></td>
              <td data-label="Delivery ID"><code class="tg-truncate">{{ .Delivery.DeliveryID }}</code></td>
              <td data-label="Event"><code>{{ .Delivery.Event }}</code>{{ if .Delivery.Action }}<small class="tg-muted">{{ .Delivery.Action }}</small>{{ else }}<small class="tg-muted">no action</small>{{ end }}</td>
              <td data-label="Verification"><span class="status status-{{ .VerificationStateClass }}">{{ .VerificationState }}</span></td>
              <td data-label="Processing"><span class="status status-{{ .ProcessingStateClass }}">{{ .ProcessingState }}</span><small class="tg-muted">Claimed {{ .ProcessingStartedAt }}</small></td>
              <td data-label="Processed">{{ .ProcessedAt }}</td>
              <td data-label="Details">{{ if .Delivery.Error }}{{ .Delivery.Error }}{{ else }}No processing error{{ end }}</td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>

      <div class="tg-mobile-card-list" aria-label="Recent webhook deliveries mobile cards">
        {{ range .Deliveries }}
        <article class="tg-mobile-card">
          <div class="tg-mobile-card-head">
            <div>
              <span class="tg-mobile-card-kicker">{{ .ReceivedAt }}</span>
              <h3>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else if .Delivery.RepositoryID }}Repository #{{ .Delivery.RepositoryID }}{{ else }}Unknown repository{{ end }}</h3>
            </div>
            <span class="status status-{{ .ProcessingStateClass }}">{{ .ProcessingState }}</span>
          </div>
          <p class="tg-mobile-card-meta"><code>{{ .Delivery.Event }}</code>{{ if .Delivery.Action }}<span class="tg-dot">·</span><code>{{ .Delivery.Action }}</code>{{ end }}<span class="tg-dot">·</span><span class="status status-{{ .VerificationStateClass }}">{{ .VerificationState }}</span></p>
          <dl class="tg-mobile-card-grid">
            <div><dt>Delivery ID</dt><dd><code>{{ .Delivery.DeliveryID }}</code></dd></div>
            <div><dt>Claimed</dt><dd>{{ .ProcessingStartedAt }}</dd></div>
            <div><dt>Processed</dt><dd>{{ .ProcessedAt }}</dd></div>
          </dl>
          <p class="tg-mobile-card-detail">{{ if .Delivery.Error }}{{ .Delivery.Error }}{{ else }}No processing error recorded for this delivery.{{ end }}</p>
        </article>
        {{ end }}
      </div>

      <footer class="tg-pagination" aria-label="Webhook diagnostic pagination">
        <span class="tg-pagination-summary">Showing {{ .Filters.ShowingRows }} of {{ .Filters.FilteredRows }} matching rows</span>
        <form class="tg-page-size-form" method="get" action="/webhooks">
          <input type="hidden" name="sort" value="{{ .Filters.Sort }}">
          <input type="hidden" name="direction" value="{{ .Filters.Direction }}">
          {{ if .Filters.RepositoryID }}<input type="hidden" name="repository_id" value="{{ .Filters.RepositoryID }}">{{ end }}
          {{ if .Filters.ProcessingState }}<input type="hidden" name="processing" value="{{ .Filters.ProcessingState }}">{{ end }}
          {{ if .Filters.Event }}<input type="hidden" name="event" value="{{ .Filters.Event }}">{{ end }}
          <span class="tg-page-size">{{ .Filters.TotalRows }} total rows loaded</span>
          <label class="tg-compact-field">Rows per page
            <select name="limit">
              {{ range .LimitOptions }}<option value="{{ .Value }}"{{ if .Selected }} selected{{ end }}>{{ .Label }}</option>{{ end }}
            </select>
          </label>
          <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Apply</button>
        </form>
      </footer>
      {{ else }}
        <div class="tg-empty-row tg-data-empty">
          {{ if and .Filters.TotalRows .Filters.HasActiveFilters }}
          <strong>No webhook deliveries match these filters</strong>
          <span>Adjust filters or reset controls to return to all loaded deliveries.</span>
          {{ else }}
          <strong>No webhook deliveries recorded yet</strong>
          <span>Send a signed pull request webhook to see sanitized delivery metadata here.</span>
          {{ end }}
        </div>
      {{ end }}
    </section>
  </main>` + pageFoot

const publicationsTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-diagnostics-page">
    <header class="tg-header">
      <div>
        <p class="eyebrow">Secondary operational diagnostics</p>
        <h1 class="tg-title">Status diagnostics</h1>
        <p class="tg-subtitle">Inspect the latest desired <code>thawguard/freeze</code> statuses and recent sanitized publication attempts.</p>
      </div>
      <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/activity">Back to activity</a>
    </header>

    <section class="tg-warning-callout">
      <span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
      <span>Publication errors are sanitized before storage. Raw forge response bodies, tokens, passwords, and session IDs are not rendered.</span>
    </section>

    <section class="tg-panel tg-data-panel">
      <div class="tg-panel-head"><h2>Latest desired statuses</h2><span class="tg-badge tg-badge-info">{{ len .Publications }} shown</span></div>
      <p class="tg-panel-subtitle">The latest desired status per repository head and status context.</p>
      {{ if .Publications }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-audit-table">
          <caption class="tg-sr-only">Latest desired status publications</caption>
          <thead><tr><th>Last updated</th><th>Repository</th><th>PR / branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Mode</th><th>Description</th></tr></thead>
          <tbody>
          {{ range .Publications }}
            <tr>
              <td data-label="Last updated">{{ .UpdatedAt }}</td>
              <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Publication.RepositoryID }}{{ end }}</td>
              <td data-label="PR / branch">#{{ .Publication.PullRequestIndex }}<small class="tg-muted">{{ .Publication.TargetBranch }}</small></td>
              <td data-label="Head SHA"><code>{{ .Publication.HeadSHA }}</code></td>
              <td data-label="Context"><code>{{ .Publication.Context }}</code></td>
              <td data-label="State"><span class="status status-{{ .Publication.State }}">{{ .Publication.State }}</span></td>
              <td data-label="Mode"><code>{{ .Publication.DeliveryMode }}</code></td>
              <td data-label="Description">{{ .Publication.Description }}</td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      <div class="tg-mobile-card-list" aria-label="Latest desired statuses mobile cards">
        {{ range .Publications }}
        <article class="tg-mobile-card">
          <div class="tg-mobile-card-head">
            <div><span class="tg-mobile-card-kicker">Updated {{ .UpdatedAt }}</span><h3>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Publication.RepositoryID }}{{ end }}</h3></div>
            <span class="status status-{{ .Publication.State }}">{{ .Publication.State }}</span>
          </div>
          <p class="tg-mobile-card-meta">PR #{{ .Publication.PullRequestIndex }}<span class="tg-dot">·</span>{{ .Publication.TargetBranch }}<span class="tg-dot">·</span><code>{{ .Publication.HeadSHA }}</code></p>
          <dl class="tg-mobile-card-grid">
            <div><dt>Context</dt><dd><code>{{ .Publication.Context }}</code></dd></div>
            <div><dt>Mode</dt><dd><code>{{ .Publication.DeliveryMode }}</code></dd></div>
          </dl>
          <p class="tg-mobile-card-detail">{{ .Publication.Description }}</p>
        </article>
        {{ end }}
      </div>
      {{ else }}
        <div class="tg-empty-row tg-data-empty"><strong>No desired statuses yet</strong><span>Desired status records appear after an enforcement-active repository evaluates pull requests.</span></div>
      {{ end }}
    </section>

    <section class="tg-panel tg-data-panel">
      <div class="tg-panel-head"><h2>Recent publication attempts</h2><span class="tg-badge tg-badge-info">{{ len .Attempts }} shown</span></div>
      <p class="tg-panel-subtitle">Posted and failed attempts against the forge. Historical records from older databases may still appear here.</p>
      {{ if .Attempts }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-audit-table">
          <caption class="tg-sr-only">Recent status publication attempts</caption>
          <thead><tr><th>Attempted</th><th>Repository</th><th>PR / branch</th><th>Head SHA</th><th>State</th><th>Mode</th><th>Result</th><th>Description / error</th></tr></thead>
          <tbody>
          {{ range .Attempts }}
            <tr>
              <td data-label="Attempted">{{ .AttemptedAt }}</td>
              <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Attempt.RepositoryID }}{{ end }}</td>
              <td data-label="PR / branch">#{{ .Attempt.PullRequestIndex }}<small class="tg-muted">{{ .Attempt.TargetBranch }}</small></td>
              <td data-label="Head SHA"><code>{{ .Attempt.HeadSHA }}</code><small class="tg-muted">{{ .Attempt.Context }}</small></td>
              <td data-label="State"><span class="status status-{{ .Attempt.State }}">{{ .Attempt.State }}</span></td>
              <td data-label="Mode"><code>{{ .Attempt.Mode }}</code></td>
              <td data-label="Result"><span class="status status-{{ if eq .Attempt.Result "posted" }}ok{{ else }}failed{{ end }}">{{ .Attempt.Result }}</span></td>
              <td data-label="Description / error">{{ .Attempt.Description }}{{ if .Attempt.Error }}<small class="tg-muted">{{ .Attempt.Error }}</small>{{ end }}</td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      <div class="tg-mobile-card-list" aria-label="Recent publication attempts mobile cards">
        {{ range .Attempts }}
        <article class="tg-mobile-card">
          <div class="tg-mobile-card-head">
            <div><span class="tg-mobile-card-kicker">{{ .AttemptedAt }}</span><h3>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Attempt.RepositoryID }}{{ end }}</h3></div>
            <span class="status status-{{ if eq .Attempt.Result "posted" }}ok{{ else }}failed{{ end }}">{{ .Attempt.Result }}</span>
          </div>
          <p class="tg-mobile-card-meta">PR #{{ .Attempt.PullRequestIndex }}<span class="tg-dot">·</span>{{ .Attempt.TargetBranch }}<span class="tg-dot">·</span><code>{{ .Attempt.HeadSHA }}</code></p>
          <dl class="tg-mobile-card-grid">
            <div><dt>Context</dt><dd><code>{{ .Attempt.Context }}</code></dd></div>
            <div><dt>State</dt><dd>{{ .Attempt.State }}</dd></div>
            <div><dt>Mode</dt><dd><code>{{ .Attempt.Mode }}</code></dd></div>
          </dl>
          <p class="tg-mobile-card-detail">{{ .Attempt.Description }}{{ if .Attempt.Error }} — {{ .Attempt.Error }}{{ end }}</p>
        </article>
        {{ end }}
      </div>
      {{ else }}
        <div class="tg-empty-row tg-data-empty"><strong>No publication attempts yet</strong><span>Posted or failed forge deliveries will appear here after status publication begins.</span></div>
      {{ end }}
    </section>
  </main>` + pageFoot
