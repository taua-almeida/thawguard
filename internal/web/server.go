package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	"github.com/taua-almeida/thawguard/internal/schedule"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
	"github.com/taua-almeida/thawguard/internal/webhook"
	webassets "github.com/taua-almeida/thawguard/web"
)

const defaultWebhookMaxBodyBytes int64 = 1 << 20
const scheduledFreezeReasonMaxLength = 500

type Config struct {
	AppName                              string
	RepositoryStore                      RepositoryStore
	RepositorySecretEncryptionConfigured bool
	SetupCheckStore                      SetupCheckStore
	SetupCheckRunner                     SetupCheckRunner
	FreezeStore                          FreezeStore
	ScheduledFreezeStore                 ScheduledFreezeStore
	// ScheduleStore backs the recurring-schedule shell pages; optional (the
	// schedules region and routes degrade gracefully when absent).
	ScheduleStore ScheduleStore
	AuditStore    AuditStore
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

// ScheduleStore persists recurring freeze schedules. Schedules are created
// paused; Activate turns coverage into real freezes (materialized by the
// background runner), Pause stops coverage and ends the schedule's live
// freeze if one exists.
type ScheduleStore interface {
	List(ctx context.Context) ([]domain.Schedule, error)
	Get(ctx context.Context, id int64) (domain.Schedule, error)
	Create(ctx context.Context, params schedule.CreateParams, actor domain.Actor) (domain.Schedule, error)
	Delete(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error)
	Activate(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error)
	Pause(ctx context.Context, id int64, actor domain.Actor) (domain.Schedule, error)
	ListRules(ctx context.Context, scheduleID int64) ([]domain.ScheduleWeeklyRule, error)
	AddRules(ctx context.Context, params schedule.AddRulesParams, actor domain.Actor) ([]domain.ScheduleWeeklyRule, error)
	DeleteRule(ctx context.Context, scheduleID, ruleID int64, actor domain.Actor) (domain.ScheduleWeeklyRule, error)
	ListWindows(ctx context.Context, scheduleID int64) ([]domain.ScheduleDatedWindow, error)
	AddWindow(ctx context.Context, params schedule.AddWindowParams, actor domain.Actor) (domain.ScheduleDatedWindow, bool, error)
	DeleteWindow(ctx context.Context, scheduleID, windowID int64, actor domain.Actor) (domain.ScheduleDatedWindow, error)
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
	ListPage(ctx context.Context, state string, repositoryID int64, offset, limit int) ([]statuspublication.Publication, int, error)
	ListAttemptsPage(ctx context.Context, result string, repositoryID int64, offset, limit int) ([]statuspublication.Attempt, int, error)
}

type WebhookRepositoryStore interface {
	FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error)
	WebhookSecret(ctx context.Context, repositoryID int64) (string, bool, error)
}

type WebhookDeliveryStore interface {
	ListPage(ctx context.Context, processing string, repositoryID int64, order webhook.DeliveryOrder, offset, limit int) ([]webhook.Delivery, int, error)
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
	// "/{$}" matches exactly "/"; the bare "GET /" pattern is the catch-all
	// for every unmatched GET path, which must 404 instead of rendering the
	// dashboard.
	s.mux.HandleFunc("GET /{$}", s.handleDashboard)
	s.mux.HandleFunc("GET /", s.handleUnknownPath)
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
	// "GET .../new" wins over "GET .../{id}" by pattern specificity.
	s.mux.HandleFunc("GET /scheduled-freezes/schedules/new", s.handleScheduleNew)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/new", s.handleScheduleCreate)
	s.mux.HandleFunc("GET /scheduled-freezes/schedules/{id}", s.handleScheduleDetail)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/delete", s.handleScheduleDelete)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/activate", s.handleScheduleActivate)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/pause", s.handleSchedulePause)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/rules", s.handleScheduleRuleAdd)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/rules/{ruleID}/delete", s.handleScheduleRuleDelete)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/windows", s.handleScheduleWindowAdd)
	s.mux.HandleFunc("POST /scheduled-freezes/schedules/{id}/windows/{windowID}/delete", s.handleScheduleWindowDelete)
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
		s.mux.HandleFunc("GET /dev/preview/publications", s.handleDevPreviewPublications)
		s.mux.HandleFunc("GET /dev/preview/webhooks", s.handleDevPreviewWebhooks)
		s.mux.HandleFunc("GET /dev/preview/users", s.handleDevPreviewUsers)
		s.mux.HandleFunc("GET /dev/preview/scheduled-freezes", s.handleDevPreviewScheduledFreezes)
		s.mux.HandleFunc("GET /dev/preview/schedule-detail", s.handleDevPreviewScheduleDetail)
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

// handleUnknownPath serves the styled 404 card for GET paths no route claims.
// It runs before any auth redirect on purpose: the path doesn't exist, so
// there is nothing to sign in for; the card's single action still switches to
// "Sign in" when the visitor has no viewing session.
func (s *Server) handleUnknownPath(w http.ResponseWriter, r *http.Request) {
	signedOut := false
	if s.cfg.AuthService != nil {
		session, ok, err := s.currentSession(r)
		signedOut = err != nil || !ok || !session.Roles.CanView()
	}
	s.renderErrorPage(w, http.StatusNotFound, signedOut)
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
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.StatusPublicationStore == nil {
		http.Error(w, "status publication store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	query := publicationsQueryFromValues(r.URL.Query())
	data, ok := s.loadPublicationsPageData(w, r, query, session)
	if !ok {
		return
	}
	if isHXRequest(r) {
		s.renderPage(w, "components/publications-live", data)
		return
	}
	s.renderPage(w, "layouts/publications", data)
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
	w.Header().Add("Vary", "HX-Request")
	if s.cfg.WebhookDeliveryStore == nil {
		http.Error(w, "webhook delivery store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	query := webhooksQueryFromValues(r.URL.Query())
	data, ok := s.loadWebhooksPageData(w, r, query, session)
	if !ok {
		return
	}
	if isHXRequest(r) {
		s.renderPage(w, "components/webhooks-live", data)
		return
	}
	s.renderPage(w, "layouts/webhooks", data)
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
	case "freeze-lifted-scheduled":
		state.Notice = "Freeze lifted. Its schedule will not re-freeze this branch until its next scheduled window."
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
	// scheduledNotice/scheduledToast replace the plain messaging when the
	// closed freeze was created by a recurring schedule; empty means no
	// schedule-specific variant exists for this action.
	scheduledNotice string
	scheduledToast  toastView
}

func (s *Server) handleEndFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.endFreeze, closeFreezeOutcome{
		notice: "freeze-lifted",
		toast:  toastView{Message: "Freeze lifted.", Tone: "success"},
		// Ending a schedule-created freeze suppresses the schedule until its
		// next window; the messaging must say so or the thaw looks permanent.
		scheduledNotice: "freeze-lifted-scheduled",
		scheduledToast:  toastView{Message: "Freeze lifted. Its schedule will not re-freeze this branch until its next scheduled window.", Tone: "success"},
	})
}

func (s *Server) handleCancelFreeze(w http.ResponseWriter, r *http.Request) {
	s.handleCloseFreeze(w, r, s.cancelFreeze, closeFreezeOutcome{
		notice: "freeze-cancelled",
		toast:  toastView{Message: "Freeze cancelled.", Tone: "info"},
	})
}

func (s *Server) handleCloseFreeze(w http.ResponseWriter, r *http.Request, closeFreeze func(context.Context, int64, domain.Actor) (domain.BranchFreeze, error), outcome closeFreezeOutcome) {
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
	closed, err := closeFreeze(r.Context(), freezeID, session.auditActor())
	if err != nil {
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
	notice, toast := outcome.notice, outcome.toast
	if closed.ScheduleID != nil && outcome.scheduledNotice != "" {
		notice, toast = outcome.scheduledNotice, outcome.scheduledToast
	}
	if isHXRequest(r) {
		s.renderFreezesFragment(w, r, "components/active-freezes-fragment", freezesPageState{}, session, &toast)
		return
	}
	http.Redirect(w, r, "/freezes?notice="+notice, http.StatusSeeOther)
}

func (s *Server) endFreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return s.cfg.FreezeStore.End(ctx, id, actor)
}

func (s *Server) cancelFreeze(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error) {
	return s.cfg.FreezeStore.Cancel(ctx, id, actor)
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
	case "recurring-schedule-deleted":
		state.Notice, state.NoticeTone = "Recurring schedule deleted.", "info"
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
	audit.ActionScheduleCreated:                    {Label: "Recurring schedule", Outcome: "Created", OutcomeClass: "ok"},
	audit.ActionScheduleDeleted:                    {Label: "Recurring schedule", Outcome: "Deleted", OutcomeClass: "warning"},
	audit.ActionScheduleActivated:                  {Label: "Recurring schedule", Outcome: "Activated", OutcomeClass: "ok"},
	audit.ActionSchedulePaused:                     {Label: "Recurring schedule", Outcome: "Paused", OutcomeClass: "warning"},
	audit.ActionScheduleSuppressed:                 {Label: "Recurring schedule", Outcome: "Manually thawed", OutcomeClass: "warning"},
	audit.ActionScheduleRulesAdded:                 {Label: "Recurring schedule", Outcome: "Rules added", OutcomeClass: "ok"},
	audit.ActionScheduleRuleRemoved:                {Label: "Recurring schedule", Outcome: "Rule removed", OutcomeClass: "warning"},
	audit.ActionScheduleWindowAdded:                {Label: "Recurring schedule", Outcome: "Window added", OutcomeClass: "ok"},
	audit.ActionScheduleWindowRemoved:              {Label: "Recurring schedule", Outcome: "Window removed", OutcomeClass: "warning"},
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
		view.Detail = "Reason: " + activityReasonOrUnavailable(details, "reason") + "."
	case audit.ActionBranchFreezePlannedUnfreeze, audit.ActionFreezeSchedulePlannedUnfreeze:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at", false) + ". Reason: " + activityReasonOrUnavailable(details, "reason") + "."
	case audit.ActionFreezeScheduleCreated:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Starts " + activityTimeOrUnavailable(details, "starts_at", false) + "; planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at", true) + ". Reason: " + activityReasonOrUnavailable(details, "reason") + "."
	case audit.ActionFreezeScheduleUpdated:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = activityScheduleUpdateDetail(details)
	case audit.ActionFreezeScheduleCancelled:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Reason: " + activityReasonOrUnavailable(details, "reason") + "."
	case audit.ActionFreezeScheduleActivated, audit.ActionFreezeScheduleStartedNow:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Started " + activityTimeOrUnavailable(details, "starts_at", false) + "; planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at", true) + ". Reason: " + activityReasonOrUnavailable(details, "reason") + "."
	case audit.ActionScheduleCreated, audit.ActionScheduleDeleted, audit.ActionScheduleActivated, audit.ActionSchedulePaused:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Schedule " + activityTextOrUnavailable(details, "name", 100) + " (" + activityTextOrUnavailable(details, "kind", 16) + ", " + activityTextOrUnavailable(details, "timezone", 64) + "). Reason: " + activityReasonOrUnavailable(details, "reason") + "."
	case audit.ActionScheduleSuppressed:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Schedule " + activityTextOrUnavailable(details, "name", 100) + ": freeze ended manually; suppressed until " + activityTimeOrUnavailable(details, "suppressed_until", false) + "; resumes " + activityTimeOrUnavailable(details, "resumes_at", true) + "."
	case audit.ActionScheduleRulesAdded, audit.ActionScheduleRuleRemoved:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Schedule " + activityTextOrUnavailable(details, "name", 100) + ": " + activityTextOrUnavailable(details, "days", 40) + " " + activityTextOrUnavailable(details, "start_time", 5) + " → " + activityTextOrUnavailable(details, "end_time", 5) + " (" + activityTextOrUnavailable(details, "end_day", 16) + ")."
	case audit.ActionScheduleWindowAdded, audit.ActionScheduleWindowRemoved:
		view.Target = activityRepositoryTarget(repositories, event, details, "branch")
		view.Detail = "Schedule " + activityTextOrUnavailable(details, "name", 100) + ": window " + activityTextOrUnavailable(details, "window_name", 100) + ", " + activityTextOrUnavailable(details, "starts_at", 16) + " → " + activityTextOrUnavailable(details, "ends_at", 16) + " local time."
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

// activityReasonOrUnavailable renders an optional freeze reason from audit
// details. Reasons may legitimately be empty, so a recorded blank renders as
// "none" while a missing or unsafe value still renders as "unavailable".
func activityReasonOrUnavailable(details activityDetails, key string) string {
	raw, ok := details[key]
	if !ok {
		return "unavailable"
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "unavailable"
	}
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return activityTextOrUnavailable(details, key, scheduledFreezeReasonMaxLength)
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
	return "Reason " + activityReasonOrUnavailable(details, "reason_before") + " → " + activityReasonOrUnavailable(details, "reason_after") + "; starts " + activityTimeOrUnavailable(details, "starts_at_before", false) + " → " + activityTimeOrUnavailable(details, "starts_at_after", false) + "; planned unfreeze " + activityTimeOrUnavailable(details, "planned_ends_at_before", true) + " → " + activityTimeOrUnavailable(details, "planned_ends_at_after", true) + "."
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
