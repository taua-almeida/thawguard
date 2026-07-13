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
)

const defaultWebhookMaxBodyBytes int64 = 1 << 20
const defaultAuditLogLimit = 25
const maxAuditLogLimit = 500

type Config struct {
	AppName                              string
	RepositoryStore                      RepositoryStore
	RepositorySecretEncryptionConfigured bool
	SetupCheckStore                      SetupCheckStore
	SetupCheckRunner                     SetupCheckRunner
	FreezeStore                          FreezeStore
	ScheduledFreezeStore                 ScheduledFreezeStore
	AuditStore                           AuditStore
	StatusDecisionStore                  StatusDecisionStore
	StatusPublicationStore               StatusPublicationStore
	WebhookRepositoryStore               WebhookRepositoryStore
	WebhookDeliveryStore                 WebhookDeliveryStore
	PullRequestWebhookProcessor          PullRequestWebhookProcessor
	WebhookMaxBodyBytes                  int64
	AuthService                          AuthService
	EnforcementService                   EnforcementService
	ReconciliationJobStore               ReconciliationJobStore
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
	Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error)
}

type FreezeStore interface {
	ListActive(ctx context.Context) ([]domain.BranchFreeze, error)
	CreateActive(ctx context.Context, params freeze.CreateParams, actor domain.Actor) (domain.BranchFreeze, error)
	End(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
	Cancel(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type ScheduledFreezeStore interface {
	ListScheduled(ctx context.Context, limit int) ([]domain.BranchFreeze, error)
	CreateScheduled(ctx context.Context, params freeze.ScheduleParams, actor domain.Actor) (domain.BranchFreeze, error)
	CancelScheduled(ctx context.Context, id int64, actor domain.Actor) (domain.BranchFreeze, error)
}

type AuditStore interface {
	List(ctx context.Context, limit int) ([]audit.Event, error)
	ListBySubjectType(ctx context.Context, subjectType string, limit int) ([]audit.Event, error)
}

type StatusDecisionStore interface {
	ListRecent(ctx context.Context, limit int) ([]statusresult.Result, error)
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

type repositoryView struct {
	Repository           domain.Repository
	SetupChecks          []setupcheck.Check
	RepositoryChecks     []setupcheck.Check
	Branches             []repositoryBranchView
	LastCheckedAt        string
	EnforcementLabel     string
	EnforcementClass     string
	StatusPostVerifiedAt string
	IsSetupIncomplete    bool
	IsReady              bool
	IsUnhealthy          bool
	// EnforcementFailedAt and FailureRemediation present the stored sanitized
	// enforcement failure (timestamp formatted, remediation mapped from the
	// stable reason category) for the unhealthy state.
	EnforcementFailedAt string
	FailureRemediation  string
	RecoveryInProgress  bool
	RecoveryAttempts    int
	NextRecoveryAt      string
	// VerifyAvailable is true when the latest recorded readiness run has
	// every mandatory read-only check OK; the POST re-runs readiness, so this
	// only controls whether the action is offered.
	VerifyAvailable     bool
	VerifyBlockedReason string
}

type repositoryBranchView struct {
	Name          string
	IsDefault     bool
	SetupLabel    string
	SetupClass    string
	LastCheckedAt string
	Checks        []setupcheck.Check
}

// managedBranchOption is one (repository, exact branch) choice for the freeze
// and scheduled-freeze forms; POST validation stays authoritative.
type managedBranchOption struct {
	RepositoryID int64
	Name         string
}

type repositoryOverview struct {
	RepositoryCount             int
	WebhookConfiguredCount      int
	StatusTokenConfiguredCount  int
	SetupCheckRepositoryCount   int
	EnforcementActiveCount      int
	WebhookSecretStorageEnabled bool
}

type freezeView struct {
	Freeze          domain.BranchFreeze
	Repository      domain.Repository
	PlannedEndsAt   string
	HasPlannedEndAt bool
}

type scheduledFreezeView struct {
	Freeze        domain.BranchFreeze
	Repository    domain.Repository
	StartsAt      string
	PlannedEndsAt string
	EndedAt       string
	StatusLabel   string
	StateClass    string
	CanCancel     bool
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

type systemAuditEventView struct {
	Event      audit.Event
	Repository domain.Repository
	CreatedAt  string
	Label      string
	Summary    string
	Detail     string
	Actor      string
	StateClass string
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
	SystemEvents            []systemAuditEventView
	StatusAttempts          []statusPublicationAttemptView
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
	s.mux.HandleFunc("POST /repositories/reconcile", s.handleReconcileEnforcement)
	s.mux.HandleFunc("POST /repositories/recover", s.handleRecoverEnforcement)
	s.mux.HandleFunc("GET /freezes", s.handleFreezes)
	s.mux.HandleFunc("POST /freezes", s.handleCreateFreeze)
	s.mux.HandleFunc("POST /freezes/end", s.handleEndFreeze)
	s.mux.HandleFunc("POST /freezes/cancel", s.handleCancelFreeze)
	s.mux.HandleFunc("GET /scheduled-freezes", s.handleScheduledFreezes)
	s.mux.HandleFunc("POST /scheduled-freezes", s.handleCreateScheduledFreeze)
	s.mux.HandleFunc("POST /scheduled-freezes/cancel", s.handleCancelScheduledFreeze)
	s.mux.HandleFunc("GET /decisions", s.handleDecisions)
	s.mux.HandleFunc("POST /decisions", s.handleCreateDecision)
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
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
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
		internalServerError(w)
		return
	}
	if hasUsers {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderSetup(w, r, "")
}

func (s *Server) handleCreateFirstAdmin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	hasUsers, err := s.cfg.AuthService.HasUsers(r.Context())
	if err != nil {
		internalServerError(w)
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
	if !sameOriginRequest(r) {
		s.renderSetupStatus(w, r, "Setup form expired. Please try again.", http.StatusForbidden)
		return
	}
	if !s.validSetupCSRFToken(r) {
		s.renderSetupStatus(w, r, "Setup form expired. Please try again.", http.StatusForbidden)
		return
	}
	session, err := s.cfg.AuthService.CreateFirstAdmin(r.Context(), auth.CreateFirstAdminParams{
		Email:       r.PostFormValue("email"),
		DisplayName: r.PostFormValue("display_name"),
		Password:    r.PostFormValue("password"),
	})
	if err != nil {
		if !auth.IsValidationError(err) {
			internalServerError(w)
			return
		}
		s.renderSetupStatus(w, r, err.Error(), http.StatusBadRequest)
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
		internalServerError(w)
		return
	}
	if !hasUsers {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if session, ok, err := s.currentSession(r); err != nil {
		internalServerError(w)
		return
	} else if ok {
		http.Redirect(w, r, postLoginPath(session.MustChangePassword), http.StatusSeeOther)
		return
	}
	s.renderLoginStatus(w, r, "", http.StatusOK)
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
	if !sameOriginRequest(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !s.validLoginCSRFToken(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, err := s.cfg.AuthService.Login(r.Context(), auth.LoginParams{Email: r.PostFormValue("email"), Password: r.PostFormValue("password")})
	if err != nil {
		if !auth.IsAuthenticationError(err) {
			internalServerError(w)
			return
		}
		s.renderLoginStatus(w, r, err.Error(), http.StatusUnauthorized)
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
			internalServerError(w)
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
	scheduledFreezes, err := s.scheduledFreezes(r.Context(), 3)
	if err != nil {
		internalServerError(w)
		return
	}
	s.render(w, dashboardTemplate, map[string]any{
		"AppName":                     s.cfg.AppName,
		"ActivePage":                  "dashboard",
		"CurrentUser":                 currentUserFromSession(session),
		"CSRFToken":                   session.CSRFToken,
		"RepositoryCount":             len(repositories),
		"ActiveFreezeCount":           len(freezes),
		"ScheduledFreezePreviewCount": len(scheduledFreezes),
		"Freezes":                     s.freezeViews(repositories, freezes),
		"ScheduledFreezes":            scheduledFreezeViews(repositories, scheduledFreezes),
	})
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	repositories, results, err := s.decisionPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), "", session)
}

func (s *Server) handleCreateDecision(w http.ResponseWriter, r *http.Request) {
	if s.cfg.StatusDecisionStore == nil {
		http.Error(w, "status decision store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireThawApproverForm(w, r)
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
	outcome, err := s.cfg.StatusDecisionStore.ApproveThaw(r.Context(), statusresult.ThawApprovalParams{
		RepositoryID:     repositoryID,
		PullRequestIndex: pullRequestIndex,
		TargetBranch:     r.PostFormValue("target_branch"),
		HeadSHA:          r.PostFormValue("head_sha"),
		Reason:           r.PostFormValue("reason"),
		Confirmation:     thawApprovalConfirmationFromForm(r),
	}, session.auditActor())
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
		s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), err.Error(), session)
		return
	}
	if outcome.ConfirmationRequired {
		repositories, results, dataErr := s.decisionPageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		confirmation := sharedHeadConfirmationViewFrom(outcome, repositoryID, pullRequestIndex, strings.TrimSpace(r.PostFormValue("target_branch")), strings.TrimSpace(r.PostFormValue("reason")))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		s.renderDecisions(w, repositories, s.statusResultViews(repositories, results), "", session, confirmation)
		return
	}
	http.Redirect(w, r, "/decisions", http.StatusSeeOther)
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
		view.AffectedPullRequests = append(view.AffectedPullRequests, sharedHeadAffectedPullRequestView{Index: pr.Index, Title: pr.Title, TargetBranch: pr.TargetBranch, ShortHeadSHA: shortHeadSHA(pr.HeadSHA)})
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
	repositories, deliveries, events, attempts, err := s.webhookDeliveryPageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderWebhookDeliveries(w, auditLogViewData(controls, repositories, deliveries, events, attempts), session)
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
	s.renderRepositories(w, views, "", session)
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
	s.handleRepositoryBranchMutation(w, r, func(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error {
		_, err := s.cfg.RepositoryStore.AddBranch(ctx, repositoryID, branch, actor)
		return err
	})
}

func (s *Server) handleRemoveRepositoryBranch(w http.ResponseWriter, r *http.Request) {
	s.handleRepositoryBranchMutation(w, r, func(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error {
		return s.cfg.RepositoryStore.RemoveBranch(ctx, repositoryID, branch, actor)
	})
}

func (s *Server) handleRepositoryBranchMutation(w http.ResponseWriter, r *http.Request, mutate func(ctx context.Context, repositoryID int64, branch string, actor domain.Actor) error) {
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
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
	if err := mutate(r.Context(), repositoryID, r.PostFormValue("branch"), session.auditActor()); err != nil {
		s.renderRepositoriesValidationError(w, r, err, session)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

// renderRepositoriesValidationError re-renders the repositories page for a
// typed validation error and hides internal error details.
func (s *Server) renderRepositoriesValidationError(w http.ResponseWriter, r *http.Request, err error, session sessionState) {
	if !repository.IsValidationError(err) && !repositorysetup.IsValidationError(err) {
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
		s.renderRepositories(w, views, err.Error(), session)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleSetRepositoryStatusToken(w http.ResponseWriter, r *http.Request) {
	if s.cfg.RepositoryStore == nil {
		http.Error(w, "repository store is not configured", http.StatusServiceUnavailable)
		return
	}
	if !s.cfg.RepositorySecretEncryptionConfigured {
		http.Error(w, "status token encryption is not configured", http.StatusServiceUnavailable)
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
	_, err = s.cfg.RepositoryStore.SetStatusToken(r.Context(), repositoryID, r.PostFormValue("status_token"), session.auditActor())
	if err != nil {
		if repositorysetup.IsConfigurationError(err) {
			http.Error(w, "status token encryption is not configured", http.StatusServiceUnavailable)
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
		s.renderRepositories(w, views, err.Error(), session)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleVerifyStatusPosting(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.VerifyStatusPosting(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleActivateEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.ActivateEnforcement(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleReconcileEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.ReconcileEnforcement(ctx, repositoryID, actor)
		return err
	})
}

func (s *Server) handleRecoverEnforcement(w http.ResponseWriter, r *http.Request) {
	s.handleEnforcementTransition(w, r, func(ctx context.Context, repositoryID int64, actor domain.Actor) error {
		_, err := s.cfg.EnforcementService.RecoverEnforcement(ctx, repositoryID, actor)
		return err
	})
}

// handleEnforcementTransition guards the admin-only CSRF-protected enforcement
// actions and re-renders the repositories page with the typed validation
// message when the service rejects or reports a sanitized failure.
func (s *Server) handleEnforcementTransition(w http.ResponseWriter, r *http.Request, transition func(ctx context.Context, repositoryID int64, actor domain.Actor) error) {
	if s.cfg.EnforcementService == nil {
		http.Error(w, "enforcement service is not configured", http.StatusServiceUnavailable)
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
	if err := transition(r.Context(), repositoryID, session.auditActor()); err != nil {
		s.renderRepositoriesValidationError(w, r, err, session)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) handleFreezes(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	repositories, freezes, auditEvents, branchOptions, err := s.freezePageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, branchOptions, "", session)
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

	params, err := freezeCreateParamsFromForm(r)
	if err == nil {
		_, err = s.cfg.FreezeStore.CreateActive(r.Context(), params, session.auditActor())
	}
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, freezes, auditEvents, branchOptions, dataErr := s.freezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, branchOptions, err.Error(), session)
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
		repositories, freezes, auditEvents, branchOptions, dataErr := s.freezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderFreezes(w, repositories, s.freezeViews(repositories, freezes), auditEvents, branchOptions, err.Error(), session)
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

func (s *Server) handleScheduledFreezes(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireView(w, r)
	if !ok {
		return
	}
	repositories, scheduled, branchOptions, err := s.scheduledFreezePageData(r.Context())
	if err != nil {
		internalServerError(w)
		return
	}
	s.renderScheduledFreezes(w, repositories, scheduledFreezeViews(repositories, scheduled), branchOptions, "", session)
}

func (s *Server) handleCreateScheduledFreeze(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireFreezerForm(w, r)
	if !ok {
		return
	}
	params, err := scheduledFreezeParamsFromForm(r)
	if err == nil {
		_, err = s.cfg.ScheduledFreezeStore.CreateScheduled(r.Context(), params, session.auditActor())
	}
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, scheduled, branchOptions, dataErr := s.scheduledFreezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderScheduledFreezes(w, repositories, scheduledFreezeViews(repositories, scheduled), branchOptions, err.Error(), session)
		return
	}
	http.Redirect(w, r, "/scheduled-freezes", http.StatusSeeOther)
}

func (s *Server) handleCancelScheduledFreeze(w http.ResponseWriter, r *http.Request) {
	if s.cfg.ScheduledFreezeStore == nil {
		http.Error(w, "scheduled freeze store is not configured", http.StatusServiceUnavailable)
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
	_, err = s.cfg.ScheduledFreezeStore.CancelScheduled(r.Context(), freezeID, session.auditActor())
	if err != nil {
		if !freeze.IsValidationError(err) {
			internalServerError(w)
			return
		}
		repositories, scheduled, branchOptions, dataErr := s.scheduledFreezePageData(r.Context())
		if dataErr != nil {
			internalServerError(w)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderScheduledFreezes(w, repositories, scheduledFreezeViews(repositories, scheduled), branchOptions, err.Error(), session)
		return
	}
	http.Redirect(w, r, "/scheduled-freezes", http.StatusSeeOther)
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
		http.Error(w, "forbidden", http.StatusForbidden)
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
			internalServerError(w)
			return
		}
		s.renderAccountPassword(w, err.Error(), http.StatusBadRequest, session)
		return
	}
	setSessionCookie(w, r, sessionStateFromAuth(newSession))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderAccountPassword(w http.ResponseWriter, formError string, status int, session sessionState) {
	tpl, err := template.New("page").Parse(accountPasswordTemplate)
	if err != nil {
		internalServerError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = tpl.Execute(w, map[string]any{
		"AppName":            s.cfg.AppName,
		"FormError":          formError,
		"CSRFToken":          session.CSRFToken,
		"MustChangePassword": session.MustChangePassword,
	})
}

func (s *Server) requireRepositoryManagerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleForm(w, r, func(roles auth.RoleSet) bool { return roles.CanManageRepositories() })
}

func (s *Server) requireFreezerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	return s.requireRoleForm(w, r, func(roles auth.RoleSet) bool { return roles.CanFreeze() })
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

func (s *Server) systemAuditEvents(ctx context.Context) ([]audit.Event, error) {
	if s.cfg.AuditStore == nil {
		return nil, nil
	}
	return s.cfg.AuditStore.List(ctx, 25)
}

func (s *Server) webhookDeliveryPageData(ctx context.Context) ([]domain.Repository, []webhook.Delivery, []audit.Event, []statuspublication.Attempt, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	deliveries, err := s.webhookDeliveries(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	events, err := s.systemAuditEvents(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	attempts, err := s.statusPublicationAttempts(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return repositories, deliveries, events, attempts, nil
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

func auditLogViewData(controls auditLogControls, repositories []domain.Repository, deliveries []webhook.Delivery, events []audit.Event, attempts []statuspublication.Attempt) auditLogView {
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
		SystemEvents:            systemAuditEventViews(repositories, events),
		StatusAttempts:          statusPublicationAttemptViews(repositories, attempts),
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

func systemAuditEventViews(repositories []domain.Repository, events []audit.Event) []systemAuditEventView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]systemAuditEventView, 0, len(events))
	for _, event := range events {
		view, ok := systemAuditEventViewForEvent(repositoriesByID, event)
		if ok {
			views = append(views, view)
		}
	}
	return views
}

func systemAuditEventViewForEvent(repositoriesByID map[int64]domain.Repository, event audit.Event) (systemAuditEventView, bool) {
	details := map[string]string{}
	if strings.TrimSpace(event.DetailsJSON) != "" {
		if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
			details = map[string]string{}
		}
	}
	view := systemAuditEventView{
		Event:      event,
		CreatedAt:  event.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		Actor:      actorLabelForEvent(event, details["actor_kind"], details["actor_role"]),
		StateClass: "info",
	}
	if repositoryID, ok := auditDetailInt64(details, "repository_id"); ok {
		view.Repository = repositoriesByID[repositoryID]
	}
	if view.Actor == "unknown" {
		view.Actor = "system"
	}
	switch event.Action {
	case audit.ActionRepositoryCreated:
		view.Label = "Repository added"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = "Default branch " + auditDetailOrDash(details, "default_branch")
		view.StateClass = "ok"
	case audit.ActionRepositoryWebhookSecretConfigured:
		view.Label = "Webhook secret configured"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditRotationDetail(details, "webhook_secret_was_configured")
		view.StateClass = "ok"
	case audit.ActionRepositoryStatusTokenConfigured:
		view.Label = "Status token configured"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditRotationDetail(details, "status_token_was_configured")
		view.StateClass = "ok"
	case audit.ActionRepositoryOpenPullRequestsSynced:
		view.Label = "Open PRs synced"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "target_branch")
		view.Detail = auditDetailOrDash(details, "open_count") + " open from forge, " + auditDetailOrDash(details, "closed_absent_count") + " cached closed"
		view.StateClass = "ok"
	case audit.ActionRepositoryStatusPostVerified:
		view.Label = "Status posting verified"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = "Controlled " + domain.SetupStatusContext + " post on " + auditDetailOrDash(details, "default_branch") + " head " + auditDetailOrDash(details, "head_sha")
		view.StateClass = "ok"
	case audit.ActionRepositoryStatusPostVerifyFailed:
		view.Label = "Status-post verification failed"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "reason") + " — state " + auditDetailOrDash(details, "enforcement_state")
		view.StateClass = "failed"
	case audit.ActionRepositoryEnforcementActivated:
		view.Label = "Enforcement activated"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "open_pull_request_count") + " open PRs, " + auditDetailOrDash(details, "statuses_posted") + " statuses posted"
		view.StateClass = "ok"
	case audit.ActionRepositoryEnforcementActivateFail:
		view.Label = "Enforcement activation failed"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "reason") + " — state " + auditDetailOrDash(details, "enforcement_state")
		view.StateClass = "failed"
	case audit.ActionRepositoryEnforcementReconciled:
		view.Label = "Enforcement reconciled"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "open_pull_request_count") + " open PRs, " + auditDetailOrDash(details, "statuses_posted") + " statuses posted"
		view.StateClass = "ok"
	case audit.ActionRepositoryEnforcementReconcileFail:
		view.Label = "Enforcement reconciliation failed"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "reason") + " — state " + auditDetailOrDash(details, "enforcement_state")
		view.StateClass = "failed"
	case audit.ActionRepositoryEnforcementRecovered:
		view.Label = "Enforcement recovered"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "open_pull_request_count") + " open PRs, " + auditDetailOrDash(details, "statuses_posted") + " statuses posted"
		view.StateClass = "ok"
	case audit.ActionRepositoryEnforcementRecoverFail:
		view.Label = "Enforcement recovery failed"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "reason") + " — state " + auditDetailOrDash(details, "enforcement_state")
		view.StateClass = "failed"
	case audit.ActionRepositoryRuntimeConvergenceFail:
		view.Label = "Runtime convergence failed"
		view.Summary = auditRepositoryLabel(view.Repository, details)
		view.Detail = auditDetailOrDash(details, "reason") + " — automatic recovery pending"
		view.StateClass = "failed"
	case audit.ActionBranchFreezeCreated:
		view.Label = "Freeze created"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = auditDetailOrDash(details, "reason")
		view.StateClass = "failed"
	case audit.ActionBranchFreezeEnded:
		view.Label = "Freeze lifted"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = auditDetailOrDash(details, "reason")
		view.StateClass = "ok"
	case audit.ActionBranchFreezeCancelled:
		view.Label = "Freeze cancelled"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = auditDetailOrDash(details, "reason")
		view.StateClass = "warning"
	case audit.ActionBranchFreezePlannedUnfreeze:
		view.Label = "Planned unfreeze executed"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = "Planned end " + auditDetailOrDash(details, "planned_ends_at") + " — " + auditDetailOrDash(details, "reason")
		view.StateClass = "ok"
	case audit.ActionFreezeScheduleCreated:
		view.Label = "Freeze scheduled"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = "Starts " + auditDetailOrDash(details, "starts_at") + ", planned end " + auditDetailOrDash(details, "planned_ends_at") + " — " + auditDetailOrDash(details, "reason")
		view.StateClass = "pending"
	case audit.ActionFreezeScheduleCancelled:
		view.Label = "Schedule cancelled"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = auditDetailOrDash(details, "reason")
		view.StateClass = "warning"
	case audit.ActionFreezeScheduleActivated:
		view.Label = "Scheduled freeze activated"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = "Started " + auditDetailOrDash(details, "starts_at") + " — " + auditDetailOrDash(details, "reason")
		view.StateClass = "failed"
	case audit.ActionFreezeSchedulePlannedUnfreeze:
		view.Label = "Planned unfreeze executed"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " → " + auditDetailOrDash(details, "branch")
		view.Detail = "Planned end " + auditDetailOrDash(details, "planned_ends_at") + " — " + auditDetailOrDash(details, "reason")
		view.StateClass = "ok"
	case audit.ActionThawExceptionApproved:
		view.Label = "Thaw approved"
		view.Summary = auditRepositoryLabel(view.Repository, details) + " PR #" + auditDetailOrDash(details, "pull_request_index")
		view.Detail = "Head " + auditDetailOrDash(details, "head_sha") + " on " + auditDetailOrDash(details, "target_branch") + " — " + auditDetailOrDash(details, "reason")
		view.StateClass = "ok"
	case audit.ActionThawExceptionSharedHeadApproved:
		created, createdCount, createdOK := auditPullRequestIndexList(details, "created_pull_request_indexes")
		alreadyCovered, alreadyCoveredCount, alreadyCoveredOK := auditPullRequestIndexList(details, "already_covered_pull_request_indexes")
		declaredCreatedCount, declaredCreatedOK := auditNonnegativeInt(details, "created_pull_request_count")
		declaredCoveredCount, declaredCoveredOK := auditNonnegativeInt(details, "already_covered_pull_request_count")
		headSHA, headOK := auditHeadSHA(details, "head_sha")
		reason, reasonOK := auditTextDetail(details, "reason", 500)
		repositoryLabel := auditSharedHeadRepositoryLabel(view.Repository, details)
		if !createdOK || !alreadyCoveredOK || !declaredCreatedOK || !declaredCoveredOK || !headOK || !reasonOK || declaredCreatedCount != createdCount || declaredCoveredCount != alreadyCoveredCount || createdCount+alreadyCoveredCount == 0 {
			view.Label = "Shared-head confirmation recorded"
			view.Summary = repositoryLabel
			view.Detail = "Approval details unavailable"
			view.StateClass = "warning"
			break
		}
		if createdCount == 0 {
			view.Label = "Shared head already covered"
			view.Summary = repositoryLabel + " · Active exceptions: " + alreadyCovered
		} else {
			view.Label = "Shared-head thaw approved"
			view.Summary = repositoryLabel + " · New exceptions: " + created
			if alreadyCoveredCount > 0 {
				view.Summary += " · Already covered: " + alreadyCovered
			}
		}
		view.Detail = "Head " + headSHA + " — Confirmation reason: " + reason
		view.StateClass = "ok"
	case audit.ActionUserRolesUpdated:
		view.Label = "User roles updated"
		view.Summary = "User #" + event.SubjectID
		view.Detail = "Roles " + auditDetailOrDash(details, "roles_before") + " → " + auditDetailOrDash(details, "roles_after")
		view.StateClass = "info"
	case audit.ActionUserDisabled:
		view.Label = "User disabled"
		view.Summary = "User #" + event.SubjectID
		view.Detail = "Login blocked and all sessions revoked"
		view.StateClass = "warning"
	case audit.ActionUserEnabled:
		view.Label = "User re-enabled"
		view.Summary = "User #" + event.SubjectID
		view.Detail = "Login allowed again; no sessions restored"
		view.StateClass = "ok"
	case audit.ActionUserPasswordChanged:
		view.Label = "Password changed"
		view.Summary = "User #" + event.SubjectID
		view.Detail = "Self-service change; previous sessions revoked"
		view.StateClass = "ok"
	case audit.ActionUserPasswordReset:
		view.Label = "Password reset"
		view.Summary = "User #" + event.SubjectID
		view.Detail = "Temporary password set by an admin; all sessions revoked and a new password is required at next login"
		view.StateClass = "warning"
	default:
		return systemAuditEventView{}, false
	}
	return view, true
}

func auditDetailInt64(details map[string]string, key string) (int64, bool) {
	value, err := strconv.ParseInt(strings.TrimSpace(details[key]), 10, 64)
	return value, err == nil && value > 0
}

func auditNonnegativeInt(details map[string]string, key string) (int, bool) {
	raw, exists := details[key]
	if !exists {
		return 0, false
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	return value, err == nil && value >= 0
}

func auditPullRequestIndexList(details map[string]string, key string) (string, int, bool) {
	raw, exists := details[key]
	if !exists {
		return "", 0, false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0, true
	}
	parts := strings.Split(raw, ",")
	labels := make([]string, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		index, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || index <= 0 || index > 1_000_000 {
			return "", 0, false
		}
		if _, exists := seen[index]; exists {
			return "", 0, false
		}
		seen[index] = struct{}{}
		labels = append(labels, "#"+strconv.Itoa(index))
	}
	return strings.Join(labels, ", "), len(labels), true
}

func auditTextDetail(details map[string]string, key string, maxLength int) (string, bool) {
	raw, exists := details[key]
	value := strings.TrimSpace(raw)
	if !exists || value == "" || len(value) > maxLength {
		return "", false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return value, true
}

func auditHeadSHA(details map[string]string, key string) (string, bool) {
	value, ok := auditTextDetail(details, key, 64)
	if !ok || len(value) < 6 {
		return "", false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return "", false
		}
	}
	return value, true
}

func auditSharedHeadRepositoryLabel(repo domain.Repository, details map[string]string) string {
	if repo.ID > 0 {
		return repo.FullName()
	}
	if repositoryID, ok := auditDetailInt64(details, "repository_id"); ok {
		return "Repository #" + strconv.FormatInt(repositoryID, 10)
	}
	return "Repository"
}

func auditRepositoryLabel(repo domain.Repository, details map[string]string) string {
	if repo.ID > 0 {
		return repo.FullName()
	}
	if fullName := strings.TrimSpace(details["full_name"]); fullName != "" {
		return fullName
	}
	if repositoryID := strings.TrimSpace(details["repository_id"]); repositoryID != "" {
		return "Repository #" + repositoryID
	}
	return "Repository"
}

func auditDetailOrDash(details map[string]string, key string) string {
	if value := strings.TrimSpace(details[key]); value != "" {
		return value
	}
	return "—"
}

func auditRotationDetail(details map[string]string, key string) string {
	if details[key] == "true" {
		return "Existing credential was replaced"
	}
	return "Credential was set"
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

func (s *Server) scheduledFreezePageData(ctx context.Context) ([]domain.Repository, []domain.BranchFreeze, []managedBranchOption, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	scheduled, err := s.scheduledFreezes(ctx, 100)
	if err != nil {
		return nil, nil, nil, err
	}
	branchOptions, err := s.managedBranchOptions(ctx, repositories)
	if err != nil {
		return nil, nil, nil, err
	}
	return repositories, scheduled, branchOptions, nil
}

func (s *Server) freezePageData(ctx context.Context) ([]domain.Repository, []domain.BranchFreeze, []freezeAuditView, []managedBranchOption, error) {
	repositories, err := s.repositories(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	freezes, err := s.activeFreezes(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	auditEvents, err := s.freezeAuditViews(ctx, repositories)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	branchOptions, err := s.managedBranchOptions(ctx, repositories)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return repositories, freezes, auditEvents, branchOptions, nil
}

func (s *Server) freezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze) []freezeView {
	repositoriesByID := make(map[int64]domain.Repository, len(repositories))
	for _, repo := range repositories {
		repositoriesByID[repo.ID] = repo
	}
	views := make([]freezeView, 0, len(freezes))
	for _, freeze := range freezes {
		views = append(views, freezeView{
			Freeze:          freeze,
			Repository:      repositoriesByID[freeze.RepositoryID],
			PlannedEndsAt:   optionalScheduleTime(freeze.PlannedEndsAt),
			HasPlannedEndAt: freeze.PlannedEndsAt != nil && !freeze.PlannedEndsAt.IsZero(),
		})
	}
	return views
}

func scheduledFreezeViews(repositories []domain.Repository, freezes []domain.BranchFreeze) []scheduledFreezeView {
	repositoriesByID := repositoriesByID(repositories)
	views := make([]scheduledFreezeView, 0, len(freezes))
	for _, scheduled := range freezes {
		label, stateClass := scheduledFreezeStatus(scheduled.Status)
		views = append(views, scheduledFreezeView{
			Freeze:        scheduled,
			Repository:    repositoriesByID[scheduled.RepositoryID],
			StartsAt:      optionalScheduleTime(scheduled.StartsAt),
			PlannedEndsAt: optionalScheduleTime(scheduled.PlannedEndsAt),
			EndedAt:       optionalScheduleTime(scheduled.EndsAt),
			StatusLabel:   label,
			StateClass:    stateClass,
			CanCancel:     scheduled.Status == domain.BranchFreezeStatusScheduled,
		})
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
			view.Actor = actorLabelForEvent(event, details["actor_kind"], details["actor_role"])
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
	case audit.ActionBranchFreezeCreated, audit.ActionBranchFreezeEnded, audit.ActionBranchFreezeCancelled, audit.ActionBranchFreezePlannedUnfreeze, audit.ActionFreezeScheduleCreated, audit.ActionFreezeScheduleCancelled, audit.ActionFreezeScheduleActivated, audit.ActionFreezeSchedulePlannedUnfreeze:
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

func actorLabelForEvent(event audit.Event, kind string, role string) string {
	role = strings.TrimSpace(role)
	if event.ActorUserID != nil {
		label := "user #" + strconv.FormatInt(*event.ActorUserID, 10)
		if role != "" {
			label += " (" + role + ")"
		}
		return label
	}
	return actorLabel(kind, role)
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
	jobsByRepository := make(map[int64]jobs.Job)
	if s.cfg.ReconciliationJobStore != nil {
		pending, err := s.cfg.ReconciliationJobStore.ListReconciliations(ctx)
		if err != nil {
			return nil, err
		}
		for _, job := range pending {
			jobsByRepository[job.RepositoryID] = job
		}
	}
	views := make([]repositoryView, 0, len(repositories))
	for _, repo := range repositories {
		view := repositoryView{Repository: repo}
		view.EnforcementLabel, view.EnforcementClass = enforcementView(repo.EnforcementState)
		view.IsSetupIncomplete = repo.EnforcementState == domain.EnforcementSetupIncomplete
		view.IsReady = repo.EnforcementState == domain.EnforcementReady
		view.IsUnhealthy = repo.EnforcementState == domain.EnforcementUnhealthy
		if repo.StatusPostVerifiedAt != nil {
			view.StatusPostVerifiedAt = formatReadinessTime(*repo.StatusPostVerifiedAt)
		}
		if repo.EnforcementFailedAt != nil {
			view.EnforcementFailedAt = formatReadinessTime(*repo.EnforcementFailedAt)
		}
		if view.IsUnhealthy {
			view.FailureRemediation = enforcementFailureRemediation(repo.EnforcementFailureReason)
			if job, ok := jobsByRepository[repo.ID]; ok {
				view.RecoveryAttempts = job.Attempts
				view.RecoveryInProgress = job.LeaseActive(time.Now().UTC())
				if !view.RecoveryInProgress {
					view.NextRecoveryAt = formatReadinessTime(job.RunAt)
				}
			}
		}
		if s.cfg.SetupCheckStore != nil {
			checks, err := s.cfg.SetupCheckStore.ListByRepository(ctx, repo.ID)
			if err != nil {
				return nil, err
			}
			view.SetupChecks = latestSetupChecks(checks)
			if len(view.SetupChecks) > 0 {
				view.LastCheckedAt = formatReadinessTime(view.SetupChecks[0].CheckedAt)
			}
		}
		branches, err := s.managedBranches(ctx, repo.ID)
		if err != nil {
			return nil, err
		}
		view.RepositoryChecks, view.Branches = groupReadinessChecks(repo, branches, view.SetupChecks)
		if view.IsSetupIncomplete {
			view.VerifyAvailable, view.VerifyBlockedReason = verifyActionAvailability(view.SetupChecks)
		}
		views = append(views, view)
	}
	return views, nil
}

// verifyActionAvailability decides whether the Verify status posting action
// is offered based on the latest recorded readiness run. Every mandatory
// read-only check must be OK; the expected status-posting-untested warning is
// the only allowed non-OK result.
func verifyActionAvailability(latest []setupcheck.Check) (bool, string) {
	if len(latest) == 0 {
		return false, "Run the read-only readiness checks first. Verification is offered once every mandatory check passes."
	}
	for _, check := range latest {
		if check.Result.Status == setupcheck.StatusOK {
			continue
		}
		if check.Result.Name == setupcheck.CheckStatusPostingUntested && check.Result.Status == setupcheck.StatusWarning {
			continue
		}
		return false, "Fix the failing readiness checks and rerun them. Verification is offered once every mandatory read-only check passes."
	}
	return true, ""
}

func (s *Server) managedBranches(ctx context.Context, repositoryID int64) ([]domain.RepositoryBranch, error) {
	if s.cfg.RepositoryStore == nil {
		return nil, nil
	}
	return s.cfg.RepositoryStore.ListBranches(ctx, repositoryID)
}

func groupReadinessChecks(repo domain.Repository, branches []domain.RepositoryBranch, checks []setupcheck.Check) ([]setupcheck.Check, []repositoryBranchView) {
	repositoryChecks := make([]setupcheck.Check, 0)
	checksByBranch := make(map[string][]setupcheck.Check)
	for _, check := range checks {
		if check.Branch == "" {
			repositoryChecks = append(repositoryChecks, check)
			continue
		}
		checksByBranch[check.Branch] = append(checksByBranch[check.Branch], check)
	}
	views := make([]repositoryBranchView, 0, len(branches))
	for _, branch := range branches {
		branchChecks := checksByBranch[branch.Name]
		label, class := readinessStatus(branchChecks)
		lastCheckedAt := ""
		if branch.LastCheckedAt != nil {
			lastCheckedAt = formatReadinessTime(*branch.LastCheckedAt)
		}
		views = append(views, repositoryBranchView{
			Name:          branch.Name,
			IsDefault:     branch.Name == repo.DefaultBranch,
			SetupLabel:    label,
			SetupClass:    class,
			LastCheckedAt: lastCheckedAt,
			Checks:        branchChecks,
		})
	}
	return repositoryChecks, views
}

func readinessStatus(checks []setupcheck.Check) (string, string) {
	if len(checks) == 0 {
		return "not checked", "status-warning"
	}
	status := setupcheck.StatusOK
	for _, check := range checks {
		if check.Result.Status == setupcheck.StatusFailed {
			return "failed", "status-failed"
		}
		if check.Result.Status == setupcheck.StatusWarning {
			status = setupcheck.StatusWarning
		}
	}
	if status == setupcheck.StatusWarning {
		return "warning", "status-warning"
	}
	return "passed", "status-ok"
}

// enforcementFailureRemediation maps the stable stored failure categories to
// concrete operator guidance shown next to the unhealthy state.
func enforcementFailureRemediation(reason string) string {
	switch reason {
	case domain.EnforcementFailureReadinessChecks:
		return "Fix the failing read-only readiness checks below (branch protection, required context, webhook evidence, token access), rerun them, then retry enforcement recovery."
	case domain.EnforcementFailureSetupStatusPost:
		return "The stored status token could not post a commit status. Fix the token permissions or forge setup, then retry enforcement recovery."
	case domain.EnforcementFailureOpenPRSync:
		return "Open pull requests could not be listed from the forge. Check forge availability and token read access, then retry enforcement recovery."
	case domain.EnforcementFailureEvaluation:
		return "The current freeze policy could not be evaluated. Review the audit log for the failed run, then retry enforcement recovery."
	case domain.EnforcementFailurePublication:
		return "One or more " + domain.RequiredStatusContext + " statuses could not be posted. Check forge availability and token permissions, then retry enforcement recovery."
	case domain.EnforcementFailureRuntime:
		return "Runtime convergence bookkeeping did not complete. Automatic recovery will rerun the complete current repository policy."
	default:
		return "Review the sanitized failure in the audit log, fix the forge setup or credentials, then retry enforcement recovery."
	}
}

func enforcementView(state domain.EnforcementState) (string, string) {
	switch state {
	case domain.EnforcementActive:
		return "enforcement active", "status-ok"
	case domain.EnforcementUnhealthy:
		return "unhealthy", "status-failed"
	case domain.EnforcementReady:
		return "ready", "status-warning"
	default:
		return "setup incomplete", "status-warning"
	}
}

func formatReadinessTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04 UTC")
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

func (s *Server) renderRepositories(w http.ResponseWriter, views []repositoryView, formError string, session sessionState) {
	overview := repositoryOverview{RepositoryCount: len(views), WebhookSecretStorageEnabled: s.cfg.RepositorySecretEncryptionConfigured}
	for _, view := range views {
		if view.Repository.HasWebhookSecret {
			overview.WebhookConfiguredCount++
		}
		if view.Repository.HasStatusToken {
			overview.StatusTokenConfiguredCount++
		}
		if len(view.SetupChecks) > 0 {
			overview.SetupCheckRepositoryCount++
		}
		if view.Repository.EnforcementActive() {
			overview.EnforcementActiveCount++
		}
	}
	s.render(w, repositoriesTemplate, map[string]any{
		"AppName":                           s.cfg.AppName,
		"ActivePage":                        "repositories",
		"Overview":                          overview,
		"RepositoryViews":                   views,
		"FormError":                         formError,
		"CSRFToken":                         session.CSRFToken,
		"CurrentUser":                       currentUserFromSession(session),
		"RequiredContext":                   domain.RequiredStatusContext,
		"SetupSteps":                        setupcheck.ManualSetupSteps(),
		"WebhookSecretEncryptionConfigured": s.cfg.RepositorySecretEncryptionConfigured,
	})
}

func (s *Server) renderFreezes(w http.ResponseWriter, repositories []domain.Repository, freezes []freezeView, auditEvents []freezeAuditView, branchOptions []managedBranchOption, formError string, session sessionState) {
	s.render(w, freezesTemplate, map[string]any{
		"AppName":                 s.cfg.AppName,
		"ActivePage":              "freezes",
		"CurrentUser":             currentUserFromSession(session),
		"EnforceableRepositories": enforcementActiveRepositories(repositories),
		"BranchOptions":           branchOptions,
		"Freezes":                 freezes,
		"AuditEvents":             auditEvents,
		"FormError":               formError,
		"CSRFToken":               session.CSRFToken,
	})
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

func (s *Server) renderScheduledFreezes(w http.ResponseWriter, repositories []domain.Repository, scheduled []scheduledFreezeView, branchOptions []managedBranchOption, formError string, session sessionState) {
	s.render(w, scheduledFreezesTemplate, map[string]any{
		"AppName":                 s.cfg.AppName,
		"ActivePage":              "scheduled",
		"CurrentUser":             currentUserFromSession(session),
		"EnforceableRepositories": enforcementActiveRepositories(repositories),
		"BranchOptions":           branchOptions,
		"ScheduledFreezes":        scheduled,
		"FormError":               formError,
		"CSRFToken":               session.CSRFToken,
	})
}

func (s *Server) renderDecisions(w http.ResponseWriter, repositories []domain.Repository, results []statusResultView, formError string, session sessionState, confirmations ...sharedHeadConfirmationView) {
	data := map[string]any{
		"AppName":                 s.cfg.AppName,
		"ActivePage":              "thaws",
		"CurrentUser":             currentUserFromSession(session),
		"EnforceableRepositories": enforcementActiveRepositories(repositories),
		"Results":                 results,
		"FormError":               formError,
		"CSRFToken":               session.CSRFToken,
		"RequiredContext":         domain.RequiredStatusContext,
	}
	if len(confirmations) > 0 {
		data["SharedHeadConfirmation"] = confirmations[0]
	}
	s.render(w, decisionsTemplate, data)
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
		"ActivePage":   "activity",
		"CurrentUser":  currentUserFromSession(session),
		"CSRFToken":    session.CSRFToken,
		"Publications": publications,
		"Attempts":     attempts,
	})
}

func (s *Server) renderWebhookDeliveries(w http.ResponseWriter, auditLog auditLogView, session sessionState) {
	s.render(w, webhookDeliveriesTemplate, map[string]any{
		"AppName":                 s.cfg.AppName,
		"ActivePage":              "audit",
		"CurrentUser":             currentUserFromSession(session),
		"CSRFToken":               session.CSRFToken,
		"RequiredContext":         domain.RequiredStatusContext,
		"Deliveries":              auditLog.Deliveries,
		"SystemEvents":            auditLog.SystemEvents,
		"StatusAttempts":          auditLog.StatusAttempts,
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

func (s *Server) renderSetup(w http.ResponseWriter, r *http.Request, formError string) {
	s.renderSetupStatus(w, r, formError, http.StatusOK)
}

func (s *Server) renderSetupStatus(w http.ResponseWriter, r *http.Request, formError string, status int) {
	csrfToken, err := s.newSetupCSRFToken(w, r)
	if err != nil {
		internalServerError(w)
		return
	}
	tpl, err := template.New("page").Parse(setupTemplate)
	if err != nil {
		internalServerError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = tpl.Execute(w, map[string]any{
		"AppName":   s.cfg.AppName,
		"FormError": formError,
		"CSRFToken": csrfToken,
	})
}

func (s *Server) renderLoginStatus(w http.ResponseWriter, r *http.Request, formError string, status int) {
	csrfToken, err := s.newLoginCSRFToken(w, r)
	if err != nil {
		internalServerError(w)
		return
	}
	tpl, err := template.New("page").Parse(loginTemplate)
	if err != nil {
		internalServerError(w)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = tpl.Execute(w, map[string]any{
		"AppName":   s.cfg.AppName,
		"FormError": formError,
		"CSRFToken": csrfToken,
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
        <a class="tg-nav-item{{ if eq .ActivePage "audit" }} is-active{{ end }}" href="/webhooks"><svg class="tg-icon"><use href="#tg-i-audit"></use></svg>Audit Log</a>
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

const authPageHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .AppName }}</title>
  <link rel="stylesheet" href="/static/thawguard.css">
</head>
<body>
  <main class="tg-main tg-auth-page">
    <section class="tg-panel tg-auth-card">
      <div class="tg-auth-brand">
        <span class="tg-logo-mark" aria-hidden="true"><svg class="tg-brand-icon" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" d="M12 21.7c4.5-2.2 7-5.7 7-9.7V5.3L12 2.6 5 5.3V12c0 4 2.5 7.5 7 9.7z M12 8v8 M8.5 10l7 4 M15.5 10l-7 4"/></svg></span>
        <span>{{ .AppName }}</span>
      </div>`

const authPageFoot = `
    </section>
  </main>
</body></html>`

const setupTemplate = authPageHead + `
      <div class="tg-panel-head tg-panel-head-stacked">
        <div>
          <p class="eyebrow">First admin setup</p>
          <h1 class="tg-title">Create the first Thawguard admin</h1>
          <p class="tg-subtitle">Create a local admin account. The first account starts with all MVP roles so a fresh install can configure repositories and run freeze/thaw flows.</p>
        </div>
      </div>
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      <form method="post" action="/setup" class="tg-setup-form tg-auth-form">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label>Email <input type="email" name="email" autocomplete="email" required></label>
        <label>Display name <input name="display_name" autocomplete="name" required></label>
        <label class="tg-field-wide">Password <input type="password" name="password" autocomplete="new-password" minlength="12" required></label>
        <div class="tg-form-submit tg-field-wide"><button type="submit" class="tg-btn tg-btn-primary">Create admin</button></div>
      </form>
      <p class="tg-local-note"><span>Use a strong local password. Thawguard remains cooperative enforcement for trusted teams, not an unbypassable forge security boundary.</span></p>` + authPageFoot

const loginTemplate = authPageHead + `
      <div class="tg-panel-head tg-panel-head-stacked">
        <div>
          <p class="eyebrow">Local sign in</p>
          <h1 class="tg-title">Sign in to Thawguard</h1>
          <p class="tg-subtitle">Freeze branches. Thaw exceptions. Keep release flow auditable.</p>
        </div>
      </div>
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      <form method="post" action="/login" class="tg-setup-form tg-auth-form">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label class="tg-field-wide">Email <input type="email" name="email" autocomplete="email" required autofocus></label>
        <label class="tg-field-wide">Password <input type="password" name="password" autocomplete="current-password" required></label>
        <div class="tg-form-submit tg-field-wide"><button type="submit" class="tg-btn tg-btn-primary">Sign in</button></div>
      </form>` + authPageFoot

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

const accountPasswordTemplate = authPageHead + `
      <div class="tg-panel-head tg-panel-head-stacked">
        <div>
          <p class="eyebrow">Account security</p>
          <h1 class="tg-title">Change your password</h1>
          {{ if .MustChangePassword }}
          <p class="tg-subtitle">A temporary password was set for this account. Choose a new password to continue using {{ .AppName }}.</p>
          {{ else }}
          <p class="tg-subtitle">Changing your password signs out every session for this account and starts a fresh one here.</p>
          {{ end }}
        </div>
      </div>
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      <form method="post" action="/account/password" class="tg-setup-form tg-auth-form">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label class="tg-field-wide">Current password <input type="password" name="current_password" autocomplete="current-password" required></label>
        <label class="tg-field-wide">New password <input type="password" name="new_password" autocomplete="new-password" minlength="12" required></label>
        <label class="tg-field-wide">Confirm new password <input type="password" name="new_password_confirmation" autocomplete="new-password" minlength="12" required></label>
        <div class="tg-form-submit tg-field-wide"><button type="submit" class="tg-btn tg-btn-primary">Change password</button></div>
      </form>
      <div class="tg-account-links">
        {{ if not .MustChangePassword }}<a class="tg-btn tg-btn-secondary tg-btn-sm" href="/">Back to dashboard</a>{{ end }}
        <form method="post" action="/logout">
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm">Log out</button>
        </form>
      </div>` + authPageFoot

const dashboardTemplate = pageHead + `
  <main class="tg-main tg-dashboard">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Dashboard</h1>
        <p class="tg-subtitle">Freeze branches. Thaw exceptions. Keep release flow auditable.</p>
      </div>
      <div class="tg-header-actions">
        {{ if .CurrentUser.CanFreeze }}
        <a class="tg-btn tg-btn-primary" href="/freezes"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg>Freeze Branch</a>
        {{ end }}
        {{ if .CurrentUser.CanThaw }}
        <a class="tg-btn tg-btn-secondary" href="/decisions"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Thaw PR</a>
        {{ end }}
      </div>
    </header>

    <section class="tg-stats" aria-label="Dashboard summary">
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg></span>
        <span><span class="tg-stat-label">Active Freezes</span><strong class="tg-stat-value">{{ .ActiveFreezeCount }}</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg></span>
        <span><span class="tg-stat-label">Active Thaws</span><strong class="tg-stat-value">0</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-activity"></use></svg></span>
        <span><span class="tg-stat-label">Events Today</span><strong class="tg-stat-value">0</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-repositories"></use></svg></span>
        <span><span class="tg-stat-label">Repos Monitored</span><strong class="tg-stat-value">{{ .RepositoryCount }}</strong></span>
      </article>
      <article class="tg-stat tg-stat-scheduled">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span>
        <span><span class="tg-stat-label">Schedules shown</span><strong class="tg-stat-value">{{ .ScheduledFreezePreviewCount }}</strong></span>
      </article>
    </section>

    <section class="tg-columns">
      <article class="tg-panel">
        <div class="tg-panel-head"><h2>Active Freezes</h2><span class="tg-badge">{{ .ActiveFreezeCount }} active</span></div>
        {{ if .Freezes }}
          {{ range .Freezes }}
          <div class="tg-freeze-row">
            <div class="tg-freeze-main"><span class="tg-lock" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg></span><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch">{{ .Freeze.Branch }}</code></div>
            <div class="tg-freeze-meta"><span>{{ .Freeze.Reason }}</span><span class="tg-dot">·</span><span class="tg-muted">recorded locally</span></div>
          </div>
          {{ end }}
        {{ else }}
          <div class="tg-empty-row">
            <strong>No active freezes yet</strong>
            <span>Create a local freeze to see branch cards here.</span>
          </div>
        {{ end }}
      </article>

      <article class="tg-panel">
        <div class="tg-panel-head"><h2>Recent Events</h2><a class="tg-btn tg-btn-secondary tg-btn-sm" href="/webhooks">View All</a></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-freeze"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg></span><span>Branch freeze workflow is ready for local records</span><span class="tg-muted">local</span></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-ok"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span><span>Commit statuses post only for enforcement-active repositories</span><span class="tg-muted">enforcement</span></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-fail"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span><span>Signed webhook receiver stores sanitized delivery metadata only</span><span class="tg-muted">safe</span></div>
        <div class="tg-event-row"><span class="tg-event-icon tg-event-ok"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span><span>Required status context is <code>` + domain.RequiredStatusContext + `</code></span><span class="tg-muted">future</span></div>
      </article>
    </section>

    <section class="tg-panel tg-scheduled-panel">
      <div class="tg-panel-head tg-scheduled-head">
        <h2>Scheduled Windows</h2>
        <span class="tg-badge tg-badge-scheduled">{{ .ScheduledFreezePreviewCount }} shown</span>
        <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/scheduled-freezes">View Schedules</a>
      </div>
      {{ if .ScheduledFreezes }}
        {{ range .ScheduledFreezes }}
        <div class="tg-schedule-row">
          <div class="tg-schedule-main"><span class="tg-scheduled-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch tg-branch-scheduled">{{ .Freeze.Branch }}</code></div>
          <div class="tg-schedule-meta"><span><span class="tg-caps">Starts</span> {{ .StartsAt }}</span><span><span class="tg-caps">Planned end</span> {{ .PlannedEndsAt }}</span><span class="tg-dot">·</span><span>{{ .Freeze.Reason }}</span></div>
          <div class="tg-schedule-actions"><span class="status status-{{ .StateClass }}">{{ .StatusLabel }}</span></div>
        </div>
        {{ end }}
      {{ else }}
        <div class="tg-empty-row"><strong>No scheduled windows yet</strong><span>Create a one-time freeze window from Scheduled Freezes.</span></div>
      {{ end }}
    </section>

    <section class="tg-warning-callout">
      <span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
      <span>Repositories start setup-incomplete and cannot enforce freezes yet. Read-only readiness checks are available, but activation still requires a later controlled status-post test.</span>
      <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories">View Setup</a>
    </section>
  </main>` + pageFoot

const webhookDeliveriesTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-audit-page">
    <header class="tg-header">
      <div>
        <p class="eyebrow">Signed webhook delivery history</p>
        <h1 class="tg-title">Audit Log</h1>
        <p class="tg-subtitle">Inspect sanitized webhook delivery metadata, verification state, and local processing outcomes.</p>
      </div>
      <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>Sanitized local metadata only</span>
    </header>

    <section class="tg-warning-callout">
      <span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
      <span>This page does not store or render raw webhook payloads, signatures, webhook secrets, or status tokens. Local users are role-gated for audit visibility.</span>
    </section>

    <section class="tg-panel tg-data-panel tg-audit-log-panel">
      <div class="tg-panel-head"><h2>System activity</h2><span class="tg-badge tg-badge-info">{{ len .SystemEvents }} audit events</span></div>
      <p class="tg-panel-subtitle">Recent setup, freeze, sync, and thaw actions recorded as sanitized audit events.</p>
      {{ if .SystemEvents }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-audit-table">
          <caption class="tg-sr-only">Recent system activity</caption>
          <thead><tr><th>Time</th><th>Action</th><th>Repository</th><th>Summary</th><th>Actor</th><th>Details</th></tr></thead>
          <tbody>
          {{ range .SystemEvents }}
            <tr>
              <td data-label="Time">{{ .CreatedAt }}</td>
              <td data-label="Action"><span class="status status-{{ .StateClass }}">{{ .Label }}</span></td>
              <td data-label="Repository"><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-repositories"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository{{ end }}</code></span></td>
              <td data-label="Summary">{{ .Summary }}</td>
              <td data-label="Actor">{{ .Actor }}</td>
              <td data-label="Details">{{ .Detail }}</td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row tg-data-empty"><strong>No system activity yet</strong><span>Repository setup, freeze lifecycle, open PR sync, and thaw approvals will appear here.</span></div>
      {{ end }}
    </section>

    <section class="tg-panel tg-data-panel tg-audit-log-panel">
      <div class="tg-panel-head"><h2>Status publication attempts</h2><span class="tg-badge tg-badge-info">{{ len .StatusAttempts }} attempts</span></div>
      <p class="tg-panel-subtitle">Recent live posting attempts for the <code>{{ .RequiredContext }}</code> status context. Errors shown here are already sanitized by the publisher.</p>
      {{ if .StatusAttempts }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-audit-table">
          <caption class="tg-sr-only">Recent status publication attempts</caption>
          <thead><tr><th>Attempted</th><th>Repository</th><th>PR</th><th>Head SHA</th><th>Mode</th><th>Result</th><th>Description</th></tr></thead>
          <tbody>
          {{ range .StatusAttempts }}
            <tr>
              <td data-label="Attempted">{{ .AttemptedAt }}</td>
              <td data-label="Repository"><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-repositories"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Attempt.RepositoryID }}{{ end }}</code></span></td>
              <td data-label="PR">#{{ .Attempt.PullRequestIndex }}</td>
              <td data-label="Head SHA"><code>{{ .Attempt.HeadSHA }}</code><small class="tg-muted">{{ .Attempt.TargetBranch }}</small></td>
              <td data-label="Mode"><code>{{ .Attempt.Mode }}</code></td>
              <td data-label="Result"><span class="status status-{{ if eq .Attempt.Result "posted" }}ok{{ else if eq .Attempt.Result "failed" }}failed{{ else }}pending{{ end }}">{{ .Attempt.Result }}</span></td>
              <td data-label="Description">{{ .Attempt.Description }}{{ if .Attempt.Error }}<small class="tg-muted">{{ .Attempt.Error }}</small>{{ end }}</td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row tg-data-empty"><strong>No status publication attempts yet</strong><span>Live status post attempts will appear here after freeze/thaw recomputation for enforcement-active repositories.</span></div>
      {{ end }}
    </section>

    <section class="tg-panel tg-data-panel tg-audit-log-panel">
      <div class="tg-table-toolbar" aria-label="Audit log controls">
        <div class="tg-toolbar-main">
          <h2>Recent webhook deliveries</h2>
          <p>Latest signed pull request webhook receipts and local recomputation processing states.</p>
        </div>
        <div class="tg-toolbar-controls" aria-label="Audit log table controls">
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="#audit-filters">Filters{{ if .Filters.HasActiveFilters }} active{{ end }}</a>
        </div>
      </div>

      <section id="audit-filters" class="tg-modal tg-filter-modal" aria-labelledby="audit-filters-title">
        <a class="tg-modal-backdrop" href="#" aria-label="Close audit filters"></a>
        <div class="tg-modal-card" role="dialog" aria-modal="true">
          <div class="tg-modal-head">
            <h2 id="audit-filters-title">Filter audit log</h2>
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

      <footer class="tg-pagination" aria-label="Audit log pagination">
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
          <span>Adjust filters or clear controls to return to the full audit log.</span>
          {{ else }}
          <strong>No webhook deliveries recorded yet</strong>
          <span>Send a signed pull request webhook to see sanitized audit metadata here.</span>
          {{ end }}
        </div>
      {{ end }}
    </section>
  </main>` + pageFoot

const publicationsTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Status publication diagnostics</p>
      <h1>Status publications</h1>
      <p>Each intent below is the latest desired <code>thawguard/freeze</code> status per repository head. Attempts record real posted or failed deliveries to the forge for enforcement-active repositories; errors are sanitized before storage.</p>
    </section>

    <section class="panel">
      <h2>Latest desired statuses</h2>
      {{ if .Publications }}
      <table>
        <thead><tr><th>Last updated</th><th>Repository</th><th>PR</th><th>Target branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Mode</th><th>Description</th></tr></thead>
        <tbody>
        {{ range .Publications }}
          <tr>
            <td data-label="Last updated">{{ .UpdatedAt }}</td>
            <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Publication.RepositoryID }}{{ end }}</td>
            <td data-label="PR">#{{ .Publication.PullRequestIndex }}</td>
            <td data-label="Target branch">{{ .Publication.TargetBranch }}</td>
            <td data-label="Head SHA"><code>{{ .Publication.HeadSHA }}</code></td>
            <td data-label="Context"><code>{{ .Publication.Context }}</code></td>
            <td data-label="State"><span class="status status-{{ .Publication.State }}">{{ .Publication.State }}</span></td>
            <td data-label="Mode"><code>{{ .Publication.DeliveryMode }}</code></td>
            <td data-label="Description">{{ .Publication.Description }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No local publication intents yet.</p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Recent live posting attempts</h2>
      <p class="muted">Posted and failed attempts against the forge. Historical records from older databases may still appear here.</p>
      {{ if .Attempts }}
      <table>
        <thead><tr><th>Attempted</th><th>Repository</th><th>PR</th><th>Target branch</th><th>Head SHA</th><th>Context</th><th>State</th><th>Mode</th><th>Result</th><th>Description</th><th>Error</th></tr></thead>
        <tbody>
        {{ range .Attempts }}
          <tr>
            <td data-label="Attempted">{{ .AttemptedAt }}</td>
            <td data-label="Repository">{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Attempt.RepositoryID }}{{ end }}</td>
            <td data-label="PR">#{{ .Attempt.PullRequestIndex }}</td>
            <td data-label="Target branch">{{ .Attempt.TargetBranch }}</td>
            <td data-label="Head SHA"><code>{{ .Attempt.HeadSHA }}</code></td>
            <td data-label="Context"><code>{{ .Attempt.Context }}</code></td>
            <td data-label="State"><span class="status status-{{ .Attempt.State }}">{{ .Attempt.State }}</span></td>
            <td data-label="Mode"><code>{{ .Attempt.Mode }}</code></td>
            <td data-label="Result"><code>{{ .Attempt.Result }}</code></td>
            <td data-label="Description">{{ .Attempt.Description }}</td>
            <td data-label="Error">{{ if .Attempt.Error }}{{ .Attempt.Error }}{{ else }}—{{ end }}</td>
          </tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No status publication attempts yet.</p>
      {{ end }}
    </section>
  </main>` + pageFoot

const repositoriesTemplate = pageHead + `
  <main class="tg-main tg-setup-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Repositories</h1>
        <p class="tg-subtitle">Connect Forgejo/Codeberg repositories and verify freeze setup.</p>
      </div>
      {{ if .CurrentUser.CanManageRepositories }}
      <div class="tg-header-actions">
        <a class="tg-btn tg-btn-primary" href="#connect-repository"><svg class="tg-icon"><use href="#tg-i-plus"></use></svg>Add Repository</a>
      </div>
      {{ end }}
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    <section class="tg-stats tg-setup-stats" aria-label="Repository setup summary">
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-repositories"></use></svg></span>
        <span><span class="tg-stat-label">Repos</span><strong class="tg-stat-value">{{ .Overview.RepositoryCount }}</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span>
        <span><span class="tg-stat-label">Webhooks</span><strong class="tg-stat-value">{{ .Overview.WebhookConfiguredCount }}</strong></span>
      </article>
      <article class="tg-stat">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-key"></use></svg></span>
        <span><span class="tg-stat-label">Status tokens</span><strong class="tg-stat-value">{{ .Overview.StatusTokenConfiguredCount }}</strong></span>
      </article>
      <article class="tg-stat tg-stat-info">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span>
        <span><span class="tg-stat-label">Checks</span><strong class="tg-stat-value">Local</strong></span>
      </article>
      <article class="tg-stat tg-stat-scheduled">
        <span class="tg-stat-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-icy-shield"></use></svg></span>
        <span><span class="tg-stat-label">Enforcing</span><strong class="tg-stat-value">{{ .Overview.EnforcementActiveCount }}</strong></span>
      </article>
    </section>

    {{ if .CurrentUser.CanManageRepositories }}
    <section id="connect-repository" class="tg-modal tg-connect-modal" aria-labelledby="connect-repository-title">
      <a class="tg-modal-backdrop" href="#" aria-label="Close connect repository"></a>
      <div class="tg-modal-card" role="dialog" aria-modal="true">
        <div class="tg-modal-head">
          <h2 id="connect-repository-title">Connect a repository</h2>
          <a href="#" class="tg-modal-close" aria-label="Close"><svg class="tg-icon"><use href="#tg-i-close"></use></svg></a>
        </div>
        <p class="tg-setup-copy">Add the Forgejo or Codeberg repository Thawguard should watch. The required status context stays fixed as <code>{{ .RequiredContext }}</code>.</p>
        <form method="post" action="/repositories" class="tg-setup-form tg-connect-form">
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <label>Forge
            <select name="forge">
              <option value="forgejo">Forgejo</option>
              <option value="codeberg">Codeberg</option>
            </select>
          </label>
          <label>Base URL <input name="base_url" value="https://codeberg.org"></label>
          <label>Owner <input name="owner" placeholder="acme" required></label>
          <label>Repository <input name="name" placeholder="shop-api" required></label>
          <label>Default branch <input name="default_branch" value="main"></label>
          <div class="tg-form-submit"><button type="submit" class="tg-btn tg-btn-primary">Connect</button></div>
        </form>
        <p class="tg-local-note"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg><span>Repository credentials are write-only and restricted to admins.</span></p>
      </div>
    </section>
    {{ else }}
    <section class="tg-warning-callout">
      <span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
      <span>Your role can view repository readiness evidence. Admin role is required to add repositories, rotate credentials, or run readiness checks.</span>
    </section>
    {{ end }}

    <div class="tg-section-heading tg-section-heading-compact">
      <div>
        <h2>Configured repositories</h2>
        <p>Run read-only Forgejo/Codeberg readiness checks for repository access, signed webhook evidence, and every exact managed branch.</p>
      </div>
    </div>

    {{ if .RepositoryViews }}
    <section class="tg-repo-grid" aria-label="Configured repositories">
      {{ range $view := .RepositoryViews }}
      <article class="tg-repo-card">
        <div class="tg-repo-card-head">
          <div>
            <p class="tg-repo-kicker">{{ .Repository.Forge }}</p>
            <h3>{{ .Repository.FullName }}</h3>
          </div>
          <div class="tg-repo-badges">
            <span class="tg-badge {{ .EnforcementClass }}">{{ .EnforcementLabel }}</span>
            {{ if .Repository.HasWebhookSecret }}<span class="tg-badge status-ok">webhook configured</span>{{ else }}<span class="tg-badge status-warning">webhook missing</span>{{ end }}
            {{ if .Repository.HasStatusToken }}<span class="tg-badge status-ok">status token configured</span>{{ else }}<span class="tg-badge status-warning">status token missing</span>{{ end }}
          </div>
        </div>
        {{ if .Repository.EnforcementActive }}
        <p class="tg-muted">Enforcement is active{{ if .StatusPostVerifiedAt }}; status posting last verified at {{ .StatusPostVerifiedAt }}{{ end }}. Freezes, schedules, and thaw approvals publish <code>` + domain.RequiredStatusContext + `</code> statuses for this repository.</p>
        {{ else if .IsReady }}
        <p class="tg-muted">Status posting verified{{ if .StatusPostVerifiedAt }} at {{ .StatusPostVerifiedAt }}{{ end }} with a controlled <code>` + domain.SetupStatusContext + `</code> status. Ready to activate — enforcement stays off until an admin explicitly activates it.</p>
        {{ else if .IsUnhealthy }}
        <p class="error">Enforcement is unhealthy{{ if .Repository.EnforcementFailureReason }}: {{ .Repository.EnforcementFailureReason }}{{ if .EnforcementFailedAt }} ({{ .EnforcementFailedAt }}){{ end }}{{ else }}: the last enforcement run failed{{ end }}. Freeze, schedule, and thaw actions stay disabled while recovery reruns the complete enforcement proof.</p>
        {{ if .RecoveryInProgress }}
        <p class="tg-muted">Recovery in progress. Attempt count: {{ .RecoveryAttempts }}.</p>
        {{ else }}
        <p class="tg-muted">Automatic recovery is pending. Attempt count: {{ .RecoveryAttempts }}{{ if .NextRecoveryAt }}. Next retry: {{ .NextRecoveryAt }}{{ end }}.</p>
        {{ end }}
        <p class="tg-muted">{{ .FailureRemediation }}</p>
        {{ else if not .Repository.EnforcementActive }}
        <p class="tg-muted">This repository cannot enforce freezes, schedules, or thaws. Readiness checks are read-only; status posting is not tested until the controlled verification below.</p>
        {{ end }}
        <dl class="tg-repo-meta">
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-git-branch"></use></svg></span><dt>Default branch</dt><dd><code>{{ .Repository.DefaultBranch }}</code></dd></div>
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-check"></use></svg></span><dt>Required context</dt><dd><code>` + domain.RequiredStatusContext + `</code></dd></div>
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-key"></use></svg></span><dt>Status token</dt><dd>{{ if .Repository.HasStatusToken }}<span class="tg-badge status-ok">stored encrypted</span>{{ else }}<span class="tg-badge status-warning">not stored</span>{{ end }}</dd></div>
          <div><span class="tg-meta-icon"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg></span><dt>Last readiness check</dt><dd>{{ if .LastCheckedAt }}{{ .LastCheckedAt }}{{ else }}<span class="tg-badge status-warning">not checked</span>{{ end }}</dd></div>
        </dl>
        <div class="tg-repo-checks">
          <strong>Repository readiness</strong>
          {{ if .RepositoryChecks }}
            {{ range .RepositoryChecks }}
            <div class="tg-repo-check"><span class="status status-{{ .Result.Status }}">{{ if eq .Result.Status "ok" }}passed{{ else }}{{ .Result.Status }}{{ end }}</span><div><strong>{{ .Result.Name }}</strong><small>{{ .Result.Description }}{{ if .Result.Remediation }} {{ .Result.Remediation }}{{ end }}</small></div></div>
            {{ end }}
          {{ else }}
            <p class="tg-muted">No repository-level readiness evidence has been recorded yet.</p>
          {{ end }}
        </div>
        <div class="tg-repo-branches">
          <div class="tg-repo-branches-head">
            <strong>Managed branches</strong>
            <span class="tg-badge tg-badge-info">exact names only</span>
          </div>
          <p class="tg-muted">Freezes and scheduled freezes only apply to these exact branch names. Each branch is checked independently.</p>
          {{ if .Branches }}
          <ul class="tg-branch-list">
            {{ range .Branches }}
            <li class="tg-branch-row">
              <code class="tg-branch">{{ .Name }}</code>
              {{ if .IsDefault }}<span class="tg-badge tg-badge-info">default</span>{{ end }}
              <span class="tg-badge {{ .SetupClass }}">{{ .SetupLabel }}</span>
              {{ if .LastCheckedAt }}<small>checked {{ .LastCheckedAt }}</small>{{ end }}
              {{ if and $.CurrentUser.CanManageRepositories (not .IsDefault) (not $view.Repository.EnforcementActive) }}
              <form method="post" action="/repositories/branches/remove" data-confirm-submit data-confirm-title="Remove managed branch?" data-confirm-message="Freezes and schedules can no longer target this branch. Removal is rejected while the branch has an active or scheduled freeze." data-confirm-action="Remove branch">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ $view.Repository.ID }}">
                <input type="hidden" name="branch" value="{{ .Name }}">
                <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-close"></use></svg>Remove</button>
              </form>
              {{ end }}
              {{ if .Checks }}
              <div class="tg-repo-checks">
                {{ range .Checks }}
                <div class="tg-repo-check"><span class="status status-{{ .Result.Status }}">{{ if eq .Result.Status "ok" }}passed{{ else }}{{ .Result.Status }}{{ end }}</span><div><strong>{{ .Result.Name }}</strong><small>{{ .Result.Description }}{{ if .Result.Remediation }} {{ .Result.Remediation }}{{ end }}</small></div></div>
                {{ end }}
              </div>
              {{ else }}
              <small>No readiness evidence recorded for this branch.</small>
              {{ end }}
            </li>
            {{ end }}
          </ul>
          {{ else }}
          <p class="tg-muted">No managed branches are recorded for this repository. Add the exact branch names Thawguard should manage.</p>
          {{ end }}
          {{ if $.CurrentUser.CanManageRepositories }}
            {{ if .Repository.EnforcementActive }}
            <p class="tg-muted">Branch editing is disabled while enforcement is active. Deactivate repository enforcement before changing managed branches.</p>
            {{ else }}
            <form method="post" action="/repositories/branches" class="tg-branch-add-form">
              <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
              <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
              <input name="branch" maxlength="255" placeholder="release/1.4" aria-label="Add managed branch for {{ .Repository.FullName }}" required>
              <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-git-branch"></use></svg>Add branch</button>
            </form>
            {{ end }}
          {{ end }}
        </div>
        {{ if $.CurrentUser.CanManageRepositories }}
        <div class="tg-repo-actions">
          {{ if $.WebhookSecretEncryptionConfigured }}
          <div class="tg-credential-grid">
            <section class="tg-credential-card" data-credential-block>
              <div class="tg-credential-summary">
                <span class="tg-credential-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-key"></use></svg></span>
                <div>
                  <strong>Webhook secret</strong>
                  <span>{{ if .Repository.HasWebhookSecret }}Stored encrypted. Hidden until you intentionally rotate it.{{ else }}Required to verify signed pull_request webhooks.{{ end }}</span>
                </div>
                {{ if .Repository.HasWebhookSecret }}<span class="tg-badge status-ok">stored encrypted</span>{{ else }}<span class="tg-badge status-warning">missing</span>{{ end }}
              </div>
              {{ if .Repository.HasWebhookSecret }}
              <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn" data-credential-reveal data-credential-target="webhook-secret-{{ .Repository.ID }}" data-confirm-title="Rotate webhook secret?" data-confirm-message="The current encrypted webhook secret stays active until you submit a replacement. Reveal this input only when you are ready to update the matching forge webhook secret." data-confirm-action="Reveal secret input" aria-controls="webhook-secret-{{ .Repository.ID }}" aria-expanded="false"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>Rotate secret</button>
              <form method="post" action="/repositories/webhook-secret" id="webhook-secret-{{ .Repository.ID }}" class="tg-secret-form tg-credential-form" hidden data-credential-form>
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
                <input type="password" name="webhook_secret" minlength="16" maxlength="512" autocomplete="new-password" placeholder="New webhook secret" aria-label="New webhook secret for {{ .Repository.FullName }}" required disabled data-credential-input>
                <div class="tg-credential-form-actions">
                  <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-check"></use></svg>Save new secret</button>
                  <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn" data-credential-cancel>Cancel</button>
                </div>
              </form>
              {{ else }}
              <form method="post" action="/repositories/webhook-secret" class="tg-secret-form tg-credential-form is-visible">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
                <input type="password" name="webhook_secret" minlength="16" maxlength="512" autocomplete="new-password" placeholder="Webhook secret" aria-label="Webhook secret for {{ .Repository.FullName }}" required>
                <div class="tg-credential-form-actions">
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>Set secret</button>
                </div>
              </form>
              {{ end }}
            </section>

            <section class="tg-credential-card" data-credential-block>
              <div class="tg-credential-summary">
                <span class="tg-credential-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-key"></use></svg></span>
                <div>
                  <strong>Status token</strong>
                  <span>{{ if .Repository.HasStatusToken }}Stored encrypted. Hidden until rotation.{{ else }}Required for enforcement: posts the <code>` + domain.RequiredStatusContext + `</code> commit status and syncs open PRs.{{ end }}</span>
                </div>
                {{ if .Repository.HasStatusToken }}<span class="tg-badge status-ok">stored encrypted</span>{{ else }}<span class="tg-badge status-warning">missing</span>{{ end }}
              </div>
              {{ if .Repository.HasStatusToken }}
              <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn" data-credential-reveal data-credential-target="status-token-{{ .Repository.ID }}" data-confirm-title="Rotate status token?" data-confirm-message="The current encrypted status token stays active until you submit a replacement. Reveal this input only when you are ready to update live posting credentials for this repository." data-confirm-action="Reveal token input" aria-controls="status-token-{{ .Repository.ID }}" aria-expanded="false"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>Rotate token</button>
              <form method="post" action="/repositories/status-token" id="status-token-{{ .Repository.ID }}" class="tg-secret-form tg-credential-form" hidden data-credential-form>
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
                <input type="password" name="status_token" minlength="16" maxlength="1024" autocomplete="new-password" placeholder="New status token" aria-label="New status token for {{ .Repository.FullName }}" required disabled data-credential-input>
                <div class="tg-credential-form-actions">
                  <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-check"></use></svg>Save new token</button>
                  <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn" data-credential-cancel>Cancel</button>
                </div>
              </form>
              {{ else }}
              <form method="post" action="/repositories/status-token" class="tg-secret-form tg-credential-form is-visible">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
                <input type="password" name="status_token" minlength="16" maxlength="1024" autocomplete="new-password" placeholder="Status token" aria-label="Status token for {{ .Repository.FullName }}" required>
                <div class="tg-credential-form-actions">
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-key"></use></svg>Set token</button>
                </div>
              </form>
              {{ end }}
            </section>
          </div>
          <p class="tg-muted">Credential values are write-only and stored encrypted.</p>
          {{ else }}
          <p class="tg-muted">Set <code>THAWGUARD_SECRET_KEY</code> to save webhook secrets and status tokens.</p>
          {{ end }}
          <form method="post" action="/repositories/setup-check">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-health-check"></use></svg>Run readiness checks</button>
          </form>
          {{ if .IsSetupIncomplete }}
            {{ if .VerifyAvailable }}
          <form method="post" action="/repositories/status-verification">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-check"></use></svg>Verify status posting</button>
          </form>
          <p class="tg-muted">Verification reruns the read-only readiness checks, then posts one harmless <code>` + domain.SetupStatusContext + `</code> success status against the current default branch head. It proves the token can post statuses without touching the merge-gating <code>` + domain.RequiredStatusContext + `</code> context.</p>
            {{ else }}
          <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm tg-repo-action-btn" disabled>Verify status posting</button>
          <p class="tg-muted">{{ .VerifyBlockedReason }}</p>
            {{ end }}
          {{ end }}
          {{ if .IsReady }}
          <form method="post" action="/repositories/activate" data-confirm-submit data-confirm-title="Activate enforcement?" data-confirm-message="Activation reruns readiness and the controlled thawguard/setup status test, synchronizes current open pull requests, publishes real thawguard/freeze statuses for every affected head SHA, and enables freeze, schedule, and thaw operations for this repository." data-confirm-action="Activate enforcement">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-icy-shield"></use></svg>Activate enforcement</button>
          </form>
          {{ end }}
          {{ if .Repository.EnforcementActive }}
          <form method="post" action="/repositories/reconcile" data-confirm-submit data-confirm-title="Reconcile enforcement now?" data-confirm-message="Reconciliation reruns the read-only readiness checks, refreshes current open pull requests from the forge, and republishes the current thawguard/freeze policy for every affected head SHA. If convergence fails, enforcement is marked unhealthy until recovery succeeds." data-confirm-action="Reconcile now">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-health-check"></use></svg>Reconcile now</button>
          </form>
          {{ end }}
          {{ if .IsUnhealthy }}
          <form method="post" action="/repositories/recover" data-confirm-submit data-confirm-title="Retry enforcement recovery?" data-confirm-message="Recovery reruns every read-only readiness check, tests a controlled thawguard/setup status post, synchronizes current open pull requests, and republishes the current thawguard/freeze policy. The repository returns to active only after complete success; any failure keeps it unhealthy." data-confirm-action="Retry recovery">
            <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
            <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
            <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm tg-repo-action-btn"><svg class="tg-icon"><use href="#tg-i-icy-shield"></use></svg>Retry enforcement recovery</button>
          </form>
          {{ end }}
        </div>
        {{ else }}
        <div class="tg-empty-row"><strong>Read-only readiness evidence</strong><span>Ask an admin to change repository credentials or run readiness checks.</span></div>
        {{ end }}
      </article>
      {{ end }}
    </section>
    {{ else }}
    <section class="tg-panel tg-empty-row">
      <strong>No repositories configured yet</strong>
      <span>Add your first Forgejo or Codeberg repository to start setup.</span>
    </section>
    {{ end }}

    <section class="tg-panel tg-setup-checklist">
      <div class="tg-panel-head"><h2>Manual setup checklist</h2><span class="tg-badge tg-badge-info">local guidance</span></div>
      <div class="tg-checklist-grid">
        <article><span>1</span><div><strong>Required status context</strong><p>Configure every managed branch to require the exact context <code>{{ .RequiredContext }}</code>.</p></div></article>
        <article><span>2</span><div><strong>Signed webhook receiver</strong><p>Point pull request webhooks at <code>/webhooks/forgejo</code> with the repository webhook secret.</p></div></article>
        <article><span>3</span><div><strong>Read-only readiness</strong><p>Run the live read-only checks. Status posting remains unverified until a later controlled activation test.</p></div></article>
      </div>
    </section>
  </main>` + pageFoot

const freezesTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-freezes-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Branch Freezes</h1>
        <p class="tg-subtitle">Freeze a branch to block merges, then review and lift active freezes.</p>
      </div>
      <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg>Cooperative enforcement — auditable, not a hard security gate</span>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    <section class="tg-freeze-workbench" aria-label="Create branch freeze and preview impact">
      <section class="tg-panel tg-freeze-form-panel">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div>
            <h2>Create a freeze</h2>
            <p class="tg-panel-subtitle">Open PRs on the branch receive a failing <code>` + domain.RequiredStatusContext + `</code> status check.</p>
          </div>
        </div>
        {{ if not .CurrentUser.CanFreeze }}
        <div class="tg-empty-row">
          <strong>Read-only freeze access</strong>
          <span>Your role can view freezes. Explicit freezer role is required to create, lift, or cancel freezes.</span>
        </div>
        {{ else if .EnforceableRepositories }}
        <form method="post" action="/freezes" class="tg-setup-form tg-freeze-form" data-freeze-form>
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <input type="hidden" name="timezone_offset_minutes" value="0" data-timezone-offset-minutes>
          <label>Repository
            <select name="repository_id" required data-freeze-repository>
            {{ range .EnforceableRepositories }}<option value="{{ .ID }}">{{ .FullName }}</option>{{ end }}
            </select>
          </label>
          <label>Branch
            <select name="branch" required data-freeze-branch>
            {{ range .BranchOptions }}<option value="{{ .Name }}" data-repository="{{ .RepositoryID }}">{{ .Name }}</option>{{ end }}
            </select>
          </label>
          <label class="tg-field-wide">Reason <input name="reason" placeholder="Release cut 2026-07 — QA verification in progress" required></label>
          <label>Planned unfreeze <input type="datetime-local" name="planned_ends_at" aria-describedby="immediate-planned-unfreeze-help"></label>
          <small id="immediate-planned-unfreeze-help" class="tg-muted">Optional. Uses your browser's local timezone and is stored as UTC.</small>
          <div class="tg-freeze-form-footer tg-field-wide">
            <span class="tg-muted"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>Every freeze is written to the audit log.</span>
            <div class="tg-freeze-form-actions">
              <button type="reset" class="tg-btn tg-btn-secondary tg-btn-sm">Reset</button>
              <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-freeze-branch"></use></svg>Freeze Branch</button>
            </div>
          </div>
        </form>
        {{ else }}
        <div class="tg-empty-row">
          <strong>No repository has active enforcement</strong>
          <span>Repository enforcement is not active. Complete setup and activate enforcement before creating a freeze.</span>
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories">Repository setup</a>
        </div>
        {{ end }}
      </section>

      <aside class="tg-panel tg-impact-card">
        <div class="tg-panel-head tg-impact-head">
          <div class="tg-impact-title-row">
            <h2><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-branch-impact"></use></svg>Preview impact</h2>
          <span class="tg-badge status-warning">3 open PRs</span>
          </div>
          <p class="tg-panel-subtitle">Live preview of PRs blocked by this freeze. Updates on repo/branch change; real lookup is wired later.</p>
        </div>
        <div class="tg-impact-context"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-git-branch"></use></svg><code data-preview-repository>Selected repository</code><span class="tg-arrow">→</span><code class="tg-branch" data-preview-branch>main</code></div>
        <div class="tg-pr-preview-list">
          <div class="tg-pr-preview-row"><a href="#">#248</a><div><strong>Fix checkout tax rounding</strong><small>Ivo · a3f7c2d</small></div></div>
          <div class="tg-pr-preview-row"><a href="#">#245</a><div><strong>Add coupon validation endpoint</strong><small>Priya · 7be9f1d</small></div></div>
          <div class="tg-pr-preview-row"><a href="#">#241</a><div><strong>Update shipping rate calculator</strong><small>Lena · c02de84</small></div></div>
        </div>
        <p class="tg-impact-warning"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg>These PRs will get a failing <code>` + domain.RequiredStatusContext + `</code> check until the freeze is lifted.</p>
      </aside>
    </section>

    <section class="tg-panel tg-active-freezes-panel">
      <div class="tg-panel-head"><h2>Active Freezes</h2><span class="tg-badge">{{ len .Freezes }} active</span></div>
      {{ if .Freezes }}
      <div class="tg-table-wrap">
        <table class="tg-data-table tg-freezes-table">
          <thead><tr><th>Repository / branch</th><th>Reason</th><th>Expiry</th><th>PRs</th><th>Status</th><th></th></tr></thead>
          <tbody>
          {{ range .Freezes }}
            <tr>
              <td><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-freeze-branch"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch">{{ .Freeze.Branch }}</code></span></td>
              <td>{{ .Freeze.Reason }}</td>
              <td>{{ if .HasPlannedEndAt }}Planned unfreeze: {{ .PlannedEndsAt }}{{ else }}<span class="tg-muted">No planned unfreeze</span>{{ end }}</td>
              <td><span class="tg-muted">preview</span></td>
              <td><span class="status status-frozen">{{ .Freeze.Status }}</span></td>
              <td class="tg-table-actions">
                {{ if $.CurrentUser.CanFreeze }}
                <form method="post" action="/freezes/end" data-confirm-submit data-confirm-title="Lift freeze?" data-confirm-message="Future status recomputation can pass if no other freeze applies. This action is auditable and may publish updated statuses for known open PRs." data-confirm-action="Lift freeze">
                  <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                  <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Lift</button>
                </form>
                <form method="post" action="/freezes/cancel" data-confirm-submit data-confirm-title="Cancel freeze?" data-confirm-message="This removes the local active freeze without completing it or recording it as ended. Thawguard will recompute statuses for known open PRs after the freeze changes." data-confirm-action="Cancel freeze">
                  <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-close"></use></svg>Cancel</button>
                </form>
                {{ else }}
                <span class="tg-muted">Read only</span>
                {{ end }}
              </td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row">
          <strong>No active freezes yet</strong>
          <span>Freeze a repository branch to see it listed here.</span>
        </div>
      {{ end }}
    </section>
  </main>
  <script>
    (() => {` + branchFilterScript + `
      const form = document.querySelector('[data-freeze-form]');
      if (!form) return;
      const repo = form.querySelector('[data-freeze-repository]');
      const branch = form.querySelector('[data-freeze-branch]');
      const timezoneOffset = form.querySelector('[data-timezone-offset-minutes]');
      if (timezoneOffset) timezoneOffset.value = String(new Date().getTimezoneOffset());
      const repoOut = document.querySelector('[data-preview-repository]');
      const branchOut = document.querySelector('[data-preview-branch]');
      const update = () => {
        if (repoOut && repo) repoOut.textContent = repo.options[repo.selectedIndex]?.textContent?.trim() || 'Selected repository';
        if (branchOut && branch) branchOut.textContent = branch.value.trim() || 'branch';
      };
      repo.addEventListener('change', () => { filterBranchOptions(repo, branch); update(); });
      branch.addEventListener('change', update);
      filterBranchOptions(repo, branch);
      update();
    })();
  </script>
` + pageFoot

// branchFilterScript keeps the managed-branch select scoped to the selected
// repository. Server-side (repository_id, branch) validation stays
// authoritative when JavaScript is unavailable.
const branchFilterScript = `
      const filterBranchOptions = (repo, branch) => {
        if (!repo || !branch) return;
        let first = null;
        for (const option of branch.options) {
          const match = option.dataset.repository === repo.value;
          option.hidden = !match;
          option.disabled = !match;
          if (match && first === null) first = option;
        }
        const selected = branch.options[branch.selectedIndex];
        if ((!selected || selected.disabled) && first !== null) branch.value = first.value;
      };`

const scheduledFreezesTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-freezes-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Scheduled Freezes</h1>
        <p class="tg-subtitle">Create one-time freeze windows that activate later and optionally lift themselves at a planned unfreeze time.</p>
      </div>
      <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-schedule"></use></svg>One-time windows only</span>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    <section class="tg-freeze-workbench" aria-label="Create scheduled freeze">
      <section class="tg-panel tg-freeze-form-panel">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div>
            <h2>Create scheduled freeze</h2>
            <p class="tg-panel-subtitle">Times are interpreted as UTC for the local alpha. Recurring schedules are intentionally out of scope for v1.</p>
          </div>
        </div>
        {{ if not .CurrentUser.CanFreeze }}
        <div class="tg-empty-row">
          <strong>Read-only schedule access</strong>
          <span>Your role can view scheduled freezes. Explicit freezer role is required to create or cancel schedules.</span>
        </div>
        {{ else if .EnforceableRepositories }}
        <form method="post" action="/scheduled-freezes" class="tg-setup-form tg-freeze-form" data-scheduled-freeze-form>
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <input type="hidden" name="timezone_offset_minutes" value="0" data-timezone-offset-minutes>
          <label>Repository
            <select name="repository_id" required data-scheduled-repository>
            {{ range .EnforceableRepositories }}<option value="{{ .ID }}">{{ .FullName }}</option>{{ end }}
            </select>
          </label>
          <label>Branch
            <select name="branch" required data-scheduled-branch>
            {{ range .BranchOptions }}<option value="{{ .Name }}" data-repository="{{ .RepositoryID }}">{{ .Name }}</option>{{ end }}
            </select>
          </label>
          <label>Starts at <input type="datetime-local" name="starts_at" required></label>
          <label>Planned unfreeze <input type="datetime-local" name="planned_ends_at" aria-describedby="planned-unfreeze-help"></label>
          <small id="planned-unfreeze-help" class="tg-muted tg-field-wide">Optional. Times use your browser's local timezone and are stored as UTC.</small>
          <label class="tg-field-wide">Reason <input name="reason" placeholder="Weekend release freeze" required></label>
          <div class="tg-freeze-form-footer tg-field-wide">
            <span class="tg-muted"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>Creation, activation, planned unfreeze, and cancellation are audit events.</span>
            <div class="tg-freeze-form-actions">
              <button type="reset" class="tg-btn tg-btn-secondary tg-btn-sm">Reset</button>
              <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-schedule"></use></svg>Schedule Freeze</button>
            </div>
          </div>
        </form>
        {{ else }}
        <div class="tg-empty-row">
          <strong>No repository has active enforcement</strong>
          <span>Repository enforcement is not active. Complete setup and activate enforcement before scheduling a freeze.</span>
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories">Repository setup</a>
        </div>
        {{ end }}
      </section>

      <aside class="tg-panel tg-impact-card">
        <div class="tg-panel-head tg-impact-head"><h2><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-schedule"></use></svg>V1 scheduling rules</h2></div>
        <div class="tg-pr-preview-list">
          <div class="tg-pr-preview-row"><span class="tg-badge tg-badge-info">1</span><div><strong>One-time windows only</strong><small>No recurring schedules or branch glob rules in this slice.</small></div></div>
          <div class="tg-pr-preview-row"><span class="tg-badge tg-badge-info">2</span><div><strong>Exact branch names</strong><small>A scheduled window targets one repository branch.</small></div></div>
          <div class="tg-pr-preview-row"><span class="tg-badge tg-badge-info">3</span><div><strong>Automatic activation</strong><small>The local runner activates due windows and reuses the freeze status recomputation path.</small></div></div>
        </div>
      </aside>
    </section>

    <section class="tg-panel tg-data-panel">
      <div class="tg-panel-head"><h2>Scheduled windows</h2><span class="tg-badge tg-badge-scheduled">{{ len .ScheduledFreezes }} shown</span></div>
      {{ if .ScheduledFreezes }}
      <div class="tg-table-wrap tg-responsive-table">
        <table class="tg-data-table tg-freezes-table">
          <thead><tr><th>Repository / branch</th><th>Starts</th><th>Planned unfreeze</th><th>Status</th><th>Reason</th><th>Ended/cancelled</th><th></th></tr></thead>
          <tbody>
          {{ range .ScheduledFreezes }}
            <tr>
              <td data-label="Repository / branch"><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-schedule"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Freeze.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch tg-branch-scheduled">{{ .Freeze.Branch }}</code></span></td>
              <td data-label="Starts">{{ .StartsAt }}</td>
              <td data-label="Planned unfreeze">{{ .PlannedEndsAt }}</td>
              <td data-label="Status"><span class="status status-{{ .StateClass }}">{{ .StatusLabel }}</span></td>
              <td data-label="Reason">{{ .Freeze.Reason }}</td>
              <td data-label="Ended/cancelled">{{ .EndedAt }}</td>
              <td data-label="Actions" class="tg-table-actions">
                {{ if and .CanCancel $.CurrentUser.CanFreeze }}
                <form method="post" action="/scheduled-freezes/cancel" data-confirm-submit data-confirm-title="Cancel scheduled freeze?" data-confirm-message="This cancels a future scheduled freeze before it activates. The action is auditable and no live statuses are changed." data-confirm-action="Cancel schedule">
                  <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                  <input type="hidden" name="freeze_id" value="{{ .Freeze.ID }}">
                  <button type="submit" class="tg-btn tg-btn-secondary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-close"></use></svg>Cancel</button>
                </form>
                {{ else }}
                  <span class="tg-muted">—</span>
                {{ end }}
              </td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row"><strong>No scheduled freezes yet</strong><span>Create a one-time window to have Thawguard freeze a branch later.</span></div>
      {{ end }}
    </section>
  </main>
  <script>
    (() => {` + branchFilterScript + `
      const field = document.querySelector('[data-timezone-offset-minutes]');
      if (field) field.value = String(new Date().getTimezoneOffset());
      const repo = document.querySelector('[data-scheduled-repository]');
      const branch = document.querySelector('[data-scheduled-branch]');
      if (repo) repo.addEventListener('change', () => filterBranchOptions(repo, branch));
      filterBranchOptions(repo, branch);
    })();
  </script>` + pageFoot

const decisionsTemplate = pageHead + `
  <main class="tg-main tg-setup-page tg-thaws-page">
    <header class="tg-header">
      <div>
        <h1 class="tg-title">Thaw Requests</h1>
        <p class="tg-subtitle">Review exceptions for PRs that need to land during an active branch freeze. Every decision should be auditable — this is cooperative workflow for trusted teams, not a hard security gate.</p>
      </div>
      <span class="tg-badge tg-badge-info"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-icy-shield"></use></svg>Auditable exceptions — not a hard security gate</span>
    </header>

    {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}

    {{ with .SharedHeadConfirmation }}
    <section class="tg-panel tg-shared-head-panel" aria-labelledby="tg-shared-head-heading">
      <div class="tg-panel-head tg-panel-head-stacked">
        <div class="tg-thaw-panel-title">
          <span class="tg-thaw-panel-icon tg-shared-head-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span>
          <div>
            <h2 id="tg-shared-head-heading">These pull requests share one commit SHA</h2>
            <p class="tg-panel-subtitle">Forgejo applies commit statuses to the shared SHA, so approving this thaw will affect every pull request listed below.</p>
          </div>
        </div>
      </div>
      <p class="tg-warning-callout tg-shared-head-callout"><span aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-warning"></use></svg></span><span>Nothing has been approved yet. Thawguard paused this request before recording any exception or publishing any status for shared head <code>{{ .ShortHeadSHA }}</code>.</span></p>
      {{ $selected := .PullRequestIndex }}
      <div class="tg-table-wrap">
        <table class="tg-data-table tg-shared-head-table">
          <thead><tr><th>Pull request</th><th>Title</th><th>Target branch</th><th>Head SHA</th></tr></thead>
          <tbody>
          {{ range .AffectedPullRequests }}
            <tr>
              <td class="tg-shared-head-index">#{{ .Index }}{{ if eq .Index $selected }} <span class="tg-badge tg-badge-info">your selection</span>{{ end }}</td>
              <td class="tg-shared-head-title">{{ .Title }}</td>
              <td><code class="tg-branch">{{ .TargetBranch }}</code></td>
              <td><code>{{ .ShortHeadSHA }}</code></td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ if $.CurrentUser.CanThaw }}
      <form method="post" action="/decisions" class="tg-shared-head-confirm-form">
        <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
        <input type="hidden" name="repository_id" value="{{ .RepositoryID }}">
        <input type="hidden" name="pull_request_index" value="{{ .PullRequestIndex }}">
        <input type="hidden" name="target_branch" value="{{ .TargetBranch }}">
        <input type="hidden" name="reason" value="{{ .Reason }}">
        <input type="hidden" name="confirm_shared_head" value="true">
        <input type="hidden" name="confirmed_head_sha" value="{{ .HeadSHA }}">
        <input type="hidden" name="confirmed_affected_signature" value="{{ .AffectedSignature }}">
        <p class="tg-muted">Approving publishes one SHA-scoped <code>{{ $.RequiredContext }}</code> status that applies to all {{ .AffectedCount }} pull requests above. Thawguard refreshes the forge state first; if the head SHA or affected set changed, it asks for confirmation again.</p>
        <div class="tg-form-actions">
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/decisions">Cancel</a>
          <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Approve thaw for all {{ .AffectedCount }} PRs</button>
        </div>
      </form>
      {{ else }}
      <div class="tg-empty-row">
        <strong>Read-only thaw access</strong>
        <span>Explicit thaw approver role is required to confirm a shared-head thaw.</span>
      </div>
      {{ end }}
    </section>
    {{ end }}

    <section class="tg-thaw-workbench" aria-label="Approve a thaw exception">
      <section class="tg-panel tg-thaw-form-panel">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div class="tg-thaw-panel-title">
            <span class="tg-thaw-panel-icon" aria-hidden="true"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg></span>
            <div>
              <h2>Approve a thaw exception</h2>
              <p class="tg-panel-subtitle">Approve one open PR for its current forge head SHA. Thawguard records the exception, recomputes <code>{{ .RequiredContext }}</code>, and publishes only that status context.</p>
            </div>
          </div>
        </div>
        {{ if not .CurrentUser.CanThaw }}
        <div class="tg-empty-row">
          <strong>Read-only thaw access</strong>
          <span>Your role can view thaw decisions. Explicit thaw approver role is required to approve exceptions.</span>
        </div>
        {{ else if .EnforceableRepositories }}
        <form method="post" action="/decisions" class="tg-setup-form tg-thaw-form" data-thaw-form>
          <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
          <label>Repository
            <select name="repository_id" required data-thaw-repository>
            {{ range .EnforceableRepositories }}<option value="{{ .ID }}">{{ .FullName }}</option>{{ end }}
            </select>
          </label>
          <label>Pull request <input name="pull_request_index" inputmode="numeric" placeholder="251" required data-thaw-pr></label>
          <label>Target branch <input name="target_branch" placeholder="main" value="main" required data-thaw-branch></label>
          <label class="tg-field-wide">Reason for exception <input name="reason" placeholder="Production fix needed during release freeze" aria-describedby="thaw-alpha-note" required></label>
          <label>Exception expires
            <select name="expires_after" disabled>
              <option>24 hours after approval</option>
            </select>
          </label>
          <label>Notify channel (optional) <input name="notify_channel" placeholder="#releases" disabled></label>
          <div class="tg-form-footer tg-thaw-form-footer tg-field-wide">
            <span id="thaw-alpha-note" class="tg-muted"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-audit"></use></svg>The current head SHA is fetched from the forge at approval time, so new commits invalidate this thaw.</span>
            <div class="tg-form-actions">
              <button type="reset" class="tg-btn tg-btn-secondary tg-btn-sm">Reset</button>
              <button type="submit" class="tg-btn tg-btn-primary tg-btn-sm"><svg class="tg-icon"><use href="#tg-i-thaw-drop"></use></svg>Approve thaw</button>
            </div>
          </div>
        </form>
        {{ else }}
        <div class="tg-empty-row">
          <strong>No repository has active enforcement</strong>
          <span>Repository enforcement is not active. Complete setup and activate enforcement before approving a thaw exception.</span>
          <a class="tg-btn tg-btn-secondary tg-btn-sm" href="/repositories">Repository setup</a>
        </div>
        {{ end }}
      </section>

      <aside class="tg-panel tg-eligibility-card">
        <div class="tg-panel-head tg-panel-head-stacked">
          <div class="tg-impact-title-row">
            <h2><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-health-check"></use></svg>Eligibility preview</h2>
            <span class="tg-badge tg-badge-info">head-SHA scoped</span>
          </div>
          <p class="tg-panel-subtitle">How the approval is constrained before the forge status is published.</p>
        </div>
        <div class="tg-thaw-freeze-card">
          <div class="tg-thaw-freeze-main"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-freeze-branch"></use></svg><code data-thaw-preview-repository>Selected repository</code><span class="tg-arrow">→</span><code class="tg-branch" data-thaw-preview-branch>main</code><span class="status status-pending">Preview</span></div>
          <p>After approval, the latest result below shows the actual <code>{{ .RequiredContext }}</code> decision posted for this PR head.</p>
        </div>
        <ul class="tg-eligibility-list">
          <li><span class="tg-event-ok"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-check"></use></svg></span><span>Repository, PR number, target branch, and reason are captured for the approval.</span></li>
          <li><span class="tg-event-ok"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-check"></use></svg></span><span>The current PR head SHA is fetched from the configured Forgejo/Codeberg repository.</span></li>
          <li><span class="tg-event-ok"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-check"></use></svg></span><span>A unique head SHA scopes the approval to this one PR.</span></li>
          <li><span class="tg-event-fail"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-warning"></use></svg></span><span>If other open PRs share the head SHA, Thawguard pauses and requires explicit confirmation for every affected PR.</span></li>
        </ul>
        <div class="tg-review-actions">
          <span class="tg-caps">Reviewer decision</span>
          <div>
            <button type="button" class="tg-btn tg-btn-secondary tg-btn-sm" disabled>Deny</button>
            <button type="button" class="tg-btn tg-btn-primary tg-btn-sm" disabled><svg class="tg-icon"><use href="#tg-i-check"></use></svg>Approved by form</button>
          </div>
        </div>
      </aside>
    </section>

    <section class="tg-panel tg-open-thaws-panel">
      <div class="tg-panel-head"><h2>Thaw approval results</h2><span class="tg-badge tg-badge-info">{{ len .Results }} status results</span></div>
      {{ if .Results }}
      <div class="tg-table-wrap">
        <table class="tg-data-table tg-thaws-table">
          <thead><tr><th>Request candidate</th><th>Policy result</th><th>Status context</th><th>Expiry</th><th>Status</th><th>Workflow</th></tr></thead>
          <tbody>
          {{ range .Results }}
            <tr>
              <td><div class="tg-thaw-request-main"><a href="#">#{{ .Result.PullRequestIndex }}</a><span><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-git-branch"></use></svg><code>{{ if .Repository.ID }}{{ .Repository.FullName }}{{ else }}Repository #{{ .Result.RepositoryID }}{{ end }}</code><span class="tg-arrow">→</span><code class="tg-branch">{{ .Result.TargetBranch }}</code></span><small><code>{{ .Result.HeadSHA }}</code> · {{ .CreatedAt }}</small></div></td>
              <td>{{ .Result.Description }}</td>
              <td><span class="tg-table-repo"><svg class="tg-icon" aria-hidden="true"><use href="#tg-i-freeze-branch"></use></svg><code>{{ .Result.Context }}</code></span><small class="tg-muted">{{ if eq .Result.State "failure" }}freeze · failing{{ else }}freeze · passing{{ end }}</small></td>
              <td><span class="tg-muted">Head SHA scoped</span></td>
              <td><span class="status status-{{ .Result.State }}">{{ if eq .Result.State "success" }}Eligible{{ else if eq .Result.State "failure" }}Blocked{{ else }}{{ .Result.State }}{{ end }}</span></td>
              <td class="tg-table-actions"><button type="button" class="tg-btn tg-btn-secondary tg-btn-sm" disabled>Recorded</button></td>
            </tr>
          {{ end }}
          </tbody>
        </table>
      </div>
      {{ else }}
        <div class="tg-empty-row">
          <strong>No thaw approvals yet</strong>
          <span>Approve a PR above to record a head-SHA-scoped thaw and publish the resulting status.</span>
        </div>
      {{ end }}
    </section>
  </main>
  <script>
    (() => {
      const form = document.querySelector('[data-thaw-form]');
      if (!form) return;
      const repo = form.querySelector('[data-thaw-repository]');
      const branch = form.querySelector('[data-thaw-branch]');
      const repoOut = document.querySelector('[data-thaw-preview-repository]');
      const branchOut = document.querySelector('[data-thaw-preview-branch]');
      const update = () => {
        if (repoOut && repo) repoOut.textContent = repo.options[repo.selectedIndex]?.textContent?.trim() || 'Selected repository';
        if (branchOut && branch) branchOut.textContent = branch.value.trim() || 'branch';
      };
      repo.addEventListener('change', update);
      branch.addEventListener('input', update);
      form.addEventListener('reset', () => window.setTimeout(update, 0));
      update();
    })();
  </script>
` + pageFoot
