package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

const invalidInvitationMessage = "This invitation link is invalid or no longer available. It may have expired, been cancelled, already been used, or been replaced. Try signing in with your invited email address, or ask an Admin to check your account or active invitation."

type authInvitationAcceptData struct {
	AppName         string
	PageTitle       string
	Theme           string
	CSRFField       string
	CSRFToken       string
	FormError       string
	InvitationToken string
	Bootstrap       bool
}

type authInvitationMessageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	Heading     string
	Message     string
	ActionHref  string
	ActionLabel string
}

// usersInvitationResultView carries a freshly minted invitation link to
// exactly one buffered Users & Access response. It is built from the value the
// service already returned, never from a read, and it is never stored: the
// bearer lives in this struct and in the escaped input value it renders into,
// and nowhere else.
type usersInvitationResultView struct {
	Heading        string
	DisplayName    string
	Email          string
	InvitationLink string
	ExpiresAt      string
	// Replaced marks a replacement rather than a first issue, which adds the
	// statement that the previous link is already dead.
	Replaced bool
}

// usersInvitationView is the Active invitations row model. It never carries
// bearer material: the read model behind it only exposes metadata.
type usersInvitationView struct {
	DisplayName    string
	Email          string
	LifecycleLabel string
	LifecycleTone  string
	// LifecycleDetail explains a dead link and names the remedy: replace it.
	LifecycleDetail  string
	ExpiresAt        string
	IsAdmin          bool
	AccessTitle      string
	ScopedRoleLabels []string
	// DriftWarning is set when staged repository access no longer matches what
	// the Admin staged. Drift is reported separately from lifecycle because a
	// pending, unexpired link can still be drifted.
	DriftWarning string
	CancelPath   string
	ReplacePath  string
	// The confirmation dialog for each action is rendered once per invitation,
	// outside the duplicated desktop and mobile rows, so both breakpoints
	// address the same element. ConfirmHref is the no-JavaScript path to the
	// same dialog.
	CancelDialogID     string
	CancelConfirmHref  string
	CancelOpen         bool
	ReplaceDialogID    string
	ReplaceConfirmHref string
	ReplaceOpen        bool
}

type usersInviteRepositoryView struct {
	Label string
	Roles []usersInviteRoleView
}

type usersInviteRoleView struct {
	ID      string
	Value   string
	Label   string
	Checked bool
}

func (s *Server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	// The cap is installed before any parsing; requireAdminForm parses the
	// capped body.
	r.Body = http.MaxBytesReader(w, r.Body, invitationCreateMaxBodyBytes)
	if !s.validInvitationOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		s.renderInvitationMessage(
			w,
			http.StatusForbidden,
			"Invitation not created",
			"This request could not be verified. Return to Users & Access and try again.",
			"/users",
			"Back to Users & Access",
		)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	form, parseErr := parseInvitationCreateForm(r.PostForm)
	preserved := usersPageState{
		InviteOpen:           true,
		InviteEmail:          form.Email,
		InviteDisplayName:    form.DisplayName,
		InviteAdmin:          form.Admin,
		InviteSelectedGrants: form.SelectedGrants,
	}
	if parseErr != "" {
		preserved.FormError = parseErr
		s.renderUsersPage(w, r, http.StatusBadRequest, usersQuery{}, preserved, session)
		return
	}
	// The page behind the result dialog is loaded before the mutation, so the
	// success path performs no read at all once a bearer exists. A snapshot
	// failure aborts before anything is created.
	page, ok := s.loadUsersPageData(w, r, usersQuery{}, usersPageState{}, session)
	if !ok {
		return
	}
	credential, err := s.cfg.AuthService.CreateInvitation(r.Context(), auth.CreateInvitationParams{
		ActorUserID:      *session.UserID,
		Email:            form.Email,
		DisplayName:      form.DisplayName,
		IsAdmin:          form.Admin,
		RepositoryGrants: form.Grants,
	})
	switch {
	case err == nil:
		page.InvitationResult = &usersInvitationResultView{
			Heading:        "Invitation created",
			DisplayName:    form.DisplayName,
			Email:          form.Email,
			InvitationLink: s.invitationAcceptLink(credential.Token),
			ExpiresAt:      credential.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
		}
		if !s.renderPageBuffered(w, http.StatusOK, "layouts/users", page) {
			s.renderInvitationUndisplayedLink(w, "Invitation created")
		}
	case auth.IsValidationError(err):
		preserved.FormError = err.Error()
		s.renderUsersPage(w, r, http.StatusBadRequest, usersQuery{}, preserved, session)
	default:
		// The outcome is unknown: the invitation may or may not exist, and its
		// link was never displayed. Do not claim a rollback happened.
		s.renderInvitationMessage(
			w,
			http.StatusInternalServerError,
			"Invitation result unconfirmed",
			"Thawguard could not confirm whether the invitation was created, and no link is available. Inspect Active invitations before retrying. If the invitation appears there, replace its link, because the original was never displayed.",
			"/users",
			"Back to Users & Access",
		)
	}
}

// handleReplaceInvitationLink retires one invitation and issues a new one in
// its place. The old invitation ID in the path is the replay fence: once the
// service has retired it, a refreshed or replayed POST targets an ID that no
// longer accepts replacement, so it cannot rotate the link that was just
// shown. Nothing about the new invitation is client-supplied.
func (s *Server) handleReplaceInvitationLink(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	// The cap is installed before any parsing; requireAdminForm parses the
	// capped body.
	r.Body = http.MaxBytesReader(w, r.Body, invitationReplaceMaxBodyBytes)
	invitationID := r.PathValue("id")
	if !auth.ValidInvitationID(invitationID) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if !s.validInvitationOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		s.renderInvitationMessage(
			w,
			http.StatusForbidden,
			"Invitation link not replaced",
			"This request could not be verified. Return to Users & Access and try again.",
			"/users",
			"Back to Users & Access",
		)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !onlyInvitationReplaceFields(r.PostForm) {
		s.renderInvitationMessage(
			w,
			http.StatusBadRequest,
			"Invitation link not replaced",
			"This request could not be processed. Return to Users & Access and replace the invitation link again.",
			"/users",
			"Back to Users & Access",
		)
		return
	}
	page, ok := s.loadUsersPageData(w, r, usersQuery{}, usersPageState{}, session)
	if !ok {
		return
	}
	replacement, err := s.cfg.AuthService.ReplaceInvitationLink(r.Context(), auth.ReplaceInvitationLinkParams{
		ActorUserID:  *session.UserID,
		InvitationID: invitationID,
	})
	switch {
	case err == nil:
		page.InvitationResult = &usersInvitationResultView{
			Heading:        "Invitation link replaced",
			DisplayName:    replacement.DisplayName,
			Email:          replacement.Email,
			InvitationLink: s.invitationAcceptLink(replacement.Token),
			ExpiresAt:      replacement.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
			Replaced:       true,
		}
		if !s.renderPageBuffered(w, http.StatusOK, "layouts/users", page) {
			s.renderInvitationUndisplayedLink(w, "Invitation link replaced")
		}
	case auth.IsValidationError(err):
		// Expected staleness: the invitation was already accepted, cancelled,
		// or replaced. The refreshed Active invitations list shows the current
		// state, and no link was created.
		s.renderUsersPage(w, r, http.StatusBadRequest, usersQuery{}, usersPageState{FormError: err.Error()}, session)
	default:
		// The outcome is unknown and no link is available. Do not claim a
		// rollback happened, and do not let the Admin keep trusting a link
		// that may already be retired.
		s.renderInvitationMessage(
			w,
			http.StatusInternalServerError,
			"Replacement result unconfirmed",
			"Thawguard could not confirm whether this invitation link was replaced, and no link is available. Stop using the previous link. Reload Users & Access and replace the active invitation again.",
			"/users",
			"Back to Users & Access",
		)
	}
}

// renderInvitationUndisplayedLink answers a committed create or replacement
// whose page could not be rendered. The invitation exists and its link is
// already unrecoverable, so the only truthful remedy is another replacement.
func (s *Server) renderInvitationUndisplayedLink(w http.ResponseWriter, heading string) {
	s.renderInvitationMessage(
		w,
		http.StatusInternalServerError,
		heading+" but not displayed",
		"The invitation is active, but Thawguard could not display its link and cannot show it again. Reload Users & Access and replace the link for that invitation.",
		"/users",
		"Back to Users & Access",
	)
}

// invitationAcceptLink puts the bearer in the URL fragment so it is never sent
// to the server as a path or query value.
func (s *Server) invitationAcceptLink(token string) string {
	return s.cfg.PublicURL + "/invitations/accept#token=" + token
}

// onlyInvitationReplaceFields enforces that replacement carries the CSRF token
// and nothing else. Identity, the Admin flag, staged access, expiry, and the
// bearer are all derived server-side, so any additional field is a sign the
// request did not come from the confirmation dialog.
func onlyInvitationReplaceFields(form url.Values) bool {
	values, ok := form[csrfFormField]
	return ok && len(values) == 1 && len(form) == 1
}

func (s *Server) handleCancelInvitation(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	invitationID := r.PathValue("id")
	if !auth.ValidInvitationID(invitationID) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	err := s.cfg.AuthService.CancelInvitation(r.Context(), auth.CancelInvitationParams{
		ActorUserID:  *session.UserID,
		InvitationID: invitationID,
	})
	switch {
	case err == nil:
		http.Redirect(w, r, "/users?notice=invitation-cancelled", http.StatusSeeOther)
	case auth.IsValidationError(err):
		// Expected staleness: the invitation was already accepted, cancelled,
		// or removed. The refreshed Active invitations list shows the current
		// state, so no retry advice is added.
		s.renderUsersPage(w, r, http.StatusBadRequest, usersQuery{}, usersPageState{FormError: err.Error()}, session)
	default:
		s.renderInvitationMessage(
			w,
			http.StatusInternalServerError,
			"Cancellation result unconfirmed",
			"Thawguard could not confirm whether this invitation was cancelled. Inspect Active invitations before retrying.",
			"/users",
			"Back to Users & Access",
		)
	}
}

func (s *Server) handleInvitationAccept(w http.ResponseWriter, r *http.Request) {
	csrfToken, err := s.newInvitationCSRFToken()
	if err != nil {
		s.renderInvitationAcceptInternalError(w)
		return
	}
	s.renderPageStatus(w, http.StatusOK, "layouts/invitation-accept", authInvitationAcceptData{
		AppName:   s.cfg.AppName,
		PageTitle: "Accept invitation",
		CSRFField: csrfFormField,
		CSRFToken: csrfToken,
		Bootstrap: true,
	})
}

func (s *Server) handleInvitationAcceptPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, invitationAcceptMaxBodyBytes)
	if !s.validInvitationOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		s.renderInvitationAcceptForbidden(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.renderInvitationMessage(
				w,
				http.StatusRequestEntityTooLarge,
				"Invitation request not processed",
				"This request is too large. Reopen the original invitation link and try again.",
				"",
				"",
			)
			return
		}
		s.renderInvitationAcceptBadRequest(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !onlyInvitationAcceptFields(r.PostForm) {
		s.renderInvitationAcceptBadRequest(w)
		return
	}
	if !s.validInvitationCSRFToken(r) {
		s.logRequestRejected(r, reasonCSRFInvalid)
		s.renderInvitationAcceptForbidden(w)
		return
	}
	if s.cfg.AuthService == nil {
		s.renderInvitationAcceptInternalError(w)
		return
	}

	invitationToken := r.PostForm.Get("invitation_token")
	_, err := s.cfg.AuthService.AcceptInvitation(r.Context(), invitationToken, r.PostForm.Get("new_password"))
	switch {
	case err == nil:
		// No session is created: the invitee signs in through the ordinary
		// login flow with the password they just chose.
		s.renderInvitationMessage(
			w,
			http.StatusOK,
			"Account created",
			"Your account is ready. Sign in with your invited email address and the password you just chose.",
			"/login",
			"Sign in",
		)
	case auth.IsValidationError(err):
		csrfToken, csrfErr := s.newInvitationCSRFToken()
		if csrfErr != nil {
			s.renderInvitationAcceptInternalError(w)
			return
		}
		// The bearer is retained exactly once, in the escaped hidden token
		// field. The rejected password is discarded.
		s.renderPageStatus(w, http.StatusBadRequest, "layouts/invitation-accept", authInvitationAcceptData{
			AppName:         s.cfg.AppName,
			PageTitle:       "Choose a password",
			CSRFField:       csrfFormField,
			CSRFToken:       csrfToken,
			FormError:       err.Error(),
			InvitationToken: invitationToken,
		})
	case auth.IsInvalidInvitation(err):
		s.renderInvitationMessage(w, http.StatusBadRequest, "Invitation unavailable", invalidInvitationMessage, "", "")
	default:
		// The outcome is unknown: the account may exist. Never advise blind
		// resubmission of the bearer.
		s.renderInvitationMessage(
			w,
			http.StatusInternalServerError,
			"Acceptance result unconfirmed",
			"Thawguard could not confirm whether your account was created. Try signing in with your invited email address and the password you chose. If sign-in fails, ask an Admin for a new invitation link.",
			"/login",
			"Go to sign-in",
		)
	}
}

// invitationCreateForm carries the parsed create-invitation submission plus
// the safe values a validation failure may re-render: identity, the Admin
// flag, and every parseable grant selection. It never carries bearer material.
type invitationCreateForm struct {
	Email          string
	DisplayName    string
	Admin          bool
	Grants         []auth.InvitationRepositoryGrant
	SelectedGrants map[string]bool
}

// parseInvitationCreateForm enforces field cardinality and the canonical
// "<repository id>:<role>" grant encoding. The auth service stays
// authoritative for repository existence, email normalization, collisions,
// and grant dedup.
func parseInvitationCreateForm(form url.Values) (invitationCreateForm, string) {
	errorMessage := ""
	fail := func(message string) {
		if errorMessage == "" {
			errorMessage = message
		}
	}
	for key, values := range form {
		switch key {
		case csrfFormField, "email", "display_name":
			if len(values) != 1 {
				fail("the " + key + " field was submitted more than once")
			}
		case "admin":
			if len(values) != 1 || values[0] != "1" {
				fail("the admin selection is invalid")
			}
		case "repository_grants":
			// Each value is validated below.
		default:
			fail("the form contains an unsupported field")
		}
	}
	parsed := invitationCreateForm{
		Email:          strings.TrimSpace(form.Get("email")),
		DisplayName:    strings.TrimSpace(form.Get("display_name")),
		Admin:          form.Get("admin") == "1",
		SelectedGrants: make(map[string]bool),
	}
	for _, raw := range form["repository_grants"] {
		grant, ok := parseInvitationGrantValue(raw)
		if !ok {
			fail("a staged repository access selection is invalid")
			continue
		}
		parsed.SelectedGrants[raw] = true
		parsed.Grants = append(parsed.Grants, grant)
	}
	return parsed, errorMessage
}

// parseInvitationGrantValue accepts only the canonical form the invite dialog
// submits: a positive decimal repository ID, a colon, and an exact repository
// role. Non-canonical encodings ("+3", "03", unknown roles) are rejected
// rather than normalized.
func parseInvitationGrantValue(raw string) (auth.InvitationRepositoryGrant, bool) {
	idPart, rolePart, ok := strings.Cut(raw, ":")
	if !ok {
		return auth.InvitationRepositoryGrant{}, false
	}
	repositoryID, err := strconv.ParseInt(idPart, 10, 64)
	if err != nil || repositoryID <= 0 || strconv.FormatInt(repositoryID, 10) != idPart {
		return auth.InvitationRepositoryGrant{}, false
	}
	role := auth.Role(rolePart)
	if !role.ValidForRepository() {
		return auth.InvitationRepositoryGrant{}, false
	}
	return auth.InvitationRepositoryGrant{RepositoryID: repositoryID, Role: role}, true
}

func onlyInvitationAcceptFields(form url.Values) bool {
	for key, values := range form {
		switch key {
		case csrfFormField, "invitation_token", "new_password":
			if len(values) != 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Server) validInvitationOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == s.cfg.PublicURL
}

func usersInvitationViews(invitations []auth.ActiveInvitation, state usersPageState) []usersInvitationView {
	views := make([]usersInvitationView, 0, len(invitations))
	for _, invitation := range invitations {
		confirming := state.ConfirmInvitationID == invitation.ID
		view := usersInvitationView{
			DisplayName:        invitation.DisplayName,
			Email:              invitation.Email,
			IsAdmin:            invitation.IsAdmin,
			CancelPath:         "/users/invitations/" + invitation.ID + "/cancel",
			ReplacePath:        "/users/invitations/" + invitation.ID + "/replace",
			CancelDialogID:     "invitation-cancel-" + invitation.ID,
			CancelConfirmHref:  "/users?confirm=cancel&invitation=" + invitation.ID + "#invitation-cancel-" + invitation.ID,
			CancelOpen:         confirming && state.ConfirmAction == "cancel",
			ReplaceDialogID:    "invitation-replace-" + invitation.ID,
			ReplaceConfirmHref: "/users?confirm=replace&invitation=" + invitation.ID + "#invitation-replace-" + invitation.ID,
			ReplaceOpen:        confirming && state.ConfirmAction == "replace",
		}
		switch invitation.Lifecycle {
		case auth.InvitationLifecyclePending:
			view.LifecycleLabel = "Pending"
			view.LifecycleTone = "info"
		case auth.InvitationLifecycleExpired:
			view.LifecycleLabel = "Expired"
			view.LifecycleTone = "warning"
			view.LifecycleDetail = "The link no longer works. Replace it to issue a new link with a fresh seven-day expiry."
		case auth.InvitationLifecycleNeedsReplacement:
			view.LifecycleLabel = "Needs replacement"
			view.LifecycleTone = "danger"
			view.LifecycleDetail = "The link was invalidated because the authorizing Admin lost Admin access. Replace it to issue a new link authorized by you."
		}
		if invitation.ExpiresAt != nil {
			view.ExpiresAt = invitation.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		if invitation.AccessDrift() {
			view.DriftWarning = "Staged repository access changed after this invitation was created. Replace the link to keep the access that still exists; access for deleted repositories cannot be restored."
		}
		repositoryIDs := make(map[int64]bool)
		stagedRoles := make(map[auth.Role]bool)
		for _, grant := range invitation.RepositoryGrants {
			repositoryIDs[grant.RepositoryID] = true
			stagedRoles[grant.Role] = true
		}
		switch {
		case len(repositoryIDs) == 1:
			view.AccessTitle = "1 repository"
		case len(repositoryIDs) > 1:
			view.AccessTitle = fmt.Sprintf("%d repositories", len(repositoryIDs))
		case !invitation.IsAdmin:
			view.AccessTitle = "No repository access"
		}
		for _, role := range auth.RepositoryRoles() {
			if stagedRoles[role] {
				view.ScopedRoleLabels = append(view.ScopedRoleLabels, role.Label())
			}
		}
		views = append(views, view)
	}
	return views
}

func usersInviteRepositoryViews(repositories []domain.Repository, selected map[string]bool) []usersInviteRepositoryView {
	views := make([]usersInviteRepositoryView, 0, len(repositories))
	for _, repository := range repositories {
		view := usersInviteRepositoryView{Label: repository.FullName()}
		for _, role := range auth.RepositoryRoles() {
			value := fmt.Sprintf("%d:%s", repository.ID, role)
			view.Roles = append(view.Roles, usersInviteRoleView{
				ID:      fmt.Sprintf("invite-grant-%d-%s", repository.ID, role),
				Value:   value,
				Label:   role.Label(),
				Checked: selected[value],
			})
		}
		views = append(views, view)
	}
	return views
}

func (s *Server) renderInvitationAcceptForbidden(w http.ResponseWriter) {
	s.renderInvitationMessage(
		w,
		http.StatusForbidden,
		"Invitation request not verified",
		"This request could not be verified. Reopen the original invitation link and try again.",
		"",
		"",
	)
}

func (s *Server) renderInvitationAcceptBadRequest(w http.ResponseWriter) {
	s.renderInvitationMessage(
		w,
		http.StatusBadRequest,
		"Invitation request not processed",
		"This invitation request could not be processed. Ask an Admin for a new invitation link if the problem continues.",
		"",
		"",
	)
}

func (s *Server) renderInvitationAcceptInternalError(w http.ResponseWriter) {
	s.renderInvitationMessage(
		w,
		http.StatusInternalServerError,
		"Invitation unavailable",
		"Thawguard could not process this invitation right now. Reopen the original invitation link and try again.",
		"",
		"",
	)
}

func (s *Server) renderInvitationMessage(
	w http.ResponseWriter,
	status int,
	heading string,
	message string,
	actionHref string,
	actionLabel string,
) {
	s.renderPageStatus(w, status, "layouts/invitation-message", authInvitationMessageData{
		AppName:     s.cfg.AppName,
		PageTitle:   heading,
		Heading:     heading,
		Message:     message,
		ActionHref:  actionHref,
		ActionLabel: actionLabel,
	})
}
