package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
)

// usersPageState carries which dialog re-opens and the preserved non-secret
// values across a validation re-render. Password values are intentionally
// never part of this state.
type usersPageState struct {
	FormError         string
	CreateOpen        bool
	CreateEmail       string
	CreateDisplayName string
	CreateRoles       auth.RoleSet
	RoleFormUserID    int64
	RoleFormRoles     auth.RoleSet
	ResetFormUserID   int64
}

// defaultUsersPageState seeds the create-user form with the least-privileged
// role preselected.
func defaultUsersPageState() usersPageState {
	return usersPageState{CreateRoles: auth.RoleSet{auth.RoleViewer}}
}

type roleOption struct {
	Value    string
	Label    string
	Hint     string
	Selected bool
}

type usersUserView struct {
	ID                 int64
	DisplayName        string
	Email              string
	Disabled           bool
	MustChangePassword bool
	IsSelf             bool
	IsLastEnabledAdmin bool
	CreatedAt          string
	CreatedAtISO       string
	RoleOptions        []roleOption
	RoleFormError      string
	ResetFormOpen      bool
	ResetFormError     string
}

type usersPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	Users     []usersUserView
	UserCount int

	// FormError is the page-level fallback for a validation failure no
	// rendered dialog claims (e.g. a raced last-admin disable).
	FormError         string
	CreateOpen        bool
	CreateError       string
	CreateEmail       string
	CreateDisplayName string
	CreateRoleOptions []roleOption
}

// usersFragment is the htmx swap payload for #users-live plus an optional
// out-of-band #toasts toast.
type usersFragment struct {
	Data  usersPageData
	Toast *toastView
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
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
	if isHXRequest(r) {
		s.renderUsersFragment(w, r, defaultUsersPageState(), session, nil)
		return
	}
	s.renderUsersPage(w, r, http.StatusOK, defaultUsersPageState(), session)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
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
		s.renderUsersValidationError(w, r, err, usersPageState{
			CreateOpen:        true,
			CreateEmail:       r.PostFormValue("email"),
			CreateDisplayName: r.PostFormValue("display_name"),
			CreateRoles:       auth.RoleSet(roles),
		}, session)
		return
	}
	s.completeUsersMutation(w, r, session, "User created")
}

func (s *Server) handleUpdateUserRoles(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
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
	s.completeUsersMutation(w, r, session, "Roles saved")
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
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
		// The actor just revoked their own sessions; a fragment would render
		// a dead page under a cleared cookie, so htmx gets a full redirect.
		clearSessionCookie(w, r)
		if isHXRequest(r) {
			w.Header().Set("HX-Redirect", "/login")
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.completeUsersMutation(w, r, session, "User disabled")
}

func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
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
	s.completeUsersMutation(w, r, session, "User re-enabled")
}

func (s *Server) handleResetUserPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Vary", "HX-Request")
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
	s.completeUsersMutation(w, r, session, "Temporary password set")
}

// completeUsersMutation finishes a successful POST: htmx requests get the
// refreshed #users-live fragment plus an out-of-band success toast, browsers
// keep the legacy 303 PRG.
func (s *Server) completeUsersMutation(w http.ResponseWriter, r *http.Request, session sessionState, message string) {
	if isHXRequest(r) {
		s.renderUsersFragment(w, r, defaultUsersPageState(), session, &toastView{Message: message, Tone: "success"})
		return
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// renderUsersValidationError re-renders the users page for a typed validation
// error and hides internal error details. Password values are never echoed.
// htmx requests get a 200 fragment with the failed dialog re-opened (the
// client does not swap 4xx responses); browsers keep the legacy 400 full page.
func (s *Server) renderUsersValidationError(w http.ResponseWriter, r *http.Request, err error, state usersPageState, session sessionState) {
	if !auth.IsValidationError(err) {
		internalServerError(w)
		return
	}
	state.FormError = err.Error()
	if isHXRequest(r) {
		s.renderUsersFragment(w, r, state, session, nil)
		return
	}
	s.renderUsersPage(w, r, http.StatusBadRequest, state, session)
}

func (s *Server) renderUsersPage(w http.ResponseWriter, r *http.Request, statusCode int, state usersPageState, session sessionState) {
	data, ok := s.loadUsersPageData(w, r, state, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, statusCode, "layouts/users", data)
}

func (s *Server) renderUsersFragment(w http.ResponseWriter, r *http.Request, state usersPageState, session sessionState, toast *toastView) {
	data, ok := s.loadUsersPageData(w, r, state, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, http.StatusOK, "components/users-live-fragment", usersFragment{Data: data, Toast: toast})
}

func (s *Server) loadUsersPageData(w http.ResponseWriter, r *http.Request, state usersPageState, session sessionState) (usersPageData, bool) {
	users, err := s.cfg.AuthService.ListUsers(r.Context())
	if err != nil {
		internalServerError(w)
		return usersPageData{}, false
	}
	return usersPageDataFor(s.cfg.AppName, users, state, session), true
}

func usersPageDataFor(appName string, users []auth.User, state usersPageState, session sessionState) usersPageData {
	data := usersPageData{
		AppName:           appName,
		PageTitle:         "Users & Roles",
		ActivePage:        "users",
		CurrentUser:       currentUserFromSession(session),
		CSRFToken:         session.CSRFToken,
		CSRFField:         csrfFormField,
		Users:             usersUserViews(users, state, session),
		UserCount:         len(users),
		CreateOpen:        state.CreateOpen,
		CreateEmail:       state.CreateEmail,
		CreateDisplayName: state.CreateDisplayName,
		CreateRoleOptions: roleOptionsFor(state.CreateRoles),
	}
	if state.CreateOpen {
		data.CreateError = state.FormError
	}
	if state.FormError != "" && !usersErrorClaimed(data) {
		data.FormError = state.FormError
	}
	return data
}

// usersErrorClaimed reports whether a rendered dialog or row form already
// displays the validation message, so the page-level fallback stays quiet.
func usersErrorClaimed(data usersPageData) bool {
	if data.CreateError != "" {
		return true
	}
	for _, user := range data.Users {
		if user.RoleFormError != "" || user.ResetFormError != "" {
			return true
		}
	}
	return false
}

func usersUserViews(users []auth.User, state usersPageState, session sessionState) []usersUserView {
	lastAdminID := lastEnabledAdminID(users)
	views := make([]usersUserView, 0, len(users))
	for _, user := range users {
		roleFormRoles := userRoleSet(user)
		if state.RoleFormUserID != 0 && state.RoleFormUserID == user.ID {
			roleFormRoles = state.RoleFormRoles
		}
		isSelf := session.UserID != nil && *session.UserID == user.ID
		view := usersUserView{
			ID:                 user.ID,
			DisplayName:        user.DisplayName,
			Email:              user.Email,
			Disabled:           user.Disabled(),
			MustChangePassword: user.MustChangePassword,
			IsSelf:             isSelf,
			IsLastEnabledAdmin: lastAdminID != 0 && lastAdminID == user.ID,
			CreatedAt:          user.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
			CreatedAtISO:       user.CreatedAt.UTC().Format(time.RFC3339),
			RoleOptions:        roleOptionsFor(roleFormRoles),
			ResetFormOpen:      !isSelf && state.ResetFormUserID != 0 && state.ResetFormUserID == user.ID,
		}
		if state.FormError != "" {
			if state.RoleFormUserID != 0 && state.RoleFormUserID == user.ID {
				view.RoleFormError = state.FormError
			}
			if view.ResetFormOpen {
				view.ResetFormError = state.FormError
			}
		}
		views = append(views, view)
	}
	return views
}

// userRoleSet mirrors the fallback used for the roles label: accounts from
// before multi-role support may carry only the primary Role column.
func userRoleSet(user auth.User) auth.RoleSet {
	if len(user.Roles) > 0 {
		return user.Roles
	}
	if user.Role.Valid() {
		return auth.RoleSet{user.Role}
	}
	return nil
}

// lastEnabledAdminID returns the ID of the only enabled admin in the listed
// set, or 0 when zero or several enabled admins exist. The view pre-disables
// the guarded controls on that row; the service invariant stays authoritative
// because this snapshot can be stale across two admin sessions.
func lastEnabledAdminID(users []auth.User) int64 {
	var id int64
	count := 0
	for _, user := range users {
		if user.Disabled() || !userRoleSet(user).Contains(auth.RoleAdmin) {
			continue
		}
		count++
		id = user.ID
	}
	if count != 1 {
		return 0
	}
	return id
}

func roleOptionsFor(selected auth.RoleSet) []roleOption {
	roles := auth.Roles()
	options := make([]roleOption, 0, len(roles))
	for _, role := range roles {
		options = append(options, roleOption{Value: string(role), Label: role.Label(), Hint: roleHint(role), Selected: selected.Contains(role)})
	}
	return options
}

// roleHint is the per-role line of the legacy role explainer, shown in the
// add-user dialog only (rows stay dense).
func roleHint(role auth.Role) string {
	switch role {
	case auth.RoleAdmin:
		return "Manages repositories, users, roles, tokens, and webhook secrets."
	case auth.RoleFreezer:
		return "Creates and ends freezes."
	case auth.RoleThawApprover:
		return "Approves PR exceptions."
	case auth.RoleViewer:
		return "Reads dashboards and audit history."
	default:
		return ""
	}
}

func rolesFromForm(r *http.Request) []auth.Role {
	roles := make([]auth.Role, 0, len(r.PostForm["roles"]))
	for _, role := range r.PostForm["roles"] {
		roles = append(roles, auth.Role(strings.TrimSpace(role)))
	}
	return roles
}

func formUserID(r *http.Request) int64 {
	userID, err := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("user_id")), 10, 64)
	if err != nil {
		return 0
	}
	return userID
}
