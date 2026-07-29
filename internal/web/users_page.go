package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

type usersQuery struct {
	Search       string
	RepositoryID int64
}

type usersPageState struct {
	FormError         string
	CreateOpen        bool
	CreateEmail       string
	CreateDisplayName string

	InviteOpen        bool
	InviteEmail       string
	InviteDisplayName string
	InviteAdmin       bool
	// InviteSelectedGrants holds the parseable "<repository id>:<role>" values
	// from a rejected submission so the dialog re-renders those checkboxes
	// checked. Bearer material is never part of this state.
	InviteSelectedGrants map[string]bool

	// ConfirmAction and ConfirmInvitationID open one invitation confirmation
	// dialog server-side. They come from GET /users query values so the
	// confirmation step works without JavaScript; with JavaScript the trigger
	// link is intercepted and the already-rendered dialog opens in place.
	ConfirmAction       string
	ConfirmInvitationID string
}

type usersRepositoryOption struct {
	Value    string
	Label    string
	Selected bool
}

type usersUserView struct {
	ID                 int64
	DisplayName        string
	Email              string
	Disabled           bool
	MustChangePassword bool
	IsSelf             bool
	IsAdmin            bool
	HasLocalPassword   bool
	RepositoryCount    int
	ScopedRoleLabels   []string
	AccessTitle        string
	AccessDetail       string
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

	Users             []usersUserView
	UserCount         int
	RepositoryOptions []usersRepositoryOption
	Query             usersQuery
	Filtered          bool
	NoRepositories    bool
	FormError         string
	CreateOpen        bool
	CreateEmail       string
	CreateDisplayName string

	// InvitationResult is the one-time link view attached to a single buffered
	// create or replace response. It is nil on every other render, so a later
	// GET /users can never reproduce a bearer.
	InvitationResult   *usersInvitationResultView
	Invitations        []usersInvitationView
	InviteOpen         bool
	InviteEmail        string
	InviteDisplayName  string
	InviteAdmin        bool
	InviteRepositories []usersInviteRepositoryView
}

type userGrantEvidenceView struct {
	Role string
	Text string
	At   string
}

type userRepositoryAccessView struct {
	Repository domain.Repository
	Viewer     bool
	Freezer    bool
	Thaw       bool
	Evidence   []userGrantEvidenceView
}

type userDetailState struct {
	FormError       string
	RepositoryID    int64
	RepositoryRoles auth.RoleSet
	AdminSubmitted  bool
	AdminValue      bool
}

type userDetailPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	User    auth.User
	IsSelf  bool
	IsAdmin bool
	// IsLastRecoveryAdmin marks the only enabled Admin with a local password.
	// Demoting or disabling that account is blocked because it would leave the
	// installation without local password recovery.
	IsLastRecoveryAdmin bool
	AdminChecked        bool
	Repositories        []userRepositoryAccessView
	RepositoryCount     int
	NoRepositories      bool
	FormError           string
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	query, err := usersQueryFromRequest(r)
	if err != nil {
		s.renderUsersPage(w, r, http.StatusBadRequest, usersQuery{Search: strings.TrimSpace(r.URL.Query().Get("q"))}, usersPageState{FormError: err.Error()}, session)
		return
	}
	state, confirmErr := invitationConfirmationState(r.URL.Query())
	if confirmErr != "" {
		s.renderUsersPage(w, r, http.StatusBadRequest, query, usersPageState{FormError: confirmErr}, session)
		return
	}
	data, ok := s.loadUsersPageData(w, r, query, state, session)
	if !ok {
		return
	}
	if r.URL.Query().Get("notice") == "invitation-cancelled" {
		data.Toasts = []toastView{{Message: "Invitation cancelled. Its email address is no longer reserved and can be invited again.", Tone: "success", DismissHref: "/users"}}
	}
	s.renderPageStatus(w, http.StatusOK, "layouts/users", data)
}

func usersQueryFromRequest(r *http.Request) (usersQuery, error) {
	query := usersQuery{Search: strings.TrimSpace(r.URL.Query().Get("q"))}
	if len(query.Search) > auth.UserDirectorySearchMaxLength {
		return query, auth.ValidationError{Message: "search is too long"}
	}
	rawRepositoryID := strings.TrimSpace(r.URL.Query().Get("repo"))
	if rawRepositoryID == "" {
		return query, nil
	}
	repositoryID, err := strconv.ParseInt(rawRepositoryID, 10, 64)
	if err != nil || repositoryID <= 0 {
		return query, auth.ValidationError{Message: "repository filter is invalid"}
	}
	query.RepositoryID = repositoryID
	return query, nil
}

// invitationConfirmationState reads the no-JavaScript confirmation request.
// Both values must be present together, appear once, name a supported action,
// and carry a canonical invitation ID; anything else is rejected rather than
// silently narrowed, so a malformed link can never open a confirmation dialog
// bound to the wrong invitation.
func invitationConfirmationState(query url.Values) (usersPageState, string) {
	action, invitationID := query["confirm"], query["invitation"]
	if len(action) == 0 && len(invitationID) == 0 {
		return usersPageState{}, ""
	}
	if len(action) != 1 || len(invitationID) != 1 {
		return usersPageState{}, "the confirmation request is invalid"
	}
	if action[0] != "replace" && action[0] != "cancel" {
		return usersPageState{}, "the confirmation request is invalid"
	}
	if !auth.ValidInvitationID(invitationID[0]) {
		return usersPageState{}, "the confirmation request is invalid"
	}
	return usersPageState{ConfirmAction: action[0], ConfirmInvitationID: invitationID[0]}, ""
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	user, err := s.cfg.AuthService.CreateUser(r.Context(), auth.CreateUserParams{
		ActorUserID: *session.UserID,
		Email:       r.PostFormValue("email"),
		DisplayName: r.PostFormValue("display_name"),
		Password:    r.PostFormValue("temporary_password"),
	})
	if err != nil {
		if !auth.IsValidationError(err) {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
			return
		}
		s.renderUsersPage(w, r, http.StatusBadRequest, usersQuery{}, usersPageState{
			FormError:         err.Error(),
			CreateOpen:        true,
			CreateEmail:       strings.TrimSpace(r.PostFormValue("email")),
			CreateDisplayName: strings.TrimSpace(r.PostFormValue("display_name")),
		}, session)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d?notice=created", user.ID), http.StatusSeeOther)
}

func (s *Server) renderUsersPage(w http.ResponseWriter, r *http.Request, status int, query usersQuery, state usersPageState, session sessionState) {
	data, ok := s.loadUsersPageData(w, r, query, state, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, status, "layouts/users", data)
}

func (s *Server) loadUsersPageData(w http.ResponseWriter, r *http.Request, query usersQuery, state usersPageState, session sessionState) (usersPageData, bool) {
	repositories, err := s.repositories(r.Context(), session.Grants.RepositoryReadScope())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return usersPageData{}, false
	}
	entries, err := s.cfg.AuthService.ListUsersDirectory(r.Context(), auth.UserDirectoryQuery{Search: query.Search, RepositoryID: query.RepositoryID})
	if err != nil {
		if auth.IsValidationError(err) {
			state.FormError = err.Error()
			entries, err = s.cfg.AuthService.ListUsersDirectory(r.Context(), auth.UserDirectoryQuery{})
		}
		if err != nil {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
			return usersPageData{}, false
		}
	}
	invitations, err := s.cfg.AuthService.ListActiveInvitations(r.Context())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return usersPageData{}, false
	}
	data := usersPageData{
		AppName:           s.cfg.AppName,
		PageTitle:         "Users & Access",
		ActivePage:        "users",
		CurrentUser:       currentUserFromSession(session),
		CSRFToken:         session.CSRFToken,
		CSRFField:         csrfFormField,
		RepositoryOptions: usersRepositoryOptions(repositories, query.RepositoryID),
		Query:             query,
		Filtered:          query.Search != "" || query.RepositoryID > 0,
		NoRepositories:    len(repositories) == 0,
		FormError:         state.FormError,
		CreateOpen:        state.CreateOpen,
		CreateEmail:       state.CreateEmail,
		CreateDisplayName: state.CreateDisplayName,

		Invitations:        usersInvitationViews(invitations, state),
		InviteOpen:         state.InviteOpen,
		InviteEmail:        state.InviteEmail,
		InviteDisplayName:  state.InviteDisplayName,
		InviteAdmin:        state.InviteAdmin,
		InviteRepositories: usersInviteRepositoryViews(repositories, state.InviteSelectedGrants),
	}
	data.Users = usersDirectoryViews(entries, session)
	data.UserCount = len(data.Users)
	return data, true
}

func usersRepositoryOptions(repositories []domain.Repository, selectedID int64) []usersRepositoryOption {
	options := []usersRepositoryOption{{Label: "Any repository", Selected: selectedID == 0}}
	for _, repository := range repositories {
		options = append(options, usersRepositoryOption{
			Value:    strconv.FormatInt(repository.ID, 10),
			Label:    repository.FullName(),
			Selected: repository.ID == selectedID,
		})
	}
	return options
}

func usersDirectoryViews(entries []auth.UserDirectoryEntry, session sessionState) []usersUserView {
	views := make([]usersUserView, 0, len(entries))
	for _, entry := range entries {
		view := usersUserView{
			ID:                 entry.ID,
			DisplayName:        entry.DisplayName,
			Email:              entry.Email,
			Disabled:           entry.Disabled(),
			MustChangePassword: entry.MustChangePassword,
			IsSelf:             session.UserID != nil && *session.UserID == entry.ID,
			IsAdmin:            entry.IsAdmin,
			HasLocalPassword:   entry.HasLocalPassword,
			RepositoryCount:    entry.RepositoryCount,
		}
		if entry.HasViewer {
			view.ScopedRoleLabels = append(view.ScopedRoleLabels, auth.RoleViewer.Label())
		}
		if entry.HasFreezer {
			view.ScopedRoleLabels = append(view.ScopedRoleLabels, auth.RoleFreezer.Label())
		}
		if entry.HasThawApprover {
			view.ScopedRoleLabels = append(view.ScopedRoleLabels, auth.RoleThawApprover.Label())
		}
		switch {
		case entry.IsAdmin:
			view.AccessTitle = "Admin"
			view.AccessDetail = "Views every repository"
		case entry.RepositoryCount == 0:
			view.AccessTitle = "No repository access"
		default:
			view.AccessTitle = fmt.Sprintf("%d repositories", entry.RepositoryCount)
		}
		if entry.Disabled() {
			if view.AccessDetail != "" {
				view.AccessDetail += " · Suspended while disabled"
			} else {
				view.AccessDetail = "Suspended while disabled"
			}
		}
		views = append(views, view)
	}
	return views
}

func (s *Server) handleUserDetail(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return
	}
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	userID, ok := userIDFromPath(r)
	if !ok {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	data, found := s.loadUserDetailPageData(w, r, userID, userDetailState{}, session)
	if !found {
		return
	}
	switch r.URL.Query().Get("notice") {
	case "created":
		data.Toasts = []toastView{{Message: "Local user created with no repository access. They must change the temporary password at first sign-in.", Tone: "success", DismissHref: fmt.Sprintf("/users/%d", userID)}}
	case "admin-saved":
		data.Toasts = []toastView{{Message: "Admin access saved.", Tone: "success", DismissHref: fmt.Sprintf("/users/%d", userID)}}
	case "access-saved":
		data.Toasts = []toastView{{Message: "Repository access saved.", Tone: "success", DismissHref: fmt.Sprintf("/users/%d", userID)}}
	case "disabled":
		data.Toasts = []toastView{{Message: "User disabled and sessions revoked.", Tone: "success", DismissHref: fmt.Sprintf("/users/%d", userID)}}
	case "enabled":
		data.Toasts = []toastView{{Message: "User re-enabled. Previous sessions were not restored.", Tone: "success", DismissHref: fmt.Sprintf("/users/%d", userID)}}
	}
	s.renderPage(w, "layouts/user-detail", data)
}

func userIDFromPath(r *http.Request) (int64, bool) {
	userID, err := strconv.ParseInt(strings.TrimSpace(r.PathValue("id")), 10, 64)
	return userID, err == nil && userID > 0
}

func (s *Server) loadUserDetailPageData(w http.ResponseWriter, r *http.Request, userID int64, state userDetailState, session sessionState) (userDetailPageData, bool) {
	user, err := s.cfg.AuthService.GetUser(r.Context(), userID)
	if err != nil {
		if isMissingUser(err) {
			s.renderErrorPage(w, http.StatusNotFound, false)
		} else {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
		}
		return userDetailPageData{}, false
	}
	repositories, err := s.repositories(r.Context(), session.Grants.RepositoryReadScope())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return userDetailPageData{}, false
	}
	grants, err := s.cfg.AuthService.ListUserRepositoryGrants(r.Context(), userID)
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return userDetailPageData{}, false
	}
	entries, err := s.cfg.AuthService.ListUsersDirectory(r.Context(), auth.UserDirectoryQuery{})
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return userDetailPageData{}, false
	}
	recoveryAdmins := 0
	for _, entry := range entries {
		if entry.IsAdmin && !entry.Disabled() && entry.HasLocalPassword {
			recoveryAdmins++
		}
	}
	isAdmin := user.IsAdmin
	data := userDetailPageData{
		AppName:             s.cfg.AppName,
		PageTitle:           user.DisplayName,
		ActivePage:          "users",
		CurrentUser:         currentUserFromSession(session),
		CSRFToken:           session.CSRFToken,
		CSRFField:           csrfFormField,
		User:                user,
		IsSelf:              session.UserID != nil && *session.UserID == user.ID,
		IsAdmin:             isAdmin,
		IsLastRecoveryAdmin: isAdmin && !user.Disabled() && user.HasLocalPassword && recoveryAdmins == 1,
		AdminChecked:        isAdmin,
		RepositoryCount:     len(repositories),
		NoRepositories:      len(repositories) == 0,
		FormError:           state.FormError,
	}
	if state.AdminSubmitted {
		data.AdminChecked = state.AdminValue
	}
	data.Repositories = userRepositoryAccessViews(repositories, grants, state)
	return data, true
}

func userRepositoryAccessViews(repositories []domain.Repository, grants []auth.RepositoryGrantDetail, state userDetailState) []userRepositoryAccessView {
	byRepository := make(map[int64][]auth.RepositoryGrantDetail)
	for _, grant := range grants {
		byRepository[grant.RepositoryID] = append(byRepository[grant.RepositoryID], grant)
	}
	views := make([]userRepositoryAccessView, 0, len(repositories))
	for _, repository := range repositories {
		view := userRepositoryAccessView{Repository: repository}
		for _, grant := range byRepository[repository.ID] {
			switch grant.Role {
			case auth.RoleViewer:
				view.Viewer = true
			case auth.RoleFreezer:
				view.Freezer = true
			case auth.RoleThawApprover:
				view.Thaw = true
			}
			text := "Added by a deleted or unavailable user"
			switch {
			case grant.Migrated:
				text = "Migrated legacy access"
			case grant.GranterDisplayName != "":
				text = "Added by " + grant.GranterDisplayName
			}
			view.Evidence = append(view.Evidence, userGrantEvidenceView{Role: grant.Role.Label(), Text: text, At: grant.GrantedAt.UTC().Format("2006-01-02 15:04 UTC")})
		}
		if state.RepositoryID == repository.ID {
			view.Viewer = state.RepositoryRoles.Contains(auth.RoleViewer)
			view.Freezer = state.RepositoryRoles.Contains(auth.RoleFreezer)
			view.Thaw = state.RepositoryRoles.Contains(auth.RoleThawApprover)
		}
		views = append(views, view)
	}
	return views
}

func (s *Server) handleSetUserAdmin(w http.ResponseWriter, r *http.Request) {
	session, target, ok := s.requireAdminUserMutation(w, r)
	if !ok {
		return
	}
	adminValue := r.PostFormValue("admin") == "1"
	_, err := s.cfg.AuthService.SetUserAdmin(r.Context(), auth.SetUserAdminParams{ActorUserID: *session.UserID, UserID: target.ID, Admin: adminValue})
	if err != nil {
		s.renderUserMutationError(w, r, target.ID, userDetailState{FormError: err.Error(), AdminSubmitted: true, AdminValue: adminValue}, session, err)
		return
	}
	if *session.UserID == target.ID && !adminValue {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d?notice=admin-saved", target.ID), http.StatusSeeOther)
}

func (s *Server) handleSetUserRepositoryAccess(w http.ResponseWriter, r *http.Request) {
	session, target, ok := s.requireAdminUserMutation(w, r)
	if !ok {
		return
	}
	repositoryID := repositoryIDFromForm(r)
	if _, visible := s.visibleRepository(w, r, session, repositoryID); !visible {
		return
	}
	roles := repositoryRolesFromForm(r)
	err := s.cfg.AuthService.SetUserRepositoryRoles(r.Context(), auth.SetUserRepositoryRolesParams{ActorUserID: *session.UserID, UserID: target.ID, RepositoryID: repositoryID, Roles: roles})
	if err != nil {
		s.renderUserMutationError(w, r, target.ID, userDetailState{FormError: err.Error(), RepositoryID: repositoryID, RepositoryRoles: auth.RoleSet(roles)}, session, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d?notice=access-saved", target.ID), http.StatusSeeOther)
}

func (s *Server) handleRemoveUserRepositoryAccess(w http.ResponseWriter, r *http.Request) {
	session, target, ok := s.requireAdminUserMutation(w, r)
	if !ok {
		return
	}
	repositoryID := repositoryIDFromForm(r)
	if _, visible := s.visibleRepository(w, r, session, repositoryID); !visible {
		return
	}
	err := s.cfg.AuthService.SetUserRepositoryRoles(r.Context(), auth.SetUserRepositoryRolesParams{ActorUserID: *session.UserID, UserID: target.ID, RepositoryID: repositoryID})
	if err != nil {
		s.renderUserMutationError(w, r, target.ID, userDetailState{FormError: err.Error(), RepositoryID: repositoryID}, session, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d?notice=access-saved", target.ID), http.StatusSeeOther)
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	session, target, ok := s.requireAdminUserMutation(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.AuthService.DisableUser(r.Context(), *session.UserID, target.ID); err != nil {
		s.renderUserMutationError(w, r, target.ID, userDetailState{FormError: err.Error()}, session, err)
		return
	}
	if *session.UserID == target.ID {
		clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d?notice=disabled", target.ID), http.StatusSeeOther)
}

func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	session, target, ok := s.requireAdminUserMutation(w, r)
	if !ok {
		return
	}
	if _, err := s.cfg.AuthService.EnableUser(r.Context(), *session.UserID, target.ID); err != nil {
		s.renderUserMutationError(w, r, target.ID, userDetailState{FormError: err.Error()}, session, err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/users/%d?notice=enabled", target.ID), http.StatusSeeOther)
}

func (s *Server) requireAdminUserMutation(w http.ResponseWriter, r *http.Request) (sessionState, auth.User, bool) {
	if s.cfg.AuthService == nil {
		http.Error(w, "auth service is not configured", http.StatusServiceUnavailable)
		return sessionState{}, auth.User{}, false
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return sessionState{}, auth.User{}, false
	}
	userID, valid := userIDFromPath(r)
	if !valid {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return sessionState{}, auth.User{}, false
	}
	target, err := s.cfg.AuthService.GetUser(r.Context(), userID)
	if err != nil {
		if isMissingUser(err) {
			s.renderErrorPage(w, http.StatusNotFound, false)
		} else {
			s.renderErrorPage(w, http.StatusInternalServerError, false)
		}
		return sessionState{}, auth.User{}, false
	}
	return session, target, true
}

func (s *Server) renderUserMutationError(w http.ResponseWriter, r *http.Request, userID int64, state userDetailState, session sessionState, err error) {
	if isMissingUser(err) {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	if !auth.IsValidationError(err) {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return
	}
	data, ok := s.loadUserDetailPageData(w, r, userID, state, session)
	if !ok {
		return
	}
	s.renderPageStatus(w, http.StatusBadRequest, "layouts/user-detail", data)
}

func isMissingUser(err error) bool {
	return auth.IsValidationError(err) && err.Error() == "user was not found"
}

func repositoryRolesFromForm(r *http.Request) []auth.Role {
	roles := make([]auth.Role, 0, len(r.PostForm["roles"]))
	for _, value := range r.PostForm["roles"] {
		roles = append(roles, auth.Role(strings.TrimSpace(value)))
	}
	return roles
}
