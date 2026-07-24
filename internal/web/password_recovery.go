package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/taua-almeida/thawguard/internal/auth"
)

const invalidPasswordRecoveryMessage = "This recovery link is invalid or no longer available. It may have expired, been replaced, or already been used. Ask an Admin for a new link."

type authPasswordRecoveryData struct {
	AppName       string
	PageTitle     string
	Theme         string
	CSRFField     string
	CSRFToken     string
	FormError     string
	RecoveryToken string
	Bootstrap     bool
}

type authPasswordRecoveryMessageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	Heading     string
	Message     string
	ActionHref  string
	ActionLabel string
}

type authPasswordRecoveryIssuedData struct {
	AppName           string
	PageTitle         string
	Theme             string
	TargetDisplayName string
	TargetEmail       string
	RecoveryLink      string
	ExpiresAt         string
	BackHref          string
}

func (s *Server) handleIssuePasswordRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, passwordRecoveryMaxBodyBytes)
	if !s.validPasswordRecoveryOrigin(r) {
		s.renderPasswordRecoveryMessage(
			w,
			http.StatusForbidden,
			"Recovery link not issued",
			"This request could not be verified. Return to Users & Access and try again.",
			"/users",
			"Back to Users & Access",
		)
		return
	}

	session, target, ok := s.requireAdminUserMutation(w, r)
	if !ok {
		return
	}
	issued, err := s.cfg.AuthService.IssuePasswordRecoveryToken(r.Context(), auth.IssuePasswordRecoveryParams{
		ActorUserID: *session.UserID,
		UserID:      target.ID,
	})
	if err != nil {
		status := http.StatusInternalServerError
		message := "Thawguard could not issue a recovery link. Return to the user and try again."
		if auth.IsValidationError(err) {
			status = http.StatusBadRequest
			message = err.Error()
		}
		s.renderPasswordRecoveryMessage(
			w,
			status,
			"Recovery link not issued",
			message,
			fmt.Sprintf("/users/%d", target.ID),
			"Back to user",
		)
		return
	}

	s.renderPageStatus(w, http.StatusOK, "layouts/password-recovery-issued", authPasswordRecoveryIssuedData{
		AppName:           s.cfg.AppName,
		PageTitle:         "Recovery link created",
		TargetDisplayName: target.DisplayName,
		TargetEmail:       target.Email,
		RecoveryLink:      s.cfg.PublicURL + "/password-recovery#token=" + issued.Token,
		ExpiresAt:         issued.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
		BackHref:          fmt.Sprintf("/users/%d", target.ID),
	})
}

func (s *Server) handlePasswordRecovery(w http.ResponseWriter, r *http.Request) {
	csrfToken, err := s.newPasswordRecoveryCSRFToken()
	if err != nil {
		s.renderPasswordRecoveryInternalError(w)
		return
	}
	s.renderPageStatus(w, http.StatusOK, "layouts/password-recovery", authPasswordRecoveryData{
		AppName:   s.cfg.AppName,
		PageTitle: "Password recovery",
		CSRFField: csrfFormField,
		CSRFToken: csrfToken,
		Bootstrap: true,
	})
}

func (s *Server) handlePasswordRecoveryPost(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, passwordRecoveryMaxBodyBytes)
	if !s.validPasswordRecoveryOrigin(r) {
		s.renderPasswordRecoveryForbidden(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			s.renderPasswordRecoveryMessage(
				w,
				http.StatusRequestEntityTooLarge,
				"Recovery request not processed",
				"This recovery request is too large. Reopen the original link and try again.",
				"",
				"",
			)
			return
		}
		s.renderPasswordRecoveryBadRequest(w)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || !onlyPasswordRecoveryFields(r.PostForm) {
		s.renderPasswordRecoveryBadRequest(w)
		return
	}
	if !s.validPasswordRecoveryCSRFToken(r) {
		s.renderPasswordRecoveryForbidden(w)
		return
	}
	if s.cfg.AuthService == nil {
		s.renderPasswordRecoveryInternalError(w)
		return
	}

	recoveryToken := r.PostForm.Get("recovery_token")
	err := s.cfg.AuthService.CompletePasswordRecovery(r.Context(), auth.CompletePasswordRecoveryParams{
		Token:       recoveryToken,
		NewPassword: r.PostForm.Get("new_password"),
	})
	switch {
	case err == nil:
		s.renderPasswordRecoveryMessage(
			w,
			http.StatusOK,
			"Password changed",
			"Password changed. Existing sessions were signed out. Sign in with your new password.",
			"/login",
			"Sign in",
		)
	case auth.IsValidationError(err):
		csrfToken, csrfErr := s.newPasswordRecoveryCSRFToken()
		if csrfErr != nil {
			s.renderPasswordRecoveryInternalError(w)
			return
		}
		s.renderPageStatus(w, http.StatusBadRequest, "layouts/password-recovery", authPasswordRecoveryData{
			AppName:       s.cfg.AppName,
			PageTitle:     "Choose a new password",
			CSRFField:     csrfFormField,
			CSRFToken:     csrfToken,
			FormError:     err.Error(),
			RecoveryToken: recoveryToken,
		})
	case auth.IsInvalidPasswordRecoveryToken(err):
		s.renderPasswordRecoveryMessage(
			w,
			http.StatusBadRequest,
			"Recovery link unavailable",
			invalidPasswordRecoveryMessage,
			"",
			"",
		)
	default:
		s.renderPasswordRecoveryInternalError(w)
	}
}

func onlyPasswordRecoveryFields(form url.Values) bool {
	for key, values := range form {
		switch key {
		case csrfFormField, "recovery_token", "new_password":
			if len(values) != 1 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (s *Server) validPasswordRecoveryOrigin(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == s.cfg.PublicURL
}

func (s *Server) renderPasswordRecoveryForbidden(w http.ResponseWriter) {
	s.renderPasswordRecoveryMessage(
		w,
		http.StatusForbidden,
		"Recovery request not verified",
		"This request could not be verified. Reopen the original recovery link and try again.",
		"",
		"",
	)
}

func (s *Server) renderPasswordRecoveryBadRequest(w http.ResponseWriter) {
	s.renderPasswordRecoveryMessage(
		w,
		http.StatusBadRequest,
		"Recovery request not processed",
		"This recovery request could not be processed. Ask an Admin for a new link if the problem continues.",
		"",
		"",
	)
}

func (s *Server) renderPasswordRecoveryInternalError(w http.ResponseWriter) {
	s.renderPasswordRecoveryMessage(
		w,
		http.StatusInternalServerError,
		"Password not changed",
		"Thawguard could not complete password recovery. Ask an Admin for a new link.",
		"",
		"",
	)
}

func (s *Server) renderPasswordRecoveryMessage(
	w http.ResponseWriter,
	status int,
	heading string,
	message string,
	actionHref string,
	actionLabel string,
) {
	s.renderPageStatus(w, status, "layouts/password-recovery-message", authPasswordRecoveryMessageData{
		AppName:     s.cfg.AppName,
		PageTitle:   heading,
		Heading:     heading,
		Message:     message,
		ActionHref:  actionHref,
		ActionLabel: actionLabel,
	})
}
