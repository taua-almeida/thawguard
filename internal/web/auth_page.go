package web

import "net/http"

// Auth-shell view models: one typed struct per screen, mirroring the
// dashboard_page.go pattern. Theme stays "" in production so the pages follow
// prefers-color-scheme; the dev preview forces it via ?theme=.

// authLoginData feeds pages/login.html. Email is preserved on error
// re-renders; the password never is.
type authLoginData struct {
	AppName   string
	PageTitle string
	Theme     string
	CSRFField string
	CSRFToken string
	FormError string
	Email     string
}

// authSetupData feeds pages/setup.html. Email and DisplayName are preserved
// on error re-renders; the password never is.
type authSetupData struct {
	AppName     string
	PageTitle   string
	Theme       string
	CSRFField   string
	CSRFToken   string
	FormError   string
	Email       string
	DisplayName string
}

// authAccountPasswordData feeds pages/account-password.html.
// MustChangePassword switches between the forced mode (warning callout, no
// back link) and the voluntary mode (subhead + back link).
type authAccountPasswordData struct {
	AppName            string
	PageTitle          string
	Theme              string
	CSRFField          string
	CSRFToken          string
	FormError          string
	MustChangePassword bool
}

// authErrorData feeds pages/error.html, the generic full-page error card.
type authErrorData struct {
	AppName     string
	PageTitle   string
	Theme       string
	Status      int
	Heading     string
	Message     string
	ActionHref  string
	ActionLabel string
}

// renderPageStatus is renderPage with an explicit HTTP status, for form
// re-renders and error pages (renderPage always answers 200).
func (s *Server) renderPageStatus(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
	_ = pageTemplates.ExecuteTemplate(w, name, data)
}

// errorPageContent maps a status code to the heading and copy on the generic
// error card. Copy stays plain-language and must not read as a hard security
// boundary.
func errorPageContent(status int) (heading, message string) {
	switch status {
	case http.StatusForbidden:
		return "You don't have access to this page",
			"Your account doesn't have the role this page needs, or the session that opened it has ended."
	case http.StatusNotFound:
		return "Page not found",
			"That address doesn't match any Thawguard page. The link may be stale, or the item may have been removed."
	case http.StatusServiceUnavailable:
		return "Not configured yet",
			"This part of Thawguard isn't configured on this install, so the page can't be shown."
	default:
		return "Something went wrong",
			"Thawguard hit an unexpected error handling that request. Nothing was changed — try again, or head back to the dashboard."
	}
}

// renderErrorPage writes the styled full-page error card. The status code is
// unchanged from the plain-text response this replaces; signedOut switches
// the single action to "Sign in". Full-page navigations only — htmx
// fragments, webhooks, and health checks keep plain text.
func (s *Server) renderErrorPage(w http.ResponseWriter, status int, signedOut bool) {
	heading, message := errorPageContent(status)
	data := authErrorData{
		AppName:     s.cfg.AppName,
		PageTitle:   heading,
		Status:      status,
		Heading:     heading,
		Message:     message,
		ActionHref:  "/",
		ActionLabel: "Back to dashboard",
	}
	if signedOut {
		data.ActionHref = "/login"
		data.ActionLabel = "Sign in"
	}
	s.renderPageStatus(w, status, "layouts/error", data)
}
