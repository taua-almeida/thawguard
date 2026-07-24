package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

const (
	sessionCookieName = "thawguard_session"
	setupCookieName   = "thawguard_setup"
	loginCookieName   = "thawguard_login"
	csrfFormField     = "csrf_token"
	sessionTTL        = 12 * time.Hour
	preAuthCSRFMaxAge = 30 * time.Minute
)

const (
	setupCSRFPurpose            = "setup"
	loginCSRFPurpose            = "login"
	passwordRecoveryCSRFPurpose = "password-recovery"
)

type sessionState struct {
	ID                 string
	CSRFToken          string
	UserID             *int64
	Email              string
	DisplayName        string
	Grants             auth.Grants
	MustChangePassword bool
	ExpiresAt          time.Time
}

func (s sessionState) auditActor() domain.Actor {
	role := "no_repository_access"
	if s.Grants.CanManageInstallation() {
		role = string(auth.RoleAdmin)
	} else if s.Grants.HasRepositoryAccess() {
		role = "repository_access"
	}
	if s.UserID != nil {
		return domain.Actor{UserID: s.UserID, Kind: domain.ActorKindUser, Role: role}
	}
	return domain.Actor{Kind: domain.ActorKindBootstrapAdmin, Role: role}
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionState
	now      func() time.Time
	ttl      time.Duration
}

func newSessionStore() *sessionStore {
	return &sessionStore{
		sessions: make(map[string]sessionState),
		now:      func() time.Time { return time.Now().UTC() },
		ttl:      sessionTTL,
	}
}

func (s *sessionStore) getOrCreate(w http.ResponseWriter, r *http.Request) (sessionState, error) {
	if session, ok := s.get(r); ok {
		setSessionCookie(w, r, session)
		return session, nil
	}
	session, err := s.create()
	if err != nil {
		return sessionState{}, err
	}
	setSessionCookie(w, r, session)
	return session, nil
}

func (s *sessionStore) get(r *http.Request) (sessionState, bool) {
	for _, cookie := range r.Cookies() {
		if cookie.Name != sessionCookieName || cookie.Value == "" {
			continue
		}
		s.mu.Lock()
		session, ok := s.sessions[cookie.Value]
		if ok && !s.now().Before(session.ExpiresAt) {
			delete(s.sessions, cookie.Value)
			s.mu.Unlock()
			continue
		}
		s.mu.Unlock()
		if ok {
			return session, true
		}
	}
	return sessionState{}, false
}

func (s *sessionStore) delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

func (s *sessionStore) create() (sessionState, error) {
	for range 3 {
		id, err := randomToken(32)
		if err != nil {
			return sessionState{}, err
		}
		csrfToken, err := randomToken(32)
		if err != nil {
			return sessionState{}, err
		}
		session := sessionState{
			ID:        id,
			CSRFToken: csrfToken,
			ExpiresAt: s.now().Add(s.ttl),
		}

		s.mu.Lock()
		if _, exists := s.sessions[id]; !exists {
			s.sessions[id] = session
			s.mu.Unlock()
			return session, nil
		}
		s.mu.Unlock()
	}
	return sessionState{}, errors.New("create unique session")
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func sameOriginRequest(r *http.Request) bool {
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return originMatchesRequest(r, origin)
	}
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer == "" {
		return false
	}
	parsed, err := url.Parse(referer)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == requestScheme(r) && parsed.Host == r.Host
}

func originMatchesRequest(r *http.Request, origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == requestScheme(r) && parsed.Host == r.Host
}

func requestScheme(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		scheme, _, _ := strings.Cut(forwarded, ",")
		scheme = strings.TrimSpace(scheme)
		if scheme == "http" || scheme == "https" {
			return scheme
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func newCSRFSigningKey() []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic("create csrf signing key: " + err.Error())
	}
	return key
}

func (s *Server) newSetupCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := s.newSignedCSRFToken(setupCSRFPurpose)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     setupCookieName,
		Value:    token,
		Path:     "/setup",
		Expires:  time.Now().UTC().Add(preAuthCSRFMaxAge),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	return token, nil
}

func (s *Server) validSetupCSRFToken(r *http.Request) bool {
	return s.validPreAuthCSRFToken(r, setupCSRFPurpose)
}

func clearSetupCSRFCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     setupCookieName,
		Value:    "",
		Path:     "/setup",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func (s *Server) newLoginCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	token, err := s.newSignedCSRFToken(loginCSRFPurpose)
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookieName,
		Value:    token,
		Path:     "/login",
		Expires:  time.Now().UTC().Add(preAuthCSRFMaxAge),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	return token, nil
}

func (s *Server) validLoginCSRFToken(r *http.Request) bool {
	return s.validPreAuthCSRFToken(r, loginCSRFPurpose)
}

func (s *Server) newPasswordRecoveryCSRFToken() (string, error) {
	return s.newSignedCSRFToken(passwordRecoveryCSRFPurpose)
}

func (s *Server) validPasswordRecoveryCSRFToken(r *http.Request) bool {
	return s.validPreAuthCSRFToken(r, passwordRecoveryCSRFPurpose)
}

func (s *Server) newSignedCSRFToken(purpose string) (string, error) {
	nonce, err := randomToken(32)
	if err != nil {
		return "", err
	}
	payload := purpose + "." + strconv.FormatInt(time.Now().UTC().Unix(), 10) + "." + nonce
	return payload + "." + s.signCSRFPayload(payload), nil
}

func (s *Server) validPreAuthCSRFToken(r *http.Request, purpose string) bool {
	submitted := r.PostForm.Get(csrfFormField)
	return submitted != "" && s.validSignedCSRFToken(submitted, purpose)
}

func (s *Server) validSignedCSRFToken(token string, purpose string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != purpose || parts[1] == "" || parts[2] == "" || parts[3] == "" {
		return false
	}
	issuedUnix, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return false
	}
	issuedAt := time.Unix(issuedUnix, 0).UTC()
	now := time.Now().UTC()
	if issuedAt.After(now.Add(time.Minute)) || now.Sub(issuedAt) > preAuthCSRFMaxAge {
		return false
	}
	payload := strings.Join(parts[:3], ".")
	return constantTimeTokenEqual(parts[3], s.signCSRFPayload(payload))
}

func (s *Server) signCSRFPayload(payload string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func clearLoginCSRFCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     loginCookieName,
		Value:    "",
		Path:     "/login",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, session sessionState) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.ID,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
}

func randomToken(byteLength int) (string, error) {
	buf := make([]byte, byteLength)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func constantTimeTokenEqual(submitted string, expected string) bool {
	if submitted == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) == 1
}
