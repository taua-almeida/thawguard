package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
)

const (
	sessionCookieName = "thawguard_session"
	csrfFormField     = "csrf_token"
	sessionTTL        = 12 * time.Hour
)

type sessionState struct {
	ID        string
	CSRFToken string
	Role      auth.Role
	ExpiresAt time.Time
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
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return sessionState{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[cookie.Value]
	if !ok {
		return sessionState{}, false
	}
	if !s.now().Before(session.ExpiresAt) {
		delete(s.sessions, cookie.Value)
		return sessionState{}, false
	}
	return session, true
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
			Role:      auth.RoleAdmin,
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
