package web

import (
	"context"
	"html/template"
	"net/http"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type Config struct {
	AppName         string
	RepositoryStore RepositoryStore
}

type RepositoryStore interface {
	List(ctx context.Context) ([]domain.Repository, error)
	Create(ctx context.Context, params repository.CreateParams) (domain.Repository, error)
}

type Server struct {
	cfg      Config
	mux      *http.ServeMux
	sessions *sessionStore
}

func NewServer(cfg Config) *Server {
	if cfg.AppName == "" {
		cfg.AppName = "Thawguard"
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux(), sessions: newSessionStore()}
	s.routes()
	return s
}

func (s *Server) Routes() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /repositories", s.handleRepositories)
	s.mux.HandleFunc("POST /repositories", s.handleCreateRepository)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	repositories, err := s.repositories(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, dashboardTemplate, map[string]any{
		"AppName":         s.cfg.AppName,
		"RepositoryCount": len(repositories),
	})
}

func (s *Server) handleRepositories(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessions.getOrCreate(w, r)
	if err != nil {
		http.Error(w, "create session", http.StatusInternalServerError)
		return
	}

	repositories, err := s.repositories(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderRepositories(w, repositories, "", session.CSRFToken)
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
	})
	if err != nil {
		repositories, listErr := s.repositories(r.Context())
		if listErr != nil {
			http.Error(w, listErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderRepositories(w, repositories, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
}

func (s *Server) requireRepositoryManagerForm(w http.ResponseWriter, r *http.Request) (sessionState, bool) {
	session, ok := s.sessions.get(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if !session.Role.CanManageRepositories() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return sessionState{}, false
	}
	if !constantTimeTokenEqual(r.PostForm.Get(csrfFormField), session.CSRFToken) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return sessionState{}, false
	}
	return session, true
}

func (s *Server) repositories(ctx context.Context) ([]domain.Repository, error) {
	if s.cfg.RepositoryStore == nil {
		return nil, nil
	}
	return s.cfg.RepositoryStore.List(ctx)
}

func (s *Server) renderRepositories(w http.ResponseWriter, repositories []domain.Repository, formError string, csrfToken string) {
	s.render(w, repositoriesTemplate, map[string]any{
		"AppName":         s.cfg.AppName,
		"Repositories":    repositories,
		"FormError":       formError,
		"CSRFToken":       csrfToken,
		"RequiredContext": domain.RequiredStatusContext,
		"SetupSteps":      setupcheck.ManualSetupSteps(),
	})
}

func (s *Server) render(w http.ResponseWriter, source string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, err := template.New("page").Parse(source)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = tpl.Execute(w, data)
}

const pageHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ .AppName }}</title>
  <link rel="stylesheet" href="/static/thawguard.css">
</head>
<body>`

const pageFoot = `</body></html>`

const dashboardTemplate = pageHead + `
  <main class="shell">
    <section class="hero">
      <div class="pixel-shield" aria-hidden="true"></div>
      <p class="eyebrow">Freeze branches. Thaw exceptions.</p>
      <h1>{{ .AppName }} foundation is running</h1>
      <p>{{ .RepositoryCount }} repositories are configured. Next implementation step: setup health, freeze policy, jobs, and audit events.</p>
      <p><a class="button" href="/repositories">Manage repositories</a></p>
    </section>
  </main>` + pageFoot

const repositoriesTemplate = pageHead + `
  <main class="shell stack">
    <nav class="topnav"><a href="/">Dashboard</a></nav>
    <section class="panel">
      <p class="eyebrow">Repositories</p>
      <h1>Add repository</h1>
      <p>Start with Forgejo/Codeberg repositories. Manual setup must require the exact status context <code>{{ .RequiredContext }}</code>.</p>
      {{ if .FormError }}<p class="error">{{ .FormError }}</p>{{ end }}
      <form method="post" action="/repositories" class="form-grid">
        <input type="hidden" name="` + csrfFormField + `" value="{{ .CSRFToken }}">
        <label>Forge <input name="forge" value="forgejo"></label>
        <label>Base URL <input name="base_url" value="https://codeberg.org"></label>
        <label>Owner <input name="owner" required></label>
        <label>Repository <input name="name" required></label>
        <label>Default branch <input name="default_branch" value="main"></label>
        <button type="submit">Add repository</button>
      </form>
    </section>

    <section class="panel">
      <h2>Configured repositories</h2>
      {{ if .Repositories }}
      <table>
        <thead><tr><th>Repository</th><th>Forge</th><th>Default branch</th><th>Required context</th></tr></thead>
        <tbody>
        {{ range .Repositories }}
          <tr><td>{{ .FullName }}</td><td>{{ .Forge }}</td><td>{{ .DefaultBranch }}</td><td><code>` + domain.RequiredStatusContext + `</code></td></tr>
        {{ end }}
        </tbody>
      </table>
      {{ else }}
      <p>No repositories configured yet.</p>
      {{ end }}
    </section>

    <section class="panel">
      <h2>Manual setup checklist</h2>
      <ol>{{ range .SetupSteps }}<li>{{ . }}</li>{{ end }}</ol>
    </section>
  </main>` + pageFoot
