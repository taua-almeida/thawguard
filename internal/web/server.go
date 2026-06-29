package web

import (
	"context"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

type Config struct {
	AppName          string
	RepositoryStore  RepositoryStore
	SetupCheckStore  SetupCheckStore
	SetupCheckRunner SetupCheckRunner
}

type RepositoryStore interface {
	List(ctx context.Context) ([]domain.Repository, error)
	Create(ctx context.Context, params repository.CreateParams, actor domain.Actor) (domain.Repository, error)
}

type SetupCheckStore interface {
	ListByRepository(ctx context.Context, repositoryID int64) ([]setupcheck.Check, error)
}

type SetupCheckRunner interface {
	Run(ctx context.Context, repo domain.Repository) ([]setupcheck.Result, error)
}

type repositoryView struct {
	Repository  domain.Repository
	SetupChecks []setupcheck.Check
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
	s.mux.HandleFunc("POST /repositories/setup-check", s.handleRunRepositorySetupCheck)
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
	views, err := s.repositoryViews(r.Context(), repositories)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.renderRepositories(w, views, "", session.CSRFToken)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		repositories, listErr := s.repositories(r.Context())
		if listErr != nil {
			http.Error(w, listErr.Error(), http.StatusInternalServerError)
			return
		}
		views, viewErr := s.repositoryViews(r.Context(), repositories)
		if viewErr != nil {
			http.Error(w, viewErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		s.renderRepositories(w, views, err.Error(), session.CSRFToken)
		return
	}
	http.Redirect(w, r, "/repositories", http.StatusSeeOther)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "repository not found", http.StatusNotFound)
		return
	}

	if _, err := s.cfg.SetupCheckRunner.Run(r.Context(), repo); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
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
	views := make([]repositoryView, 0, len(repositories))
	for _, repo := range repositories {
		view := repositoryView{Repository: repo}
		if s.cfg.SetupCheckStore != nil {
			checks, err := s.cfg.SetupCheckStore.ListByRepository(ctx, repo.ID)
			if err != nil {
				return nil, err
			}
			view.SetupChecks = latestSetupChecks(checks)
		}
		views = append(views, view)
	}
	return views, nil
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

func (s *Server) renderRepositories(w http.ResponseWriter, views []repositoryView, formError string, csrfToken string) {
	s.render(w, repositoriesTemplate, map[string]any{
		"AppName":         s.cfg.AppName,
		"RepositoryViews": views,
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
	      <p class="muted">Local setup checks are placeholders until live Forgejo/Codeberg verification is configured. They support setup workflow visibility, not hard enforcement.</p>
	      {{ if .RepositoryViews }}
      <table>
        <thead><tr><th>Repository</th><th>Forge</th><th>Default branch</th><th>Required context</th><th>Setup health</th><th>Actions</th></tr></thead>
        <tbody>
        {{ range .RepositoryViews }}
          <tr>
            <td>{{ .Repository.FullName }}</td>
            <td>{{ .Repository.Forge }}</td>
            <td>{{ .Repository.DefaultBranch }}</td>
            <td><code>` + domain.RequiredStatusContext + `</code></td>
            <td>
              {{ if .SetupChecks }}
                <ul class="setup-checks">
                {{ range .SetupChecks }}
                  <li><strong>{{ .Result.Name }}</strong>: <span class="status status-{{ .Result.Status }}">{{ .Result.Status }}</span><br><small>{{ .Result.Description }}{{ if .Result.Remediation }} {{ .Result.Remediation }}{{ end }}</small></li>
                {{ end }}
                </ul>
              {{ else }}
                <span class="muted">No setup checks yet.</span>
              {{ end }}
            </td>
            <td>
              <form method="post" action="/repositories/setup-check">
                <input type="hidden" name="` + csrfFormField + `" value="{{ $.CSRFToken }}">
                <input type="hidden" name="repository_id" value="{{ .Repository.ID }}">
				<button type="submit">Record local setup placeholder</button>
			  </form>
            </td>
          </tr>
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
