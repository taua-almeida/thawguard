package web

import (
	"fmt"
	"net/http"
)

type Config struct {
	AppName string
}

type Server struct {
	cfg Config
	mux *http.ServeMux
}

func NewServer(cfg Config) *Server {
	if cfg.AppName == "" {
		cfg.AppName = "Thawguard"
	}
	s := &Server{cfg: cfg, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Routes() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s</title>
  <link rel="stylesheet" href="/static/thawguard.css">
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div class="pixel-shield" aria-hidden="true"></div>
      <p class="eyebrow">Freeze branches. Thaw exceptions.</p>
      <h1>%s scaffold is running</h1>
      <p>Next implementation step: wire repositories, setup health, freeze policy, jobs, and audit events behind this server-rendered UI.</p>
    </section>
  </main>
</body>
</html>`, s.cfg.AppName, s.cfg.AppName)
}
