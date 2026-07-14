package web

import (
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates
var templateFS embed.FS

var pageTemplates = template.Must(template.ParseFS(templateFS,
	"templates/layouts/*.html",
	"templates/pages/*.html",
	"templates/components/*.html",
))

func (s *Server) renderPage(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplates.ExecuteTemplate(w, name, data)
}
