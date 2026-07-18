package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
)

//go:embed templates
var templateFS embed.FS

// templateFuncs holds the helpers available to every file-based template.
// dict builds a map from alternating key/value pairs so a caller can pass
// ad-hoc data to a primitive leaf; hasKey lets a primitive distinguish
// "key absent" from "key present with a zero value".
var templateFuncs = template.FuncMap{
	"dict": func(pairs ...any) (map[string]any, error) {
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("dict requires an even number of arguments, got %d", len(pairs))
		}
		m := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			key, ok := pairs[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict key %d is %T, want string", i/2, pairs[i])
			}
			m[key] = pairs[i+1]
		}
		return m, nil
	},
	"hasKey": func(m map[string]any, key string) bool {
		_, ok := m[key]
		return ok
	},
	// list collects its arguments into a slice so a caller can pass inline
	// option sets (e.g. ui/select Options) without a Go-side view model.
	"list": func(items ...any) []any { return items },
	// add exists for 1-based ordinals in range loops (e.g. stepper numbers).
	"add": func(a, b int) int { return a + b },
}

var pageTemplates = template.Must(template.New("").Funcs(templateFuncs).ParseFS(templateFS,
	"templates/layouts/*.html",
	"templates/pages/*.html",
	"templates/components/*.html",
	"templates/components/primitives/*.html",
))

func (s *Server) renderPage(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = pageTemplates.ExecuteTemplate(w, name, data)
}
