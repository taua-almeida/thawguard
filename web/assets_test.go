package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailwindSourcesCoverEveryPageTemplateAndAuthenticationLayout(t *testing.T) {
	source, err := os.ReadFile("styles/app.css")
	if err != nil {
		t.Fatal(err)
	}
	pages, err := filepath.Glob("../internal/web/templates/pages/*.html")
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) == 0 {
		t.Fatal("no file-based page templates found")
	}
	for _, page := range pages {
		want := `@source "../../internal/web/templates/pages/` + filepath.Base(page) + `";`
		if !strings.Contains(string(source), want) {
			t.Errorf("Tailwind source list is missing %s", filepath.Base(page))
		}
	}
	authenticationLayout := `@source "../../internal/web/templates/layouts/authentication.html";`
	if !strings.Contains(string(source), authenticationLayout) {
		t.Fatalf("Tailwind source list is missing %s", authenticationLayout)
	}
}
