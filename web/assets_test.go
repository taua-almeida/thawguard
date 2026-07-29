package web

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
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
	resultFragment := `@source "../../internal/web/templates/components/company-oidc-setup-health.html";`
	if !strings.Contains(string(source), resultFragment) {
		t.Fatalf("Tailwind source list is missing %s", resultFragment)
	}
}

func TestHTMXIndicatorAndOIDCIssuerStylesAreSelfHostedAndCSPCompatible(t *testing.T) {
	base, err := os.ReadFile("../internal/web/templates/layouts/base.html")
	if err != nil {
		t.Fatal(err)
	}
	meta := `<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>`
	metaIndex := strings.Index(string(base), meta)
	scriptIndex := strings.Index(string(base), `<script src="/static/js/htmx.min.js"`)
	if metaIndex < 0 || scriptIndex < 0 || metaIndex > scriptIndex {
		t.Fatalf("CSP-safe htmx config must appear before htmx initialization")
	}

	sourceBytes, err := os.ReadFile("styles/app.css")
	if err != nil {
		t.Fatal(err)
	}
	source := string(sourceBytes)
	for _, rule := range []string{
		".htmx-indicator {\n    display: none;",
		".htmx-request .htmx-indicator,\n  .htmx-request.htmx-indicator {\n    display: block;",
		".oidc-check-result.htmx-request .oidc-check-content {\n    display: none;",
		"padding: 0.0625rem 0.5rem 0.0625rem 0;",
		"background: var(--color-danger-soft);",
	} {
		if !strings.Contains(source, rule) {
			t.Fatalf("source stylesheet is missing self-hosted rule %q", rule)
		}
	}

	darkStart := strings.Index(source, `:root[data-theme="dark"] {`)
	if darkStart < 0 {
		t.Fatal("dark theme token block is missing")
	}
	darkEnd := strings.Index(source[darkStart:], "\n}")
	if darkEnd < 0 {
		t.Fatal("dark theme token block is malformed")
	}
	darkBlock := source[darkStart : darkStart+darkEnd]
	foreground := cssHexVariable(t, darkBlock, "--color-danger")
	background := cssHexVariable(t, darkBlock, "--color-danger-soft")
	if ratio := contrastRatio(foreground, background); ratio < 4.5 {
		t.Fatalf("dark danger-soft contrast = %.2f:1, want at least 4.5:1", ratio)
	}
}

func TestCompiledCSSContainsOIDCResultFragmentUtilitiesAndRequestRules(t *testing.T) {
	generated, err := os.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(generated)
	for _, selector := range []string{
		`.htmx-indicator{display:none}`,
		`.htmx-request .htmx-indicator,.htmx-request.htmx-indicator{display:block}`,
		`.oidc-check-result.htmx-request .oidc-check-content{display:none}`,
		`.oidc-issuer-trailing-slash{border-radius:0 var(--radius-control) var(--radius-control) 0;color:var(--color-danger);background:var(--color-danger-soft);padding:.0625rem .5rem .0625rem 0;`,
		`.min-h-44{min-height:calc(var(--spacing) * 44)}`,
	} {
		if !strings.Contains(css, selector) {
			t.Fatalf("compiled stylesheet is missing %q", selector)
		}
	}
}

func cssHexVariable(t *testing.T, block, name string) [3]float64 {
	t.Helper()
	marker := name + ": #"
	start := strings.Index(block, marker)
	if start < 0 {
		t.Fatalf("CSS variable %s is missing", name)
	}
	start += len(marker)
	if len(block) < start+6 {
		t.Fatalf("CSS variable %s has a short value", name)
	}
	var rgb [3]float64
	for i := range 3 {
		value, err := strconv.ParseUint(block[start+i*2:start+i*2+2], 16, 8)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		rgb[i] = float64(value) / 255
	}
	return rgb
}

func contrastRatio(foreground, background [3]float64) float64 {
	lighter := relativeLuminance(foreground)
	darker := relativeLuminance(background)
	if lighter < darker {
		lighter, darker = darker, lighter
	}
	return (lighter + 0.05) / (darker + 0.05)
}

func relativeLuminance(rgb [3]float64) float64 {
	for i, value := range rgb {
		if value <= 0.04045 {
			rgb[i] = value / 12.92
		} else {
			rgb[i] = math.Pow((value+0.055)/1.055, 2.4)
		}
	}
	return 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
}
