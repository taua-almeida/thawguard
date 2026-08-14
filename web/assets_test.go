package web

import (
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var templateClassAttribute = regexp.MustCompile(`class="([^"]+)"`)

// TestForgeEvidenceTemplatesUseOnlyCompiledSelectors proves every static
// utility class the shadow-access and role-evidence templates use has a
// compiled selector in web/static/app.css, so the pages render styled without
// CSS generation.
// Class lists computed by primitives carry template actions and are covered
// by the primitives' own compiled sources.
func TestForgeEvidenceTemplatesUseOnlyCompiledSelectors(t *testing.T) {
	css, err := os.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	compiled := string(css)
	for _, file := range []string{
		"../internal/web/templates/components/forge-shadow-summary.html",
		"../internal/web/templates/pages/forge-access-shadow.html",
		"../internal/web/templates/layouts/forge-access-shadow.html",
		"../internal/web/templates/pages/forge-role-evidence.html",
		"../internal/web/templates/layouts/forge-role-evidence.html",
	} {
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range templateClassAttribute.FindAllStringSubmatch(string(source), -1) {
			if strings.Contains(match[1], "{{") {
				continue
			}
			for token := range strings.FieldsSeq(match[1]) {
				// The selector must end at the class boundary: '.gap-1'
				// may not be satisfied by '.gap-1\.5'.
				selector := regexp.MustCompile(`\.` + regexp.QuoteMeta(cssEscapedClass(token)) + `[^A-Za-z0-9_\\-]`)
				if !selector.MatchString(compiled) {
					t.Errorf("%s uses class %q with no compiled selector", file, token)
				}
			}
		}
	}
}

// cssEscapedClass mirrors how Tailwind escapes utility names in selectors.
func cssEscapedClass(token string) string {
	var escaped strings.Builder
	for _, character := range token {
		switch character {
		case ':', '.', '/', '(', ')', '[', ']', '%', '#':
			escaped.WriteByte('\\')
		}
		escaped.WriteRune(character)
	}
	return escaped.String()
}

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
