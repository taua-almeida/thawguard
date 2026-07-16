//go:build e2e

package e2e

import (
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	fixtureOwner           = "e2e-owner"
	fixtureRepository      = "icebox-demo"
	fixtureReleaseBranch   = "release"
	fixtureFeatureBranch   = "feature/freeze-check"
	primaryStatusTokenName = "thawguard-e2e-status-primary"
	requiredContext        = "thawguard/freeze"
	invalidDeliveryID      = "e2e-invalid-signature-fixture"
	duplicateDeliveryID    = "e2e-duplicate-delivery-fixture"
)

type e2eConfig struct {
	forgejoURL             string
	forgejoControlToken    string
	forgejoOwnerPassword   string
	primaryStatusToken     string
	replacementStatusToken string
	thawguardURL           string
	webhookSecret          string
	thawguardPassword      string
}

type forgejoAPI struct {
	baseURL string
	token   string
	client  *http.Client
}

type apiResponse struct {
	statusCode int
	body       []byte
}

type thawguardBrowser struct {
	baseURL string
	client  *http.Client
}

type pullRequest struct {
	Number int `json:"number"`
	Head   struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

type commitStatus struct {
	ID          int64  `json:"id"`
	Context     string `json:"context"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type webhookSideEffectEvidence struct {
	webhookPage         string
	webhookRows         int
	statusResults       int
	publicationIntents  int
	publicationAttempts int
	activityEvents      int
	freezeStatuses      []commitStatus
}

func TestLocalForgejoFreezeLifecycle(t *testing.T) {
	if os.Getenv("THAWGUARD_E2E") != "1" {
		t.Skip("set THAWGUARD_E2E=1 and use make e2e")
	}
	cfg := loadConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sensitiveValues := cfg.sensitiveValues()
	forgejo := &forgejoAPI{
		baseURL: cfg.forgejoURL,
		token:   cfg.forgejoControlToken,
		client:  newScanningHTTPClient(10*time.Second, "Forgejo API", sensitiveValues),
	}
	browser := newThawguardBrowser(t, cfg.thawguardURL, sensitiveValues)

	provisionForgejoRepository(t, ctx, forgejo)
	repositoryID := configureThawguard(t, ctx, browser, cfg)
	createForgejoWebhook(t, ctx, forgejo, cfg.webhookSecret)
	pr := createForgejoPullRequest(t, ctx, forgejo)

	waitFor(t, 30*time.Second, "verified Forgejo webhook delivery", func() (bool, error) {
		page, err := browser.get(ctx, "/webhooks?processing=processed&event=pull_request")
		if err != nil {
			return false, err
		}
		return strings.Contains(page, fixtureOwner+"/"+fixtureRepository) &&
			strings.Contains(page, "opened") &&
			strings.Contains(page, "verified") &&
			nonzeroMatchingRows.MatchString(page), nil
	})

	activateEnforcement(t, ctx, browser, repositoryID)
	createFreeze(t, ctx, browser, repositoryID)
	waitForStatusWithDescription(t, ctx, forgejo, pr.Head.SHA, "failure", "Branch is frozen; merge is blocked by Thawguard")
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pr.Number)

	beforeTokenFailure := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, pr.Head.SHA)
	revokePrimaryStatusToken(t, ctx, forgejo, cfg.forgejoOwnerPassword)
	newHeadSHA := advanceFeatureBranch(t, ctx, forgejo, pr)
	waitForTokenFailureEvidence(t, ctx, forgejo, browser, repositoryID, newHeadSHA)
	afterTokenFailure := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, newHeadSHA)
	requireTokenFailureSideEffects(t, beforeTokenFailure, afterTokenFailure)
	assertNoFreezeStatus(t, ctx, forgejo, newHeadSHA)
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pr.Number)
	scanRenderedTokenSurfaces(t, ctx, browser)

	rotateStatusTokenAndRecover(t, ctx, browser, cfg, repositoryID)
	waitForRecoveredEnforcement(t, ctx, forgejo, browser, newHeadSHA)
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pr.Number)
	scanRenderedTokenSurfaces(t, ctx, browser)

	openPullRequestSyncsBeforeProbes := countOpenPullRequestSyncEvents(requirePage(t, ctx, browser, "/activity"))

	t.Run("invalid signature has no side effects", func(t *testing.T) {
		payload := syntheticPullRequestWebhookPayload(t, cfg, pr.Number+1000, newHeadSHA)
		assertInvalidSignatureHasNoSideEffects(t, ctx, forgejo, browser, cfg, repositoryID, newHeadSHA, payload)
	})
	t.Run("duplicate delivery is idempotent", func(t *testing.T) {
		payload := syntheticPullRequestWebhookPayload(t, cfg, pr.Number, newHeadSHA)
		assertDuplicateDeliveryIsIdempotent(t, ctx, forgejo, browser, cfg, repositoryID, newHeadSHA, payload)
	})

	liftFreeze(t, ctx, browser)
	waitForStatusWithDescription(t, ctx, forgejo, newHeadSHA, "success", "No active freeze applies to this PR")
	activityPage := waitForOneNewOpenPullRequestSync(t, ctx, browser, openPullRequestSyncsBeforeProbes)
	requireLatestOpenPullRequestSync(t, activityPage)
	scanRenderedTokenSurfaces(t, ctx, browser)
}

func loadConfig(t *testing.T) e2eConfig {
	t.Helper()
	cfg := e2eConfig{
		forgejoURL:             strings.TrimRight(os.Getenv("THAWGUARD_E2E_FORGEJO_URL"), "/"),
		forgejoControlToken:    os.Getenv("THAWGUARD_E2E_FORGEJO_CONTROL_TOKEN"),
		forgejoOwnerPassword:   os.Getenv("THAWGUARD_E2E_FORGEJO_OWNER_PASSWORD"),
		primaryStatusToken:     os.Getenv("THAWGUARD_E2E_PRIMARY_STATUS_TOKEN"),
		replacementStatusToken: os.Getenv("THAWGUARD_E2E_REPLACEMENT_STATUS_TOKEN"),
		thawguardURL:           "http://127.0.0.1:8080",
		webhookSecret:          os.Getenv("THAWGUARD_E2E_WEBHOOK_SECRET"),
		thawguardPassword:      os.Getenv("THAWGUARD_E2E_ADMIN_PASSWORD"),
	}
	for _, required := range []struct {
		name  string
		value string
	}{
		{name: "THAWGUARD_E2E_FORGEJO_URL", value: cfg.forgejoURL},
		{name: "THAWGUARD_E2E_FORGEJO_CONTROL_TOKEN", value: cfg.forgejoControlToken},
		{name: "THAWGUARD_E2E_FORGEJO_OWNER_PASSWORD", value: cfg.forgejoOwnerPassword},
		{name: "THAWGUARD_E2E_PRIMARY_STATUS_TOKEN", value: cfg.primaryStatusToken},
		{name: "THAWGUARD_E2E_REPLACEMENT_STATUS_TOKEN", value: cfg.replacementStatusToken},
		{name: "THAWGUARD_E2E_WEBHOOK_SECRET", value: cfg.webhookSecret},
		{name: "THAWGUARD_E2E_ADMIN_PASSWORD", value: cfg.thawguardPassword},
	} {
		if strings.TrimSpace(required.value) == "" {
			t.Fatalf("required E2E environment variable is unset: %s", required.name)
		}
	}
	if cfg.forgejoControlToken == cfg.primaryStatusToken ||
		cfg.forgejoControlToken == cfg.replacementStatusToken ||
		cfg.primaryStatusToken == cfg.replacementStatusToken {
		t.Fatal("Forgejo E2E credentials must use three distinct token values")
	}
	return cfg
}

func (cfg e2eConfig) sensitiveValues() []string {
	return []string{
		cfg.forgejoControlToken,
		cfg.forgejoOwnerPassword,
		cfg.primaryStatusToken,
		cfg.replacementStatusToken,
		cfg.webhookSecret,
		cfg.thawguardPassword,
	}
}

func provisionForgejoRepository(t *testing.T, ctx context.Context, forgejo *forgejoAPI) {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodPost, "/api/v1/user/repos", map[string]any{
		"name":           fixtureRepository,
		"default_branch": "main",
		"auto_init":      true,
		"private":        true,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo repository")

	for _, branch := range []string{fixtureReleaseBranch, fixtureFeatureBranch} {
		response, err = forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("branches"), map[string]any{
			"new_branch_name": branch,
			"old_ref_name":    "main",
		})
		requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo branch")
	}

	for _, branch := range []string{"main", fixtureReleaseBranch} {
		response, err = forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("branch_protections"), map[string]any{
			"rule_name":             branch,
			"enable_status_check":   true,
			"status_check_contexts": []string{requiredContext},
			"apply_to_admins":       true,
		})
		requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo branch protection")
		var protection struct {
			RuleName            string   `json:"rule_name"`
			EnableStatusCheck   bool     `json:"enable_status_check"`
			StatusCheckContexts []string `json:"status_check_contexts"`
		}
		decodeJSON(t, response.body, &protection, "decode branch protection")
		if protection.RuleName != branch || !protection.EnableStatusCheck || !slices.Contains(protection.StatusCheckContexts, requiredContext) {
			t.Fatalf("Forgejo returned incomplete protection for branch %q", branch)
		}
	}

	response, err = forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("contents", "fixture.txt"), map[string]any{
		"branch":  fixtureFeatureBranch,
		"message": "Add fictional E2E fixture",
		"content": base64.StdEncoding.EncodeToString([]byte("fictional local fixture\n")),
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo fixture commit")
}

func configureThawguard(t *testing.T, ctx context.Context, browser *thawguardBrowser, cfg e2eConfig) int64 {
	t.Helper()
	setupPage, err := browser.get(ctx, "/setup")
	if err != nil {
		t.Fatal(err)
	}
	setupCSRF := requireHiddenInput(t, setupPage, "csrf_token")
	requirePostForm(t, ctx, browser, "/setup", url.Values{
		"csrf_token":   {setupCSRF},
		"email":        {"admin@thawguard.test"},
		"display_name": {"E2E Admin"},
		"password":     {cfg.thawguardPassword},
	}, "create first Thawguard admin")

	repositoriesPage := requirePage(t, ctx, browser, "/repositories")
	csrf := requireHiddenInput(t, repositoriesPage, "csrf_token")
	requirePostForm(t, ctx, browser, "/repositories", url.Values{
		"csrf_token":     {csrf},
		"forge":          {"forgejo"},
		"base_url":       {cfg.forgejoURL},
		"owner":          {fixtureOwner},
		"name":           {fixtureRepository},
		"default_branch": {"main"},
	}, "configure Thawguard repository")

	repositoriesPage = requirePage(t, ctx, browser, "/repositories")
	repositoryID, err := strconv.ParseInt(requireHiddenInput(t, repositoriesPage, "repository_id"), 10, 64)
	if err != nil || repositoryID <= 0 {
		t.Fatalf("parse configured Thawguard repository ID: %v", err)
	}
	csrf = requireHiddenInput(t, repositoriesPage, "csrf_token")
	requirePostForm(t, ctx, browser, "/repositories/branches", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {strconv.FormatInt(repositoryID, 10)},
		"branch":        {fixtureReleaseBranch},
	}, "add managed branch through Thawguard")
	requirePostForm(t, ctx, browser, "/repositories/webhook-secret", url.Values{
		"csrf_token":     {csrf},
		"repository_id":  {strconv.FormatInt(repositoryID, 10)},
		"webhook_secret": {cfg.webhookSecret},
	}, "store encrypted webhook secret")
	requirePostForm(t, ctx, browser, "/repositories/status-token", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {strconv.FormatInt(repositoryID, 10)},
		"status_token":  {cfg.primaryStatusToken},
	}, "store encrypted status token")
	return repositoryID
}

func createForgejoWebhook(t *testing.T, ctx context.Context, forgejo *forgejoAPI, secret string) {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("hooks"), map[string]any{
		"type": "forgejo",
		"config": map[string]string{
			"url":          "http://127.0.0.1:8080/webhooks/forgejo",
			"content_type": "json",
			"secret":       secret,
		},
		"events": []string{"pull_request"},
		"active": true,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo webhook")
}

func createForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI) pullRequest {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("pulls"), map[string]any{
		"head":  fixtureFeatureBranch,
		"base":  "main",
		"title": "Fictional release check",
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo pull request")
	var pr pullRequest
	decodeJSON(t, response.body, &pr, "decode Forgejo pull request")
	if pr.Number <= 0 || strings.TrimSpace(pr.Head.SHA) == "" {
		t.Fatal("Forgejo pull request response is missing its number or head SHA")
	}
	return pr
}

func revokePrimaryStatusToken(t *testing.T, ctx context.Context, forgejo *forgejoAPI, ownerPassword string) {
	t.Helper()
	path := "/api/v1/users/" + url.PathEscape(fixtureOwner) + "/tokens/" + url.PathEscape(primaryStatusTokenName)
	response, err := forgejo.doBasicAuth(ctx, http.MethodDelete, path, fixtureOwner, ownerPassword)
	requireAPIStatus(t, response, err, http.StatusNoContent, "revoke primary Forgejo status token by name")
}

func advanceFeatureBranch(t *testing.T, ctx context.Context, forgejo *forgejoAPI, pr pullRequest) string {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("contents", "token-loss.txt"), map[string]any{
		"branch":  fixtureFeatureBranch,
		"message": "Advance fictional E2E feature head",
		"content": base64.StdEncoding.EncodeToString([]byte("new head for token-loss recovery proof\n")),
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo token-loss fixture commit")
	var created struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	decodeJSON(t, response.body, &created, "decode Forgejo token-loss fixture commit")
	newHeadSHA := strings.ToLower(strings.TrimSpace(created.Commit.SHA))
	if newHeadSHA == "" || newHeadSHA == strings.ToLower(pr.Head.SHA) {
		t.Fatal("Forgejo token-loss fixture did not create a distinct commit SHA")
	}

	waitFor(t, 30*time.Second, "Forgejo pull request head advance", func() (bool, error) {
		response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("pulls", strconv.Itoa(pr.Number)), nil)
		if err != nil {
			return false, err
		}
		if response.statusCode != http.StatusOK {
			return false, apiStatusError(response, "read advanced Forgejo pull request")
		}
		var current pullRequest
		if err := json.Unmarshal(response.body, &current); err != nil {
			return false, fmt.Errorf("decode advanced Forgejo pull request: %w", err)
		}
		return strings.EqualFold(strings.TrimSpace(current.Head.SHA), newHeadSHA), nil
	})
	return newHeadSHA
}

func waitForTokenFailureEvidence(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, headSHA string) {
	t.Helper()
	webhookPath := "/webhooks?" + url.Values{
		"repository_id": {strconv.FormatInt(repositoryID, 10)},
		"event":         {"pull_request"},
		"processing":    {"retryable_failure"},
		"limit":         {"100"},
	}.Encode()
	waitFor(t, 30*time.Second, "sanitized token-loss failure evidence", func() (bool, error) {
		webhookPage, err := browser.get(ctx, webhookPath)
		if err != nil {
			return false, err
		}
		repositoriesPage, err := browser.get(ctx, "/repositories")
		if err != nil {
			return false, err
		}
		publicationsPage, err := browser.get(ctx, "/publications")
		if err != nil {
			return false, err
		}
		activityPage, err := browser.get(ctx, "/activity")
		if err != nil {
			return false, err
		}
		statuses, err := listForgejoFreezeStatuses(ctx, forgejo, headSHA)
		if err != nil {
			return false, err
		}
		recoveryVisible := strings.Contains(repositoriesPage, "Automatic recovery is pending") ||
			strings.Contains(repositoriesPage, "Recovery in progress")
		return len(statuses) == 0 &&
			strings.Contains(webhookPage, "synchronized") &&
			strings.Contains(webhookPage, ">verified</span>") &&
			strings.Contains(webhookPage, ">retryable failure</span>") &&
			strings.Contains(webhookPage, "webhook processing failed") &&
			!strings.Contains(webhookPage, "post forgejo commit status") &&
			strings.Contains(repositoriesPage, "Enforcement is unhealthy: status publication failed") &&
			strings.Contains(repositoriesPage, `action="/repositories/recover"`) &&
			recoveryVisible &&
			strings.Contains(publicationsPage, headSHA) &&
			strings.Contains(publicationsPage, ">failed</span>") &&
			strings.Contains(publicationsPage, "Branch is frozen; merge is blocked by Thawguard") &&
			strings.Contains(publicationsPage, "post forgejo commit status") &&
			strings.Contains(publicationsPage, "forge returned 401") &&
			strings.Contains(activityPage, ">Runtime convergence</td>") &&
			strings.Contains(activityPage, ">Failed</span>") &&
			strings.Contains(activityPage, "status publication failed; state unhealthy. Automatic recovery remains pending."), nil
	})
}

func requireTokenFailureSideEffects(t *testing.T, before, after webhookSideEffectEvidence) {
	t.Helper()
	if after.webhookRows != before.webhookRows+1 {
		t.Fatalf("token-loss webhook changed delivery rows by %d, want 1", after.webhookRows-before.webhookRows)
	}
	if after.statusResults != before.statusResults+1 {
		t.Fatalf("token-loss webhook changed status results by %d, want 1", after.statusResults-before.statusResults)
	}
	if after.publicationIntents != before.publicationIntents+1 {
		t.Fatalf("token-loss webhook changed publication intents by %d, want 1", after.publicationIntents-before.publicationIntents)
	}
	if after.publicationAttempts != before.publicationAttempts+1 {
		t.Fatalf("token-loss webhook changed publication attempts by %d, want 1", after.publicationAttempts-before.publicationAttempts)
	}
	if after.activityEvents != before.activityEvents+1 {
		t.Fatalf("token-loss webhook changed activity events by %d, want 1", after.activityEvents-before.activityEvents)
	}
	if len(after.freezeStatuses) != 0 {
		t.Fatalf("token-loss head has %d %s statuses, want none", len(after.freezeStatuses), requiredContext)
	}
}

func assertNoFreezeStatus(t *testing.T, ctx context.Context, forgejo *forgejoAPI, headSHA string) {
	t.Helper()
	statuses, err := listForgejoFreezeStatuses(ctx, forgejo, headSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 0 {
		t.Fatalf("new pull request head has %d %s statuses after token revocation, want none", len(statuses), requiredContext)
	}
}

func rotateStatusTokenAndRecover(t *testing.T, ctx context.Context, browser *thawguardBrowser, cfg e2eConfig, repositoryID int64) {
	t.Helper()
	repositoryValue := strconv.FormatInt(repositoryID, 10)
	page := requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(page, `action="/repositories/status-token"`) || !strings.Contains(page, `action="/repositories/recover"`) {
		t.Fatal("unhealthy repository did not offer status-token rotation and enforcement recovery")
	}
	csrf := requireHiddenInput(t, page, "csrf_token")
	rotatedPage, err := browser.postForm(ctx, "/repositories/status-token", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {repositoryValue},
		"status_token":  {cfg.replacementStatusToken},
	})
	if err != nil {
		t.Fatalf("rotate Forgejo status token through Thawguard: %v", err)
	}

	csrf = requireHiddenInput(t, rotatedPage, "csrf_token")
	response, err := browser.postFormResponse(ctx, "/repositories/recover", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {repositoryValue},
	})
	if err != nil {
		t.Fatalf("trigger Thawguard enforcement recovery: %v", err)
	}
	if response.statusCode == http.StatusOK {
		return
	}
	if response.statusCode == http.StatusBadRequest &&
		(bytes.Contains(response.body, []byte("Enforcement recovery is already in progress.")) ||
			bytes.Contains(response.body, []byte("Enforcement recovery is only available for an unhealthy repository."))) {
		return
	}
	t.Fatalf("trigger Thawguard enforcement recovery returned HTTP %d", response.statusCode)
}

func waitForRecoveredEnforcement(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, headSHA string) {
	t.Helper()
	waitFor(t, 45*time.Second, "manual or harmless worker-race enforcement recovery", func() (bool, error) {
		repositoriesPage, err := browser.get(ctx, "/repositories")
		if err != nil {
			return false, err
		}
		activityPage, err := browser.get(ctx, "/activity")
		if err != nil {
			return false, err
		}
		publicationsPage, err := browser.get(ctx, "/publications")
		if err != nil {
			return false, err
		}
		statuses, err := listForgejoFreezeStatuses(ctx, forgejo, headSHA)
		if err != nil {
			return false, err
		}
		statusRecovered := len(statuses) > 0 &&
			statuses[len(statuses)-1].Status == "failure" &&
			statuses[len(statuses)-1].Description == "Branch is frozen; merge is blocked by Thawguard"
		return statusRecovered &&
			strings.Contains(repositoriesPage, "enforcement active") &&
			!strings.Contains(repositoriesPage, "Enforcement is unhealthy") &&
			strings.Contains(activityPage, ">Status token configuration</td>") &&
			strings.Contains(activityPage, "Status token rotated; the value remains hidden.") &&
			strings.Contains(activityPage, ">Enforcement recovery</td>") &&
			strings.Contains(activityPage, ">Succeeded</span>") &&
			strings.Contains(activityPage, "1 open PRs evaluated; 1 statuses posted and 0 failed.") &&
			strings.Contains(activityPage, "status publication failed; state unhealthy. Automatic recovery remains pending.") &&
			strings.Contains(publicationsPage, headSHA) &&
			strings.Contains(publicationsPage, ">failed</span>") &&
			strings.Contains(publicationsPage, "post forgejo commit status") &&
			strings.Contains(publicationsPage, ">posted</span>"), nil
	})
}

func scanRenderedTokenSurfaces(t *testing.T, ctx context.Context, browser *thawguardBrowser) {
	t.Helper()
	for _, path := range []string{
		"/repositories",
		"/freezes",
		"/decisions",
		"/activity",
		"/webhooks",
		"/publications",
	} {
		_ = requirePage(t, ctx, browser, path)
	}
}

// syntheticPullRequestWebhookPayload is an in-memory E2E fixture sent by this
// test, not an event emitted by Forgejo. It contains only fields required for
// pull request parsing and processing and uses the disposable fictional repo.
func syntheticPullRequestWebhookPayload(t *testing.T, cfg e2eConfig, index int, headSHA string) []byte {
	t.Helper()
	payload := map[string]any{
		"action": "synchronized",
		"repository": map[string]any{
			"owner":     map[string]string{"login": fixtureOwner},
			"name":      fixtureRepository,
			"clone_url": cfg.forgejoURL + "/" + fixtureOwner + "/" + fixtureRepository + ".git",
		},
		"pull_request": map[string]any{
			"number":   index,
			"title":    "Fictional release check",
			"state":    "open",
			"html_url": cfg.forgejoURL + "/" + fixtureOwner + "/" + fixtureRepository + "/pulls/" + strconv.Itoa(index),
			"base":     map[string]string{"ref": "main"},
			"head":     map[string]string{"sha": headSHA},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode synthetic E2E webhook fixture: %v", err)
	}
	return body
}

func assertInvalidSignatureHasNoSideEffects(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, cfg e2eConfig, repositoryID int64, headSHA string, payload []byte) {
	t.Helper()
	before := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	if strings.Contains(before.webhookPage, invalidDeliveryID) {
		t.Fatalf("invalid-signature fixture delivery ID %q already exists", invalidDeliveryID)
	}

	response, err := postSyntheticWebhook(ctx, cfg, payload, invalidDeliveryID, "invalid-e2e-signing-secret")
	requireAcceptedWebhookResponse(t, response, err, "invalid-signature fixture")

	after := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	if strings.Contains(after.webhookPage, invalidDeliveryID) {
		t.Fatalf("invalid-signature fixture delivery ID %q was recorded", invalidDeliveryID)
	}
	requireIdenticalWebhookEvidence(t, before, after, "invalid-signature fixture")
}

func assertDuplicateDeliveryIsIdempotent(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, cfg e2eConfig, repositoryID int64, headSHA string, payload []byte) {
	t.Helper()
	before := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	if strings.Contains(before.webhookPage, duplicateDeliveryID) {
		t.Fatalf("duplicate fixture delivery ID %q already exists", duplicateDeliveryID)
	}

	response, err := postSyntheticWebhook(ctx, cfg, payload, duplicateDeliveryID, cfg.webhookSecret)
	requireAcceptedWebhookResponse(t, response, err, "first duplicate fixture request")
	afterFirst := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	requireProcessedVerifiedDelivery(t, afterFirst.webhookPage, duplicateDeliveryID)
	if afterFirst.webhookRows != before.webhookRows+1 {
		t.Fatalf("first duplicate fixture request changed webhook rows by %d, want 1", afterFirst.webhookRows-before.webhookRows)
	}
	if afterFirst.statusResults != before.statusResults+1 {
		t.Fatalf("first duplicate fixture request changed status results by %d, want 1", afterFirst.statusResults-before.statusResults)
	}
	if afterFirst.publicationIntents != before.publicationIntents {
		t.Fatalf("first duplicate fixture request changed idempotent publication intent count from %d to %d", before.publicationIntents, afterFirst.publicationIntents)
	}
	if afterFirst.publicationAttempts != before.publicationAttempts+1 {
		t.Fatalf("first duplicate fixture request changed publication attempts by %d, want 1", afterFirst.publicationAttempts-before.publicationAttempts)
	}
	if afterFirst.activityEvents != before.activityEvents {
		t.Fatalf("first duplicate fixture request unexpectedly changed activity events from %d to %d", before.activityEvents, afterFirst.activityEvents)
	}
	if len(afterFirst.freezeStatuses) != len(before.freezeStatuses)+1 {
		t.Fatalf("first duplicate fixture request changed Forgejo freeze statuses by %d, want 1", len(afterFirst.freezeStatuses)-len(before.freezeStatuses))
	}
	if latest := afterFirst.freezeStatuses[len(afterFirst.freezeStatuses)-1]; latest.Status != "failure" {
		t.Fatalf("first duplicate fixture request posted latest %s=%q, want failure", requiredContext, latest.Status)
	}

	response, err = postSyntheticWebhook(ctx, cfg, payload, duplicateDeliveryID, cfg.webhookSecret)
	requireAcceptedWebhookResponse(t, response, err, "second duplicate fixture request")
	afterSecond := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	requireProcessedVerifiedDelivery(t, afterSecond.webhookPage, duplicateDeliveryID)
	requireIdenticalWebhookEvidence(t, afterFirst, afterSecond, "second duplicate fixture request")
}

func postSyntheticWebhook(ctx context.Context, cfg e2eConfig, payload []byte, deliveryID, signingSecret string) (apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.thawguardURL+"/webhooks/forgejo", bytes.NewReader(payload))
	if err != nil {
		return apiResponse{}, fmt.Errorf("create synthetic E2E webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forgejo-Event", "pull_request")
	req.Header.Set("X-Forgejo-Delivery", deliveryID)
	req.Header.Set("X-Forgejo-Signature", syntheticWebhookSignature(payload, signingSecret))
	resp, err := newScanningHTTPClient(10*time.Second, "Thawguard webhook", cfg.sensitiveValues()).Do(req)
	if err != nil {
		return apiResponse{}, fmt.Errorf("send synthetic E2E webhook request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return apiResponse{}, fmt.Errorf("read synthetic E2E webhook response: %w", err)
	}
	return apiResponse{statusCode: resp.StatusCode, body: body}, nil
}

func syntheticWebhookSignature(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func requireAcceptedWebhookResponse(t *testing.T, response apiResponse, err error, operation string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
	if response.statusCode != http.StatusAccepted || string(response.body) != "accepted\n" {
		t.Fatalf("%s did not return the generic accepted response (status=%d)", operation, response.statusCode)
	}
}

func collectWebhookSideEffectEvidence(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, headSHA string) webhookSideEffectEvidence {
	t.Helper()
	webhookPath := "/webhooks?" + url.Values{
		"repository_id": {strconv.FormatInt(repositoryID, 10)},
		"event":         {"pull_request"},
		"limit":         {"100"},
	}.Encode()
	webhookPage := requirePage(t, ctx, browser, webhookPath)
	decisionsPage := requirePage(t, ctx, browser, "/decisions")
	publicationsPage := requirePage(t, ctx, browser, "/publications")
	activityPage := requirePage(t, ctx, browser, "/activity")
	statuses, err := listForgejoFreezeStatuses(ctx, forgejo, headSHA)
	if err != nil {
		t.Fatal(err)
	}
	return webhookSideEffectEvidence{
		webhookPage:         webhookPage,
		webhookRows:         requirePageCount(t, webhookPage, webhookRowsPattern, "webhook rows"),
		statusResults:       requirePageCount(t, decisionsPage, statusResultsPattern, "status results"),
		publicationIntents:  requirePageCount(t, publicationsPage, publicationIntentsPattern, "publication intents"),
		publicationAttempts: requirePageCount(t, publicationsPage, publicationAttemptsPattern, "publication attempts"),
		activityEvents:      requirePageCount(t, activityPage, activityEventsPattern, "activity events"),
		freezeStatuses:      statuses,
	}
}

func requirePageCount(t *testing.T, page string, pattern *regexp.Regexp, label string) int {
	t.Helper()
	match := pattern.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("could not read %s count from rendered page", label)
	}
	count, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("parse %s count: %v", label, err)
	}
	return count
}

func listForgejoFreezeStatuses(ctx context.Context, forgejo *forgejoAPI, headSHA string) ([]commitStatus, error) {
	response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("commits", headSHA, "statuses"), nil)
	if err != nil {
		return nil, err
	}
	if response.statusCode != http.StatusOK {
		return nil, apiStatusError(response, "list Forgejo commit statuses")
	}
	var statuses []commitStatus
	if err := json.Unmarshal(response.body, &statuses); err != nil {
		return nil, fmt.Errorf("decode Forgejo commit statuses: %w", err)
	}
	filtered := statuses[:0]
	for _, status := range statuses {
		if status.Context == requiredContext {
			filtered = append(filtered, status)
		}
	}
	slices.SortFunc(filtered, func(a, b commitStatus) int { return cmp.Compare(a.ID, b.ID) })
	return filtered, nil
}

func requireProcessedVerifiedDelivery(t *testing.T, page, deliveryID string) {
	t.Helper()
	marker := ">" + html.EscapeString(deliveryID) + "</code>"
	if count := strings.Count(page, marker); count != 2 {
		t.Fatalf("delivery ID %q rendered %d times, want one desktop row and one mobile card", deliveryID, count)
	}
	markerIndex := strings.Index(page, marker)
	rowStart := strings.LastIndex(page[:markerIndex], `<tr id="delivery-`)
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("delivery ID %q is missing its desktop row", deliveryID)
	}
	row := page[rowStart : markerIndex+rowEndOffset]
	if !strings.Contains(row, ">verified</span>") || !strings.Contains(row, ">processed</span>") {
		t.Fatalf("delivery ID %q is not rendered as verified and processed", deliveryID)
	}
}

func countOpenPullRequestSyncEvents(page string) int {
	return strings.Count(page, `<td data-label="Action">Open pull request sync</td>`)
}

func waitForOneNewOpenPullRequestSync(t *testing.T, ctx context.Context, browser *thawguardBrowser, before int) string {
	t.Helper()
	expected := before + 1
	var activityPage string
	waitFor(t, 30*time.Second, "one new open pull request sync activity event", func() (bool, error) {
		page, err := browser.get(ctx, "/activity")
		if err != nil {
			return false, err
		}
		activityPage = page
		return countOpenPullRequestSyncEvents(page) >= expected, nil
	})
	if actual := countOpenPullRequestSyncEvents(activityPage); actual != expected {
		t.Fatalf("open pull request sync activity events changed from %d to %d, want exactly %d", before, actual, expected)
	}
	return activityPage
}

func requireLatestOpenPullRequestSync(t *testing.T, page string) {
	t.Helper()
	marker := `<td data-label="Action">Open pull request sync</td>`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatal("activity is missing an open pull request sync event")
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr>")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatal("latest open pull request sync event is missing its activity row")
	}
	row := page[rowStart : markerIndex+rowEndOffset]
	if !strings.Contains(row, "1 open PRs synchronized; 0 cached PRs marked closed.") {
		t.Fatal("latest forge sync did not confirm one real PR and zero invalid-signature cache entries")
	}
}

func requireIdenticalWebhookEvidence(t *testing.T, before, after webhookSideEffectEvidence, operation string) {
	t.Helper()
	if before.webhookRows != after.webhookRows ||
		before.statusResults != after.statusResults ||
		before.publicationIntents != after.publicationIntents ||
		before.publicationAttempts != after.publicationAttempts ||
		before.activityEvents != after.activityEvents ||
		!slices.Equal(before.freezeStatuses, after.freezeStatuses) {
		t.Fatalf("%s changed side-effect evidence: webhook rows %d→%d, status results %d→%d, publication intents %d→%d, publication attempts %d→%d, activity events %d→%d, Forgejo freeze statuses %d→%d",
			operation,
			before.webhookRows, after.webhookRows,
			before.statusResults, after.statusResults,
			before.publicationIntents, after.publicationIntents,
			before.publicationAttempts, after.publicationAttempts,
			before.activityEvents, after.activityEvents,
			len(before.freezeStatuses), len(after.freezeStatuses))
	}
}

func activateEnforcement(t *testing.T, ctx context.Context, browser *thawguardBrowser, repositoryID int64) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/repositories")
	csrf := requireHiddenInput(t, page, "csrf_token")
	repositoryValue := strconv.FormatInt(repositoryID, 10)
	requirePostForm(t, ctx, browser, "/repositories/setup-check", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {repositoryValue},
	}, "run Thawguard readiness checks")

	page = requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(page, `action="/repositories/status-verification"`) {
		t.Fatal("status-post verification was not offered after readiness checks")
	}
	csrf = requireHiddenInput(t, page, "csrf_token")
	requirePostForm(t, ctx, browser, "/repositories/status-verification", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {repositoryValue},
	}, "verify Thawguard status posting")

	page = requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(page, `action="/repositories/activate"`) {
		t.Fatal("enforcement activation was not offered after status verification")
	}
	csrf = requireHiddenInput(t, page, "csrf_token")
	requirePostForm(t, ctx, browser, "/repositories/activate", url.Values{
		"csrf_token":    {csrf},
		"repository_id": {repositoryValue},
	}, "activate Thawguard enforcement")
	page = requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(page, "enforcement active") {
		t.Fatal("repository did not reach enforcement-active state")
	}
}

func createFreeze(t *testing.T, ctx context.Context, browser *thawguardBrowser, repositoryID int64) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/freezes")
	csrf := requireHiddenInput(t, page, "csrf_token")
	requirePostForm(t, ctx, browser, "/freezes", url.Values{
		"csrf_token":              {csrf},
		"repository_id":           {strconv.FormatInt(repositoryID, 10)},
		"branch":                  {"main"},
		"reason":                  {"Fictional release verification"},
		"timezone_offset_minutes": {"0"},
	}, "create Thawguard freeze")
}

func liftFreeze(t *testing.T, ctx context.Context, browser *thawguardBrowser) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/freezes")
	csrf := requireHiddenInput(t, page, "csrf_token")
	freezeID := requireHiddenInput(t, page, "freeze_id")
	requirePostForm(t, ctx, browser, "/freezes/end", url.Values{
		"csrf_token": {csrf},
		"freeze_id":  {freezeID},
	}, "lift Thawguard freeze")
}

func waitForStatusWithDescription(t *testing.T, ctx context.Context, forgejo *forgejoAPI, sha, expected, description string) {
	t.Helper()
	waitFor(t, 30*time.Second, requiredContext+"="+expected+" with sanitized description", func() (bool, error) {
		statuses, err := listForgejoFreezeStatuses(ctx, forgejo, sha)
		if err != nil {
			return false, err
		}
		if len(statuses) == 0 {
			return false, nil
		}
		latest := statuses[len(statuses)-1]
		return latest.Status == expected && latest.Description == description, nil
	})
}

func assertMergeBlockedByRequiredStatus(t *testing.T, ctx context.Context, forgejo *forgejoAPI, index int) {
	t.Helper()
	waitFor(t, 30*time.Second, "Forgejo required-status merge-block convergence", func() (bool, error) {
		response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("pulls", strconv.Itoa(index), "merge"), map[string]string{"Do": "merge"})
		if err != nil {
			return false, nil
		}
		if response.statusCode >= 200 && response.statusCode < 300 {
			t.Fatal("Forgejo merge unexpectedly succeeded while required status was unsatisfied")
		}
		if response.statusCode != http.StatusMethodNotAllowed {
			t.Fatalf("unexpected HTTP %d while waiting for Forgejo required-status merge block", response.statusCode)
		}

		var payload struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(response.body, &payload) != nil {
			return false, nil
		}
		message := strings.ToLower(payload.Message)
		return strings.Contains(message, "required status checks") &&
			(strings.Contains(message, "not all") || strings.Contains(message, "not successful") || strings.Contains(message, "unsuccessful")), nil
	})
}

func (f *forgejoAPI) repositoryPath(parts ...string) string {
	segments := []string{"api", "v1", "repos", fixtureOwner, fixtureRepository}
	segments = append(segments, parts...)
	return "/" + strings.Join(segments, "/")
}

func (f *forgejoAPI) do(ctx context.Context, method, path string, payload any) (apiResponse, error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return apiResponse{}, fmt.Errorf("encode Forgejo request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, f.baseURL+path, body)
	if err != nil {
		return apiResponse{}, fmt.Errorf("create Forgejo request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "token "+f.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return apiResponse{}, fmt.Errorf("send Forgejo request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return apiResponse{}, fmt.Errorf("read Forgejo response: %w", err)
	}
	return apiResponse{statusCode: resp.StatusCode, body: data}, nil
}

func (f *forgejoAPI) doBasicAuth(ctx context.Context, method, path, username, password string) (apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, f.baseURL+path, nil)
	if err != nil {
		return apiResponse{}, fmt.Errorf("create Forgejo basic-auth request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(username, password)
	resp, err := f.client.Do(req)
	if err != nil {
		return apiResponse{}, fmt.Errorf("send Forgejo basic-auth request: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return apiResponse{}, fmt.Errorf("read Forgejo basic-auth response: %w", err)
	}
	return apiResponse{statusCode: resp.StatusCode, body: data}, nil
}

type scanningTransport struct {
	surface         string
	sensitiveValues []string
}

func (transport scanningTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	for _, location := range response.Header.Values("Location") {
		if containsSensitiveValue([]byte(location), transport.sensitiveValues) {
			_ = response.Body.Close()
			return nil, fmt.Errorf("sensitive token detected in %s redirect location", transport.surface)
		}
	}
	const maxScannedResponseBytes = 2 << 20
	data, err := io.ReadAll(io.LimitReader(response.Body, maxScannedResponseBytes+1))
	closeErr := response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("scan %s response body: %w", transport.surface, err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s response body after scan: %w", transport.surface, closeErr)
	}
	if len(data) > maxScannedResponseBytes {
		return nil, fmt.Errorf("%s response body exceeds the redaction scan limit", transport.surface)
	}
	if containsSensitiveValue(data, transport.sensitiveValues) {
		return nil, fmt.Errorf("sensitive token detected in %s response body", transport.surface)
	}
	response.Body = io.NopCloser(bytes.NewReader(data))
	response.ContentLength = int64(len(data))
	return response, nil
}

func containsSensitiveValue(data []byte, sensitiveValues []string) bool {
	for _, sensitive := range sensitiveValues {
		if sensitive = strings.TrimSpace(sensitive); sensitive != "" && bytes.Contains(data, []byte(sensitive)) {
			return true
		}
	}
	return false
}

func newScanningHTTPClient(timeout time.Duration, surface string, sensitiveValues []string) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: scanningTransport{
			surface:         surface,
			sensitiveValues: append([]string(nil), sensitiveValues...),
		},
	}
}

func newThawguardBrowser(t *testing.T, baseURL string, sensitiveValues []string) *thawguardBrowser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := newScanningHTTPClient(20*time.Second, "Thawguard HTTP", sensitiveValues)
	client.Jar = jar
	return &thawguardBrowser{
		baseURL: baseURL,
		client:  client,
	}
}

func (b *thawguardBrowser) get(ctx context.Context, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+path, nil)
	if err != nil {
		return "", err
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s returned %s", path, resp.Status)
	}
	return string(body), nil
}

func (b *thawguardBrowser) postForm(ctx context.Context, path string, values url.Values) (string, error) {
	response, err := b.postFormResponse(ctx, path, values)
	if err != nil {
		return "", err
	}
	if response.statusCode < 200 || response.statusCode >= 300 {
		return "", fmt.Errorf("POST %s returned HTTP %d", path, response.statusCode)
	}
	return string(response.body), nil
}

func (b *thawguardBrowser) postFormResponse(ctx context.Context, path string, values url.Values) (apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return apiResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.baseURL)
	resp, err := b.client.Do(req)
	if err != nil {
		return apiResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return apiResponse{}, err
	}
	return apiResponse{statusCode: resp.StatusCode, body: body}, nil
}

func requirePostForm(t *testing.T, ctx context.Context, browser *thawguardBrowser, path string, values url.Values, operation string) {
	t.Helper()
	_, err := browser.postForm(ctx, path, values)
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}

func requirePage(t *testing.T, ctx context.Context, browser *thawguardBrowser, path string) string {
	t.Helper()
	page, err := browser.get(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return page
}

func requireHiddenInput(t *testing.T, page, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`(?i)<input\b[^>]*\bname="` + regexp.QuoteMeta(name) + `"[^>]*\bvalue="([^"]*)"`)
	match := pattern.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatalf("page is missing hidden input %q", name)
	}
	return html.UnescapeString(match[1])
}

var (
	nonzeroMatchingRows        = regexp.MustCompile(`Showing [1-9][0-9]* of [1-9][0-9]* matching rows`)
	webhookRowsPattern         = regexp.MustCompile(`Showing ([0-9]+) of [0-9]+ matching rows`)
	statusResultsPattern       = regexp.MustCompile(`Thaw approval results</h2><span[^>]*>([0-9]+) status results</span>`)
	publicationIntentsPattern  = regexp.MustCompile(`Latest desired statuses</h2><span[^>]*>([0-9]+) shown</span>`)
	publicationAttemptsPattern = regexp.MustCompile(`Recent publication attempts</h2><span[^>]*>([0-9]+) shown</span>`)
	activityEventsPattern      = regexp.MustCompile(`Recent activity</h2><span[^>]*>([0-9]+) shown</span>`)
)

func requireAPIStatus(t *testing.T, response apiResponse, err error, expected int, operation string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
	if response.statusCode != expected {
		t.Fatalf("%s: %v", operation, apiStatusError(response, operation))
	}
}

func apiStatusError(response apiResponse, operation string) error {
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.body, &payload); err == nil && strings.TrimSpace(payload.Message) != "" {
		return fmt.Errorf("%s returned HTTP %d: %s", operation, response.statusCode, payload.Message)
	}
	return fmt.Errorf("%s returned HTTP %d", operation, response.statusCode)
}

func decodeJSON(t *testing.T, data []byte, target any, operation string) {
	t.Helper()
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
}

func waitFor(t *testing.T, timeout time.Duration, description string, check func() (bool, error)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ok, err := check()
		if ok {
			return
		}
		if err != nil {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		t.Fatalf("timed out waiting for %s: %v", description, lastErr)
	}
	t.Fatalf("timed out waiting for %s", description)
}
