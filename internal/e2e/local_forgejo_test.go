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
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	fixtureOwner             = "e2e-owner"
	fixtureRepository        = "icebox-demo"
	fixtureReleaseBranch     = "release"
	fixtureFeatureBranch     = "feature/freeze-check"
	fixtureSharedHeadBranch  = "shared-head-confirmation"
	fixturePrimaryPRTitle    = "Fictional release check"
	fixtureSharedHeadPRTitle = "Fictional shared-head confirmation"
	primaryStatusTokenName   = "thawguard-e2e-status-primary"
	requiredContext          = "thawguard/freeze"
	e2eComposeProject        = "thawguard-e2e"
	injectedDriftDescription = "E2E injected status drift while Thawguard was stopped"
	invalidDeliveryID        = "e2e-invalid-signature-fixture"
	duplicateDeliveryID      = "e2e-duplicate-delivery-fixture"
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
	thawguardSecretKey     string
	composeProject         string
	repositoryRoot         string
}

type forgejoAPI struct {
	baseURL string
	token   string
	client  *http.Client
}

type apiResponse struct {
	statusCode int
	body       []byte
	location   string
}

type thawguardBrowser struct {
	baseURL string
	client  *http.Client
}

type pullRequest struct {
	Number  int    `json:"number"`
	Title   string `json:"title"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	Base    struct {
		Ref string `json:"ref"`
	} `json:"base"`
	Head struct {
		SHA string `json:"sha"`
	} `json:"head"`
}

type forgejoBranch struct {
	Name   string `json:"name"`
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
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

type activeFreezeEvidence struct {
	id     int64
	branch string
	reason string
	status string
}

func TestLocalForgejoFreezeLifecycle(t *testing.T) {
	if os.Getenv("THAWGUARD_E2E") != "1" {
		t.Skip("set THAWGUARD_E2E=1 and use make e2e")
	}
	cfg := loadConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	pr := createForgejoPullRequest(t, ctx, forgejo, fixtureFeatureBranch, fixturePrimaryPRTitle)

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

	requireUnprotectedReleaseReadinessFailure(t, ctx, browser, repositoryID)
	createForgejoBranchProtection(t, ctx, forgejo, fixtureReleaseBranch)
	activateEnforcement(t, ctx, browser, repositoryID)
	requireRepairedReleaseReadiness(t, ctx, browser)
	firstFreeze := createFreeze(t, ctx, browser, repositoryID, "Fictional release verification")
	waitForStatusWithDescription(t, ctx, forgejo, pr.Head.SHA, "failure", "Branch is frozen; merge is blocked by Thawguard")
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pr.Number)
	proveRestartPersistenceAndReconciliation(t, ctx, forgejo, browser, cfg, repositoryID, pr)

	beforeTokenFailure := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, pr.Head.SHA)
	revokePrimaryStatusToken(t, ctx, forgejo, cfg.forgejoOwnerPassword)
	newHeadSHA := advanceFeatureBranch(
		t,
		ctx,
		forgejo,
		pr.Number,
		pr.Head.SHA,
		"token-loss.txt",
		"Advance fictional E2E feature head",
		"new head for token-loss recovery proof\n",
		"token-loss",
	)
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

	liftFreeze(t, ctx, browser, firstFreeze)
	waitForStatusWithDescription(t, ctx, forgejo, newHeadSHA, "success", "No active freeze applies to this PR")
	activityPage := waitForOneNewOpenPullRequestSync(t, ctx, browser, openPullRequestSyncsBeforeProbes)
	requireLatestOpenPullRequestSync(t, activityPage, 1)
	scanRenderedTokenSurfaces(t, ctx, browser)

	proveActiveFreezeCancellation(t, ctx, forgejo, browser, repositoryID, pr.Number, newHeadSHA, firstFreeze)
	scanRenderedTokenSurfaces(t, ctx, browser)
	proveImmediatePerPullRequestThaw(t, ctx, forgejo, browser, repositoryID, pr.Number, newHeadSHA)
	historicalThawedHeadSHA := newHeadSHA
	newHeadSHA = proveStaleHeadThawReevaluation(t, ctx, forgejo, browser, repositoryID, pr.Number, newHeadSHA)
	scanRenderedTokenSurfaces(t, ctx, browser)
	proveSharedHeadConfirmation(t, ctx, forgejo, browser, repositoryID, pr.Number, historicalThawedHeadSHA, newHeadSHA)
	scanRenderedTokenSurfaces(t, ctx, browser)
}

func proveActiveFreezeCancellation(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, pullRequestIndex int, headSHA string, firstFreeze activeFreezeEvidence) {
	t.Helper()
	const cancellationReason = "Fictional cancellation verification."

	requireNoActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"), firstFreeze)
	firstLiftRow := requireLatestActivityRow(t, requirePage(t, ctx, browser, "/activity"), "Branch freeze")
	requireBranchFreezeActivityEvidence(t, firstLiftRow, firstFreeze, "Lifted", "ok")

	secondFreeze := createFreeze(t, ctx, browser, repositoryID, cancellationReason)
	if secondFreeze.id == firstFreeze.id {
		t.Fatalf("second freeze reused lifted freeze ID %d", secondFreeze.id)
	}
	if secondFreeze.reason == firstFreeze.reason {
		t.Fatalf("second freeze reason %q did not remain distinct from lifted freeze", secondFreeze.reason)
	}
	waitForStatusWithDescription(t, ctx, forgejo, headSHA, "failure", "Branch is frozen; merge is blocked by Thawguard")
	waitForLatestPostedPublicationAttempt(t, ctx, browser, headSHA, "failure", "Branch is frozen; merge is blocked by Thawguard")
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pullRequestIndex)

	if active := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); active != secondFreeze {
		t.Fatalf("second active freeze changed before cancellation: created=%+v rendered=%+v", secondFreeze, active)
	}
	activityBefore := requirePage(t, ctx, browser, "/activity")
	createdRow := requireLatestActivityRow(t, activityBefore, "Branch freeze")
	requireBranchFreezeActivityEvidence(t, createdRow, secondFreeze, "Frozen", "frozen")
	before := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	if len(before.freezeStatuses) == 0 {
		t.Fatal("second active freeze is missing its pre-cancel Forgejo status")
	}
	latestBefore := before.freezeStatuses[len(before.freezeStatuses)-1]
	if latestBefore.Context != requiredContext || latestBefore.Status != "failure" || latestBefore.Description != "Branch is frozen; merge is blocked by Thawguard" {
		t.Fatalf("unexpected pre-cancel required status: id=%d context=%q state=%q description=%q", latestBefore.ID, latestBefore.Context, latestBefore.Status, latestBefore.Description)
	}

	cancelFreeze(t, ctx, browser, secondFreeze)
	waitForStatusWithDescription(t, ctx, forgejo, headSHA, "success", "No active freeze applies to this PR")
	waitForLatestPostedPublicationAttempt(t, ctx, browser, headSHA, "success", "No active freeze applies to this PR")
	requireNoActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"), secondFreeze)

	activityAfter := requirePage(t, ctx, browser, "/activity")
	cancelledRow := requireLatestActivityRow(t, activityAfter, "Branch freeze")
	requireBranchFreezeActivityEvidence(t, cancelledRow, secondFreeze, "Cancelled", "warning")
	if strings.Contains(cancelledRow, ">Lifted</span>") || strings.Contains(cancelledRow, firstFreeze.reason) {
		t.Fatal("cancelled branch-freeze activity was confused with the earlier lifted freeze")
	}
	if cancelledRow == firstLiftRow || !strings.Contains(activityAfter, firstLiftRow) {
		t.Fatal("cancelled branch-freeze activity did not remain distinct from the preserved Lift event")
	}

	after := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	if after.webhookRows != before.webhookRows {
		t.Fatalf("active freeze cancellation changed webhook rows from %d to %d", before.webhookRows, after.webhookRows)
	}
	if after.publicationIntents != before.publicationIntents {
		t.Fatalf("active freeze cancellation changed publication intents from %d to %d, want existing intent reused", before.publicationIntents, after.publicationIntents)
	}
	if after.publicationAttempts != before.publicationAttempts+1 {
		t.Fatalf("active freeze cancellation changed publication attempts by %d, want 1", after.publicationAttempts-before.publicationAttempts)
	}
	if len(after.freezeStatuses) != len(before.freezeStatuses)+1 {
		t.Fatalf("active freeze cancellation changed Forgejo required-context statuses by %d, want 1", len(after.freezeStatuses)-len(before.freezeStatuses))
	}
	latestAfter := after.freezeStatuses[len(after.freezeStatuses)-1]
	if latestAfter.ID <= latestBefore.ID || latestAfter.Context != requiredContext || latestAfter.Status != "success" || latestAfter.Description != "No active freeze applies to this PR" {
		t.Fatalf("unexpected post-cancel required status: id=%d context=%q state=%q description=%q", latestAfter.ID, latestAfter.Context, latestAfter.Status, latestAfter.Description)
	}

}

func proveImmediatePerPullRequestThaw(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, pullRequestIndex int, headSHA string) {
	t.Helper()
	const (
		freezeReason = "Fictional per-PR thaw verification."
		thawReason   = "Fictional immediate per-PR thaw verification"
		frozenReason = "Branch is frozen; merge is blocked by Thawguard"
		explicitThaw = "PR is explicitly thawed during an active freeze"
	)
	if len(headSHA) < 12 {
		t.Fatalf("current pull request head %q is too short for activity evidence", headSHA)
	}

	thirdFreeze := createFreeze(t, ctx, browser, repositoryID, freezeReason)
	waitForStatusWithDescription(t, ctx, forgejo, headSHA, "failure", frozenReason)
	waitForLatestPostedPublicationAttempt(t, ctx, browser, headSHA, "failure", frozenReason)
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pullRequestIndex)
	if active := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); active != thirdFreeze {
		t.Fatalf("third active freeze changed before immediate thaw: created=%+v rendered=%+v", thirdFreeze, active)
	}

	before := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)
	if len(before.freezeStatuses) == 0 {
		t.Fatal("third active freeze is missing its pre-thaw Forgejo status")
	}
	latestBefore := before.freezeStatuses[len(before.freezeStatuses)-1]
	if latestBefore.Context != requiredContext || latestBefore.Status != "failure" || latestBefore.Description != frozenReason {
		t.Fatalf("unexpected pre-thaw required status: id=%d context=%q state=%q description=%q", latestBefore.ID, latestBefore.Context, latestBefore.Status, latestBefore.Description)
	}
	openPullRequestSyncsBefore := countOpenPullRequestSyncEvents(requirePage(t, ctx, browser, "/activity"))

	decisionsPage := requirePage(t, ctx, browser, "/decisions")
	thawFormMarker := `<form method="post" action="/decisions" class="tg-setup-form tg-thaw-form" data-thaw-form>`
	thawFormStart := strings.Index(decisionsPage, thawFormMarker)
	if thawFormStart < 0 {
		t.Fatal("decisions page is missing the immediate thaw form")
	}
	thawFormEnd := strings.Index(decisionsPage[thawFormStart:], "</form>")
	if thawFormEnd < 0 {
		t.Fatal("immediate thaw form is incomplete")
	}
	renderedThawForm := decisionsPage[thawFormStart : thawFormStart+thawFormEnd+len("</form>")]
	if strings.Contains(renderedThawForm, `name="head_sha"`) {
		t.Fatal("immediate thaw form must not submit a client-provided head SHA")
	}
	form := url.Values{
		"csrf_token":         {requireHiddenInput(t, decisionsPage, "csrf_token")},
		"repository_id":      {strconv.FormatInt(repositoryID, 10)},
		"pull_request_index": {strconv.Itoa(pullRequestIndex)},
		"target_branch":      {"main"},
		"reason":             {thawReason},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, browser.baseURL+"/decisions", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", browser.baseURL)
	client := *browser.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("submit immediate per-PR thaw: %v", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	response.Body.Close()
	if readErr != nil {
		t.Fatalf("read immediate per-PR thaw response: %v", readErr)
	}
	if response.StatusCode == http.StatusConflict || bytes.Contains(responseBody, []byte("These pull requests share one commit SHA")) {
		t.Fatal("unique-head immediate thaw unexpectedly required shared-head confirmation")
	}
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/decisions" {
		t.Fatalf("immediate per-PR thaw returned HTTP %d with Location %q, want 303 to /decisions", response.StatusCode, response.Header.Get("Location"))
	}

	waitForStatusWithDescription(t, ctx, forgejo, headSHA, "success", explicitThaw)
	waitForLatestPostedPublicationAttempt(t, ctx, browser, headSHA, "success", explicitThaw)
	activityPage := waitForOneNewOpenPullRequestSync(t, ctx, browser, openPullRequestSyncsBefore)
	requireLatestOpenPullRequestSync(t, activityPage, 1)
	after := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, headSHA)

	if after.webhookRows != before.webhookRows {
		t.Fatalf("immediate per-PR thaw changed webhook rows from %d to %d", before.webhookRows, after.webhookRows)
	}
	if after.statusResults != before.statusResults+1 {
		t.Fatalf("immediate per-PR thaw changed status results by %d, want 1", after.statusResults-before.statusResults)
	}
	if after.publicationIntents != before.publicationIntents {
		t.Fatalf("immediate per-PR thaw changed publication intents from %d to %d, want existing intent reused", before.publicationIntents, after.publicationIntents)
	}
	if after.publicationAttempts != before.publicationAttempts+1 {
		t.Fatalf("immediate per-PR thaw changed publication attempts by %d, want 1", after.publicationAttempts-before.publicationAttempts)
	}
	if len(after.freezeStatuses) != len(before.freezeStatuses)+1 {
		t.Fatalf("immediate per-PR thaw changed Forgejo required-context statuses by %d, want 1", len(after.freezeStatuses)-len(before.freezeStatuses))
	}
	if after.activityEvents != before.activityEvents+2 {
		t.Fatalf("immediate per-PR thaw changed activity events by %d, want one sync and one approval", after.activityEvents-before.activityEvents)
	}
	latestAfter := after.freezeStatuses[len(after.freezeStatuses)-1]
	if latestAfter.ID <= latestBefore.ID || latestAfter.Context != requiredContext || latestAfter.Status != "success" || latestAfter.Description != explicitThaw {
		t.Fatalf("unexpected post-thaw required status: id=%d context=%q state=%q description=%q", latestAfter.ID, latestAfter.Context, latestAfter.Status, latestAfter.Description)
	}

	decisionRow := requireLatestDecisionResultRow(t, requirePage(t, ctx, browser, "/decisions"))
	for _, want := range []string{
		`<a href="#">#` + strconv.Itoa(pullRequestIndex) + `</a>`,
		`<code>` + fixtureOwner + `/` + fixtureRepository + `</code>`,
		`<code class="tg-branch">main</code>`,
		`<code>` + headSHA + `</code>`,
		explicitThaw,
		`<code>` + requiredContext + `</code>`,
		`<span class="status status-success">Eligible</span>`,
	} {
		if !strings.Contains(decisionRow, want) {
			t.Fatalf("latest immediate-thaw decision row is missing %q", want)
		}
	}

	thawActivityRow := requireLatestActivityRow(t, activityPage, "Single-PR thaw")
	for _, want := range []string{
		`<td data-label="Actor">E2E Admin</td>`,
		`<td data-label="Target">` + fixtureOwner + `/` + fixtureRepository + ` → PR #` + strconv.Itoa(pullRequestIndex) + `</td>`,
		`<td data-label="Outcome"><span class="status status-ok">Approved</span></td>`,
		`<td data-label="Details">Branch main; head ` + strings.ToLower(headSHA[:12]) + `. Reason: ` + thawReason + `.</td>`,
	} {
		if !strings.Contains(thawActivityRow, want) {
			t.Fatalf("latest Single-PR thaw activity row is missing %q", want)
		}
	}

	if active := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); active != thirdFreeze {
		t.Fatalf("third active freeze changed after immediate thaw: created=%+v rendered=%+v", thirdFreeze, active)
	}
}

func proveStaleHeadThawReevaluation(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, pullRequestIndex int, headSHA string) string {
	t.Helper()
	const (
		freezeReason = "Fictional per-PR thaw verification."
		frozenReason = "Branch is frozen; merge is blocked by Thawguard"
		explicitThaw = "PR is explicitly thawed during an active freeze"
	)

	oldHeadSHA := strings.ToLower(strings.TrimSpace(headSHA))
	if len(oldHeadSHA) < 12 {
		t.Fatalf("thawed pull request head %q is too short for stale-head evidence", headSHA)
	}

	before := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, oldHeadSHA)
	oldStatuses := slices.Clone(before.freezeStatuses)
	if len(oldStatuses) == 0 {
		t.Fatal("thawed head is missing its explicit-thaw Forgejo status")
	}
	oldLatest := oldStatuses[len(oldStatuses)-1]
	if oldLatest.Context != requiredContext || oldLatest.Status != "success" || oldLatest.Description != explicitThaw {
		t.Fatalf("unexpected stale-head pre-advance status: id=%d context=%q state=%q description=%q", oldLatest.ID, oldLatest.Context, oldLatest.Status, oldLatest.Description)
	}

	decisionsBefore := requirePage(t, ctx, browser, "/decisions")
	oldDecisionRow := requireLatestDecisionResultRow(t, decisionsBefore)
	for _, want := range []string{
		`<a href="#">#` + strconv.Itoa(pullRequestIndex) + `</a>`,
		`<code>` + fixtureOwner + `/` + fixtureRepository + `</code>`,
		`<code class="tg-branch">main</code>`,
		`<code>` + oldHeadSHA + `</code>`,
		explicitThaw,
		`<code>` + requiredContext + `</code>`,
		`<span class="status status-success">Eligible</span>`,
	} {
		if !strings.Contains(oldDecisionRow, want) {
			t.Fatalf("old exact-head decision row is missing %q", want)
		}
	}

	activityBefore := requirePage(t, ctx, browser, "/activity")
	oldThawActivityRow := requireLatestActivityRow(t, activityBefore, "Single-PR thaw")
	if want := `Branch main; head ` + oldHeadSHA[:12] + `.`; !strings.Contains(oldThawActivityRow, want) {
		t.Fatalf("old Single-PR thaw activity row is missing %q", want)
	}

	thirdFreeze := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"))
	if thirdFreeze.branch != "main" || thirdFreeze.reason != freezeReason || thirdFreeze.status != "active" {
		t.Fatalf("unexpected third-freeze evidence before head advance: id=%d branch=%q reason=%q status=%q", thirdFreeze.id, thirdFreeze.branch, thirdFreeze.reason, thirdFreeze.status)
	}

	newHeadSHA := advanceFeatureBranch(
		t,
		ctx,
		forgejo,
		pullRequestIndex,
		oldHeadSHA,
		"stale-head-thaw.txt",
		"Advance fictional E2E thawed feature head",
		"new head for exact-head thaw reevaluation proof\n",
		"stale-head thaw",
	)
	waitForOneNewProcessedPullRequestDelivery(t, ctx, browser, repositoryID, before.webhookRows, "synchronized")
	waitForLatestPostedPublicationAttempt(t, ctx, browser, newHeadSHA, "failure", frozenReason)
	waitForStatusWithDescription(t, ctx, forgejo, newHeadSHA, "failure", frozenReason)
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pullRequestIndex)

	after := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, newHeadSHA)
	if after.webhookRows != before.webhookRows+1 {
		t.Fatalf("stale-head reevaluation changed webhook rows by %d, want 1", after.webhookRows-before.webhookRows)
	}
	if after.statusResults != before.statusResults+1 {
		t.Fatalf("stale-head reevaluation changed status results by %d, want 1", after.statusResults-before.statusResults)
	}
	if after.publicationIntents != before.publicationIntents+1 {
		t.Fatalf("stale-head reevaluation changed publication intents by %d, want 1", after.publicationIntents-before.publicationIntents)
	}
	if after.publicationAttempts != before.publicationAttempts+1 {
		t.Fatalf("stale-head reevaluation changed publication attempts by %d, want 1", after.publicationAttempts-before.publicationAttempts)
	}
	if after.activityEvents != before.activityEvents {
		t.Fatalf("stale-head reevaluation changed activity events from %d to %d", before.activityEvents, after.activityEvents)
	}
	if len(after.freezeStatuses) != 1 {
		t.Fatalf("new stale-head SHA has %d %s statuses, want exactly 1", len(after.freezeStatuses), requiredContext)
	}
	newStatus := after.freezeStatuses[0]
	if newStatus.Context != requiredContext || newStatus.Status != "failure" || newStatus.Description != frozenReason {
		t.Fatalf("unexpected new-head required status: id=%d context=%q state=%q description=%q", newStatus.ID, newStatus.Context, newStatus.Status, newStatus.Description)
	}

	oldStatusesAfter, err := listForgejoFreezeStatuses(ctx, forgejo, oldHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(oldStatusesAfter, oldStatuses) {
		t.Fatalf("old exact-head Forgejo status history changed after reevaluation: before=%+v after=%+v", oldStatuses, oldStatusesAfter)
	}
	oldLatestAfter := oldStatusesAfter[len(oldStatusesAfter)-1]
	if oldLatestAfter != oldLatest || oldLatestAfter.Context != requiredContext || oldLatestAfter.Status != "success" || oldLatestAfter.Description != explicitThaw {
		t.Fatalf("old exact-head latest status changed after reevaluation: before=%+v after=%+v", oldLatest, oldLatestAfter)
	}

	decisionsAfter := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsAfter, oldDecisionRow) {
		t.Fatal("old exact-head Eligible decision row disappeared after head reevaluation")
	}
	newDecisionRow := requireLatestDecisionResultRow(t, decisionsAfter)
	for _, want := range []string{
		`<a href="#">#` + strconv.Itoa(pullRequestIndex) + `</a>`,
		`<code>` + fixtureOwner + `/` + fixtureRepository + `</code>`,
		`<code class="tg-branch">main</code>`,
		`<code>` + newHeadSHA + `</code>`,
		frozenReason,
		`<code>` + requiredContext + `</code>`,
		`<span class="status status-failure">Blocked</span>`,
	} {
		if !strings.Contains(newDecisionRow, want) {
			t.Fatalf("latest stale-head decision row is missing %q", want)
		}
	}

	activityAfter := requirePage(t, ctx, browser, "/activity")
	if !strings.Contains(activityAfter, oldThawActivityRow) {
		t.Fatal("old Single-PR thaw activity row disappeared after head reevaluation")
	}
	if latest := requireLatestActivityRow(t, activityAfter, "Single-PR thaw"); latest != oldThawActivityRow {
		t.Fatal("old Single-PR thaw activity evidence changed after head reevaluation")
	}

	publicationsPage := requirePage(t, ctx, browser, "/publications")
	newIntentRow := requireLatestPublicationIntentRow(t, publicationsPage)
	newAttemptRow := requireLatestPublicationAttemptRow(t, publicationsPage)
	for label, row := range map[string]string{
		"intent":  newIntentRow,
		"attempt": newAttemptRow,
	} {
		for _, want := range []string{
			fixtureOwner + `/` + fixtureRepository,
			`#` + strconv.Itoa(pullRequestIndex) + `<small class="tg-muted">main</small>`,
			`<code>` + newHeadSHA + `</code>`,
			`<span class="status status-failure">failure</span>`,
			`<code>forgejo_status</code>`,
			frozenReason,
		} {
			if !strings.Contains(row, want) {
				t.Fatalf("latest stale-head publication %s is missing %q", label, want)
			}
		}
	}
	if !strings.Contains(newIntentRow, `<td data-label="Context"><code>`+requiredContext+`</code></td>`) {
		t.Fatalf("latest stale-head publication intent is missing %q", requiredContext)
	}
	for _, want := range []string{
		`<small class="tg-muted">` + requiredContext + `</small>`,
		`<td data-label="Result"><span class="status status-ok">posted</span></td>`,
	} {
		if !strings.Contains(newAttemptRow, want) {
			t.Fatalf("latest stale-head publication attempt is missing %q", want)
		}
	}

	if active := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); active != thirdFreeze {
		t.Fatalf("third active freeze changed after stale-head reevaluation: before=%+v after=%+v", thirdFreeze, active)
	}
	return newHeadSHA
}

func proveSharedHeadConfirmation(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, primaryPullRequestIndex int, historicalThawedHeadSHA, sharedHeadSHA string) {
	t.Helper()
	const (
		thawReason   = "Fictional shared-head thaw confirmation"
		frozenReason = "Branch is frozen; merge is blocked by Thawguard"
		explicitThaw = "PR is explicitly thawed during an active freeze"
	)
	historicalThawedHeadSHA = strings.ToLower(strings.TrimSpace(historicalThawedHeadSHA))
	sharedHeadSHA = strings.ToLower(strings.TrimSpace(sharedHeadSHA))
	if len(historicalThawedHeadSHA) < 12 || len(sharedHeadSHA) < 12 || historicalThawedHeadSHA == sharedHeadSHA {
		t.Fatalf("shared-head confirmation requires distinct full historical and current SHAs: historical=%q current=%q", historicalThawedHeadSHA, sharedHeadSHA)
	}

	activeFreeze := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"))
	if activeFreeze.branch != "main" || activeFreeze.status != "active" {
		t.Fatalf("shared-head confirmation started without the expected active main freeze: %+v", activeFreeze)
	}
	historicalStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, historicalThawedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(historicalStatuses) == 0 {
		t.Fatal("historical thawed SHA has no retained Forgejo status evidence")
	}
	historicalLatest := historicalStatuses[len(historicalStatuses)-1]
	if historicalLatest.Context != requiredContext || historicalLatest.Status != "success" || historicalLatest.Description != explicitThaw {
		t.Fatalf("unexpected historical thawed-SHA status: id=%d context=%q state=%q description=%q", historicalLatest.ID, historicalLatest.Context, historicalLatest.Status, historicalLatest.Description)
	}
	historicalActivityPage := requirePage(t, ctx, browser, "/activity")
	historicalThawRow := requireLatestActivityRow(t, historicalActivityPage, "Single-PR thaw")
	if !strings.Contains(historicalThawRow, "head "+historicalThawedHeadSHA[:12]+".") {
		t.Fatalf("historical Single-PR thaw row is missing head %q", historicalThawedHeadSHA[:12])
	}
	historicalDecisionRow := requireDecisionResultRowForHead(t, requirePage(t, ctx, browser, "/decisions"), historicalThawedHeadSHA)
	for _, want := range []string{explicitThaw, `<span class="status status-success">Eligible</span>`} {
		if !strings.Contains(historicalDecisionRow, want) {
			t.Fatalf("historical thawed-SHA decision row is missing %q", want)
		}
	}

	branchHeadSHA := createForgejoBranch(t, ctx, forgejo, fixtureSharedHeadBranch, fixtureFeatureBranch)
	if branchHeadSHA != sharedHeadSHA {
		t.Fatalf("shared-head branch commit %q does not equal PR #%d current SHA %q", branchHeadSHA, primaryPullRequestIndex, sharedHeadSHA)
	}

	beforeOpened := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
	if len(beforeOpened.freezeStatuses) == 0 {
		t.Fatal("shared head is missing its pre-second-PR failing status")
	}
	latestBeforeOpened := beforeOpened.freezeStatuses[len(beforeOpened.freezeStatuses)-1]
	if latestBeforeOpened.Context != requiredContext || latestBeforeOpened.Status != "failure" || latestBeforeOpened.Description != frozenReason {
		t.Fatalf("unexpected pre-second-PR required status: id=%d context=%q state=%q description=%q", latestBeforeOpened.ID, latestBeforeOpened.Context, latestBeforeOpened.Status, latestBeforeOpened.Description)
	}

	secondaryPR := createForgejoPullRequest(t, ctx, forgejo, fixtureSharedHeadBranch, fixtureSharedHeadPRTitle)
	if secondaryPR.Number == primaryPullRequestIndex {
		t.Fatalf("second Forgejo pull request reused primary number %d", primaryPullRequestIndex)
	}
	if secondaryPR.Head.SHA != sharedHeadSHA {
		t.Fatalf("second Forgejo pull request head %q does not equal primary shared SHA %q", secondaryPR.Head.SHA, sharedHeadSHA)
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, primaryPullRequestIndex, fixturePrimaryPRTitle, sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, secondaryPR.Number, fixtureSharedHeadPRTitle, sharedHeadSHA)

	waitForOneNewProcessedPullRequestDelivery(t, ctx, browser, repositoryID, beforeOpened.webhookRows, "opened")
	var afterOpened webhookSideEffectEvidence
	waitFor(t, 30*time.Second, "second-PR opened webhook side effects", func() (bool, error) {
		afterOpened = collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
		if afterOpened.webhookRows > beforeOpened.webhookRows+1 ||
			afterOpened.statusResults > beforeOpened.statusResults+1 ||
			afterOpened.publicationIntents > beforeOpened.publicationIntents ||
			afterOpened.publicationAttempts > beforeOpened.publicationAttempts+1 ||
			afterOpened.activityEvents > beforeOpened.activityEvents ||
			len(afterOpened.freezeStatuses) > len(beforeOpened.freezeStatuses)+1 {
			t.Fatal("second-PR opened webhook exceeded its expected side-effect deltas")
		}
		return afterOpened.webhookRows == beforeOpened.webhookRows+1 &&
			afterOpened.statusResults == beforeOpened.statusResults+1 &&
			afterOpened.publicationIntents == beforeOpened.publicationIntents &&
			afterOpened.publicationAttempts == beforeOpened.publicationAttempts+1 &&
			afterOpened.activityEvents == beforeOpened.activityEvents &&
			len(afterOpened.freezeStatuses) == len(beforeOpened.freezeStatuses)+1, nil
	})
	waitForLatestPostedPublicationAttempt(t, ctx, browser, sharedHeadSHA, "failure", frozenReason)
	latestAfterOpened := afterOpened.freezeStatuses[len(afterOpened.freezeStatuses)-1]
	if latestAfterOpened.ID <= latestBeforeOpened.ID || latestAfterOpened.Context != requiredContext || latestAfterOpened.Status != "failure" || latestAfterOpened.Description != frozenReason {
		t.Fatalf("unexpected second-PR opened required status: id=%d context=%q state=%q description=%q", latestAfterOpened.ID, latestAfterOpened.Context, latestAfterOpened.Status, latestAfterOpened.Description)
	}
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, primaryPullRequestIndex)
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, secondaryPR.Number)
	if current := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); current != activeFreeze {
		t.Fatalf("active freeze changed while opening the shared-head PR: before=%+v after=%+v", activeFreeze, current)
	}

	decisionsPage := requirePage(t, ctx, browser, "/decisions")
	ordinaryForm := requireRenderedForm(t, decisionsPage, `<form method="post" action="/decisions" class="tg-setup-form tg-thaw-form" data-thaw-form>`, "ordinary thaw")
	if strings.Contains(ordinaryForm, `name="head_sha"`) || strings.Contains(ordinaryForm, `name="confirm_shared_head"`) {
		t.Fatal("ordinary thaw form unexpectedly contains head or confirmation fields")
	}
	ordinaryValues := url.Values{
		"csrf_token":         {requireHiddenInput(t, ordinaryForm, "csrf_token")},
		"repository_id":      {strconv.FormatInt(repositoryID, 10)},
		"pull_request_index": {strconv.Itoa(primaryPullRequestIndex)},
		"target_branch":      {"main"},
		"reason":             {thawReason},
	}

	beforeConflict := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
	beforeConflictActivity := requirePage(t, ctx, browser, "/activity")
	beforeConflictSyncs := countOpenPullRequestSyncEvents(beforeConflictActivity)
	beforeConflictSharedThaws := countSharedHeadThawEvents(beforeConflictActivity)
	beforeConflictDecisions := requirePage(t, ctx, browser, "/decisions")
	beforeConflictDecisionRow := requireLatestDecisionResultRow(t, beforeConflictDecisions)
	beforeConflictEligibleRows := countEligibleDecisionRows(beforeConflictDecisions)
	latestBeforeConflict := beforeConflict.freezeStatuses[len(beforeConflict.freezeStatuses)-1]

	conflictResponse, err := browser.postFormNoRedirect(ctx, "/decisions", ordinaryValues)
	if err != nil {
		t.Fatalf("submit ordinary shared-head thaw: %v", err)
	}
	if conflictResponse.statusCode != http.StatusConflict {
		t.Fatalf("ordinary shared-head thaw returned HTTP %d, want 409", conflictResponse.statusCode)
	}
	conflictBody := string(conflictResponse.body)
	confirmationForm := requireRenderedForm(t, conflictBody, `<form method="post" action="/decisions" class="tg-shared-head-confirm-form">`, "shared-head confirmation")
	shortSharedHead := sharedHeadSHA[:10]
	for _, want := range []string{
		"These pull requests share one commit SHA",
		"Nothing has been approved yet.",
		"shared head <code>" + shortSharedHead + "</code>",
		"Approve thaw for all 2 PRs",
	} {
		if !strings.Contains(conflictBody, want) {
			t.Fatalf("shared-head confirmation response is missing %q", want)
		}
	}
	primaryRow := requireSharedHeadConfirmationRow(t, conflictBody, primaryPullRequestIndex)
	secondaryRow := requireSharedHeadConfirmationRow(t, conflictBody, secondaryPR.Number)
	for _, want := range []string{fixturePrimaryPRTitle, `<code class="tg-branch">main</code>`, `<code>` + shortSharedHead + `</code>`, `>your selection</span>`} {
		if !strings.Contains(primaryRow, want) {
			t.Fatalf("selected shared-head confirmation row is missing %q", want)
		}
	}
	for _, want := range []string{fixtureSharedHeadPRTitle, `<code class="tg-branch">main</code>`, `<code>` + shortSharedHead + `</code>`} {
		if !strings.Contains(secondaryRow, want) {
			t.Fatalf("second shared-head confirmation row is missing %q", want)
		}
	}
	if strings.Contains(secondaryRow, "your selection") || fixturePrimaryPRTitle == fixtureSharedHeadPRTitle {
		t.Fatal("shared-head confirmation did not preserve one selected PR and two distinct titles")
	}

	confirmationFieldNames := []string{
		"csrf_token",
		"repository_id",
		"pull_request_index",
		"target_branch",
		"reason",
		"confirm_shared_head",
		"confirmed_head_sha",
		"confirmed_affected_signature",
	}
	confirmationValues := make(url.Values, len(confirmationFieldNames))
	for _, name := range confirmationFieldNames {
		confirmationValues.Set(name, requireHiddenInput(t, confirmationForm, name))
	}
	requireOnlyFormInputNames(t, confirmationForm, confirmationFieldNames)
	if confirmationValues.Get("csrf_token") == "" {
		t.Fatal("shared-head confirmation form has an empty CSRF token")
	}
	if confirmationValues.Get("repository_id") != strconv.FormatInt(repositoryID, 10) ||
		confirmationValues.Get("pull_request_index") != strconv.Itoa(primaryPullRequestIndex) ||
		confirmationValues.Get("target_branch") != "main" ||
		confirmationValues.Get("reason") != thawReason ||
		confirmationValues.Get("confirm_shared_head") != "true" ||
		confirmationValues.Get("confirmed_head_sha") != sharedHeadSHA {
		t.Fatalf("shared-head confirmation form did not preserve the original request and full current SHA")
	}
	affectedFingerprint := confirmationValues.Get("confirmed_affected_signature")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(affectedFingerprint) {
		t.Fatalf("shared-head affected-set fingerprint has invalid shape %q", affectedFingerprint)
	}
	if strings.Contains(conflictBody, `<code>`+affectedFingerprint+`</code>`) || strings.Contains(conflictBody, affectedFingerprint+`</`) {
		t.Fatal("shared-head affected-set fingerprint leaked into visible confirmation content")
	}

	activityAfterConflict := waitForOneNewOpenPullRequestSync(t, ctx, browser, beforeConflictSyncs)
	requireLatestOpenPullRequestSync(t, activityAfterConflict, 2)
	afterConflict := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
	if afterConflict.webhookRows != beforeConflict.webhookRows ||
		afterConflict.statusResults != beforeConflict.statusResults ||
		afterConflict.publicationIntents != beforeConflict.publicationIntents ||
		afterConflict.publicationAttempts != beforeConflict.publicationAttempts ||
		afterConflict.activityEvents != beforeConflict.activityEvents+1 ||
		!slices.Equal(afterConflict.freezeStatuses, beforeConflict.freezeStatuses) {
		t.Fatalf("409 confirmation changed approval/publication evidence: webhooks %d→%d, status results %d→%d, intents %d→%d, attempts %d→%d, activity %d→%d, Forgejo statuses %d→%d",
			beforeConflict.webhookRows, afterConflict.webhookRows,
			beforeConflict.statusResults, afterConflict.statusResults,
			beforeConflict.publicationIntents, afterConflict.publicationIntents,
			beforeConflict.publicationAttempts, afterConflict.publicationAttempts,
			beforeConflict.activityEvents, afterConflict.activityEvents,
			len(beforeConflict.freezeStatuses), len(afterConflict.freezeStatuses))
	}
	latestAfterConflict := afterConflict.freezeStatuses[len(afterConflict.freezeStatuses)-1]
	if latestAfterConflict != latestBeforeConflict || latestAfterConflict.Status != "failure" || latestAfterConflict.Description != frozenReason {
		t.Fatalf("409 confirmation changed the latest failing status: before=%+v after=%+v", latestBeforeConflict, latestAfterConflict)
	}
	decisionsAfterConflict := requirePage(t, ctx, browser, "/decisions")
	if latest := requireLatestDecisionResultRow(t, decisionsAfterConflict); latest != beforeConflictDecisionRow {
		t.Fatal("409 confirmation added or changed the latest status decision row")
	}
	if countEligibleDecisionRows(decisionsAfterConflict) != beforeConflictEligibleRows {
		t.Fatal("409 confirmation added a success decision row")
	}
	if countSharedHeadThawEvents(activityAfterConflict) != beforeConflictSharedThaws || strings.Contains(activityAfterConflict, "Confirmation reason: "+thawReason) {
		t.Fatal("409 confirmation added Shared-head thaw approval activity")
	}
	if current := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); current != activeFreeze {
		t.Fatalf("409 confirmation changed the active freeze: before=%+v after=%+v", activeFreeze, current)
	}

	beforeConfirmation := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
	if beforeConfirmation.webhookRows != beforeConflict.webhookRows ||
		beforeConfirmation.statusResults != beforeConflict.statusResults ||
		beforeConfirmation.publicationIntents != beforeConflict.publicationIntents ||
		beforeConfirmation.publicationAttempts != beforeConflict.publicationAttempts ||
		beforeConfirmation.activityEvents != beforeConflict.activityEvents+1 ||
		!slices.Equal(beforeConfirmation.freezeStatuses, beforeConflict.freezeStatuses) {
		t.Fatal("409 confirmation evidence changed after its audited refresh settled")
	}
	beforeConfirmationActivity := requirePage(t, ctx, browser, "/activity")
	beforeConfirmationSyncs := countOpenPullRequestSyncEvents(beforeConfirmationActivity)
	beforeConfirmationSharedThaws := countSharedHeadThawEvents(beforeConfirmationActivity)
	latestBeforeConfirmation := beforeConfirmation.freezeStatuses[len(beforeConfirmation.freezeStatuses)-1]

	confirmedResponse, err := browser.postFormNoRedirect(ctx, "/decisions", confirmationValues)
	if err != nil {
		t.Fatalf("submit explicit shared-head confirmation: %v", err)
	}
	if confirmedResponse.statusCode != http.StatusSeeOther || confirmedResponse.location != "/decisions" {
		t.Fatalf("explicit shared-head confirmation returned HTTP %d with Location %q, want 303 to /decisions", confirmedResponse.statusCode, confirmedResponse.location)
	}

	var afterConfirmation webhookSideEffectEvidence
	waitFor(t, 30*time.Second, "confirmed shared-head approval side effects", func() (bool, error) {
		afterConfirmation = collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
		if afterConfirmation.webhookRows > beforeConfirmation.webhookRows ||
			afterConfirmation.statusResults > beforeConfirmation.statusResults+1 ||
			afterConfirmation.publicationIntents > beforeConfirmation.publicationIntents ||
			afterConfirmation.publicationAttempts > beforeConfirmation.publicationAttempts+1 ||
			afterConfirmation.activityEvents > beforeConfirmation.activityEvents+2 ||
			len(afterConfirmation.freezeStatuses) > len(beforeConfirmation.freezeStatuses)+1 {
			t.Fatal("confirmed shared-head approval exceeded its expected side-effect deltas")
		}
		return afterConfirmation.webhookRows == beforeConfirmation.webhookRows &&
			afterConfirmation.statusResults == beforeConfirmation.statusResults+1 &&
			afterConfirmation.publicationIntents == beforeConfirmation.publicationIntents &&
			afterConfirmation.publicationAttempts == beforeConfirmation.publicationAttempts+1 &&
			afterConfirmation.activityEvents == beforeConfirmation.activityEvents+2 &&
			len(afterConfirmation.freezeStatuses) == len(beforeConfirmation.freezeStatuses)+1, nil
	})
	waitForLatestPostedPublicationAttempt(t, ctx, browser, sharedHeadSHA, "success", explicitThaw)
	activityAfterConfirmation := waitForOneNewOpenPullRequestSync(t, ctx, browser, beforeConfirmationSyncs)
	requireLatestOpenPullRequestSync(t, activityAfterConfirmation, 2)
	if countSharedHeadThawEvents(activityAfterConfirmation) != beforeConfirmationSharedThaws+1 {
		t.Fatal("confirmed shared-head approval did not add exactly one Shared-head thaw event")
	}
	settledAfterConfirmation := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, sharedHeadSHA)
	if settledAfterConfirmation.webhookRows != beforeConfirmation.webhookRows ||
		settledAfterConfirmation.statusResults != beforeConfirmation.statusResults+1 ||
		settledAfterConfirmation.publicationIntents != beforeConfirmation.publicationIntents ||
		settledAfterConfirmation.publicationAttempts != beforeConfirmation.publicationAttempts+1 ||
		settledAfterConfirmation.activityEvents != beforeConfirmation.activityEvents+2 ||
		len(settledAfterConfirmation.freezeStatuses) != len(beforeConfirmation.freezeStatuses)+1 ||
		!slices.Equal(settledAfterConfirmation.freezeStatuses, afterConfirmation.freezeStatuses) {
		t.Fatal("confirmed shared-head approval evidence changed after publication and activity settled")
	}
	afterConfirmation = settledAfterConfirmation
	latestAfterConfirmation := afterConfirmation.freezeStatuses[len(afterConfirmation.freezeStatuses)-1]
	if latestAfterConfirmation.ID <= latestBeforeConfirmation.ID || latestAfterConfirmation.Context != requiredContext || latestAfterConfirmation.Status != "success" || latestAfterConfirmation.Description != explicitThaw {
		t.Fatalf("unexpected confirmed shared-head required status: id=%d context=%q state=%q description=%q", latestAfterConfirmation.ID, latestAfterConfirmation.Context, latestAfterConfirmation.Status, latestAfterConfirmation.Description)
	}

	decisionsAfterConfirmation := requirePage(t, ctx, browser, "/decisions")
	decisionRow := requireLatestDecisionResultRow(t, decisionsAfterConfirmation)
	for _, want := range []string{
		`<a href="#">#` + strconv.Itoa(primaryPullRequestIndex) + `</a>`,
		`<code>` + fixtureOwner + `/` + fixtureRepository + `</code>`,
		`<code class="tg-branch">main</code>`,
		`<code>` + sharedHeadSHA + `</code>`,
		explicitThaw,
		`<code>` + requiredContext + `</code>`,
		`<span class="status status-success">Eligible</span>`,
	} {
		if !strings.Contains(decisionRow, want) {
			t.Fatalf("latest shared-head status result is missing %q", want)
		}
	}

	publicationsPage := requirePage(t, ctx, browser, "/publications")
	intentRow := requireLatestPublicationIntentRow(t, publicationsPage)
	attemptRow := requireLatestPublicationAttemptRow(t, publicationsPage)
	for label, row := range map[string]string{"intent": intentRow, "attempt": attemptRow} {
		for _, want := range []string{
			fixtureOwner + `/` + fixtureRepository,
			`#` + strconv.Itoa(primaryPullRequestIndex) + `<small class="tg-muted">main</small>`,
			`<code>` + sharedHeadSHA + `</code>`,
			`<span class="status status-success">success</span>`,
			`<code>forgejo_status</code>`,
			explicitThaw,
		} {
			if !strings.Contains(row, want) {
				t.Fatalf("latest shared-head publication %s is missing %q", label, want)
			}
		}
	}
	if !strings.Contains(intentRow, `<td data-label="Context"><code>`+requiredContext+`</code></td>`) {
		t.Fatalf("latest shared-head publication intent is missing %q", requiredContext)
	}
	for _, want := range []string{
		`<small class="tg-muted">` + requiredContext + `</small>`,
		`<td data-label="Result"><span class="status status-ok">posted</span></td>`,
	} {
		if !strings.Contains(attemptRow, want) {
			t.Fatalf("latest shared-head publication attempt is missing %q", want)
		}
	}

	sharedThawRow := requireLatestActivityRow(t, activityAfterConfirmation, "Shared-head thaw")
	for _, want := range []string{
		`<td data-label="Actor">E2E Admin</td>`,
		`<td data-label="Target">` + fixtureOwner + `/` + fixtureRepository + ` → shared head ` + sharedHeadSHA[:12] + `</td>`,
		`<td data-label="Outcome"><span class="status status-ok">Approved</span></td>`,
		`<td data-label="Details">New exceptions: #` + strconv.Itoa(primaryPullRequestIndex) + `, #` + strconv.Itoa(secondaryPR.Number) + `; already covered: none. Confirmation reason: ` + thawReason + `.</td>`,
	} {
		if !strings.Contains(sharedThawRow, want) {
			t.Fatalf("latest Shared-head thaw activity is missing %q", want)
		}
	}
	if current := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); current != activeFreeze {
		t.Fatalf("confirmed shared-head approval changed the active freeze: before=%+v after=%+v", activeFreeze, current)
	}

	historicalStatusesAfter, err := listForgejoFreezeStatuses(ctx, forgejo, historicalThawedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(historicalStatusesAfter, historicalStatuses) {
		t.Fatalf("historical thawed-SHA status evidence changed during shared-head confirmation: before=%+v after=%+v", historicalStatuses, historicalStatusesAfter)
	}
	if !strings.Contains(decisionsAfterConfirmation, historicalDecisionRow) || requireDecisionResultRowForHead(t, decisionsAfterConfirmation, historicalThawedHeadSHA) != historicalDecisionRow {
		t.Fatal("historical thawed-SHA Eligible decision row changed during shared-head confirmation")
	}
	if !strings.Contains(activityAfterConfirmation, historicalThawRow) || requireLatestActivityRow(t, activityAfterConfirmation, "Single-PR thaw") != historicalThawRow {
		t.Fatal("historical Single-PR thaw activity changed during shared-head confirmation")
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, primaryPullRequestIndex, fixturePrimaryPRTitle, sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, secondaryPR.Number, fixtureSharedHeadPRTitle, sharedHeadSHA)
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
		thawguardSecretKey:     os.Getenv("THAWGUARD_SECRET_KEY"),
		composeProject:         os.Getenv("THAWGUARD_E2E_COMPOSE_PROJECT"),
		repositoryRoot:         os.Getenv("THAWGUARD_E2E_REPO_ROOT"),
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
		{name: "THAWGUARD_SECRET_KEY", value: cfg.thawguardSecretKey},
		{name: "THAWGUARD_E2E_COMPOSE_PROJECT", value: cfg.composeProject},
		{name: "THAWGUARD_E2E_REPO_ROOT", value: cfg.repositoryRoot},
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
	if _, _, err := cfg.composeFiles(); err != nil {
		t.Fatal("invalid E2E Compose metadata")
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
		cfg.thawguardSecretKey,
	}
}

func (cfg e2eConfig) composeFiles() (string, string, error) {
	root := strings.TrimSpace(cfg.repositoryRoot)
	if cfg.composeProject != e2eComposeProject || root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", "", fmt.Errorf("compose metadata is outside the E2E allowlist")
	}
	composeFile := filepath.Join(root, "compose.yaml")
	localComposeFile := filepath.Join(root, "compose.local.yaml")
	for _, path := range []string{composeFile, localComposeFile} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("compose metadata is outside the E2E allowlist")
		}
	}
	return composeFile, localComposeFile, nil
}

func controlThawguardService(t *testing.T, ctx context.Context, cfg e2eConfig, operation string) {
	t.Helper()
	if operation != "stop" && operation != "start" {
		t.Fatal("docker compose Thawguard service operation is not allowed")
	}
	composeFile, localComposeFile, err := cfg.composeFiles()
	if err != nil {
		t.Fatal("invalid E2E Compose metadata")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	output, commandErr := exec.CommandContext(commandCtx, "docker", []string{
		"compose",
		"--project-name", e2eComposeProject,
		"--file", composeFile,
		"--file", localComposeFile,
		operation,
		"thawguard",
	}...).CombinedOutput()
	if containsSensitiveValue(output, cfg.sensitiveValues()) || commandErr != nil {
		t.Fatalf("docker compose %s thawguard failed", operation)
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
		createForgejoBranch(t, ctx, forgejo, branch, "main")
	}

	createForgejoBranchProtection(t, ctx, forgejo, "main")

	response, err = forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("contents", "fixture.txt"), map[string]any{
		"branch":  fixtureFeatureBranch,
		"message": "Add fictional E2E fixture",
		"content": base64.StdEncoding.EncodeToString([]byte("fictional local fixture\n")),
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo fixture commit")
}

func createForgejoBranchProtection(t *testing.T, ctx context.Context, forgejo *forgejoAPI, branch string) {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("branch_protections"), map[string]any{
		"rule_name":             branch,
		"enable_status_check":   true,
		"status_check_contexts": []string{requiredContext},
		"apply_to_admins":       true,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo branch protection for "+branch)
	var protection struct {
		RuleName            string   `json:"rule_name"`
		EnableStatusCheck   bool     `json:"enable_status_check"`
		StatusCheckContexts []string `json:"status_check_contexts"`
	}
	decodeJSON(t, response.body, &protection, "decode branch protection for "+branch)
	if protection.RuleName != branch || !protection.EnableStatusCheck || !slices.Contains(protection.StatusCheckContexts, requiredContext) {
		t.Fatalf("Forgejo returned incomplete protection for branch %q", branch)
	}
}

func deleteForgejoBranchProtection(t *testing.T, ctx context.Context, forgejo *forgejoAPI, branch string) {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodDelete, forgejo.repositoryPath("branch_protections", url.PathEscape(branch)), nil)
	requireAPIStatus(t, response, err, http.StatusNoContent, "delete Forgejo branch protection for "+branch)
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

func createForgejoBranch(t *testing.T, ctx context.Context, forgejo *forgejoAPI, branch, sourceRef string) string {
	t.Helper()
	allowed := (sourceRef == "main" && (branch == fixtureReleaseBranch || branch == fixtureFeatureBranch)) ||
		(sourceRef == fixtureFeatureBranch && branch == fixtureSharedHeadBranch)
	if !allowed {
		t.Fatalf("Forgejo branch creation %q from %q is not allowlisted", branch, sourceRef)
	}
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("branches"), map[string]any{
		"new_branch_name": branch,
		"old_ref_name":    sourceRef,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo branch "+branch)
	var created forgejoBranch
	decodeJSON(t, response.body, &created, "decode Forgejo branch "+branch)
	created.Name = strings.TrimSpace(created.Name)
	created.Commit.ID = strings.ToLower(strings.TrimSpace(created.Commit.ID))
	if created.Name != branch || created.Commit.ID == "" {
		t.Fatalf("Forgejo returned incomplete branch %q evidence: name=%q commit=%q", branch, created.Name, created.Commit.ID)
	}
	return created.Commit.ID
}

func createForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI, head, title string) pullRequest {
	t.Helper()
	allowed := (head == fixtureFeatureBranch && title == fixturePrimaryPRTitle) ||
		(head == fixtureSharedHeadBranch && title == fixtureSharedHeadPRTitle)
	if !allowed {
		t.Fatalf("Forgejo pull request head %q and title %q are not allowlisted", head, title)
	}
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("pulls"), map[string]any{
		"head":  head,
		"base":  "main",
		"title": title,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo pull request")
	var pr pullRequest
	decodeJSON(t, response.body, &pr, "decode Forgejo pull request")
	normalizePullRequest(&pr)
	if pr.Number <= 0 || pr.Title != title || pr.State != "open" || pr.Base.Ref != "main" || pr.Head.SHA == "" || pr.HTMLURL == "" {
		t.Fatalf("Forgejo returned incomplete pull request evidence: number=%d title=%q state=%q base=%q head=%q", pr.Number, pr.Title, pr.State, pr.Base.Ref, pr.Head.SHA)
	}
	return pr
}

func requireOpenForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI, index int, title, headSHA string) pullRequest {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("pulls", strconv.Itoa(index)), nil)
	requireAPIStatus(t, response, err, http.StatusOK, "read Forgejo pull request")
	var pr pullRequest
	decodeJSON(t, response.body, &pr, "decode Forgejo pull request")
	normalizePullRequest(&pr)
	if pr.Number != index || pr.Title != title || pr.State != "open" || pr.Base.Ref != "main" || pr.Head.SHA != headSHA || pr.HTMLURL == "" {
		t.Fatalf("unexpected open Forgejo PR #%d evidence: number=%d title=%q state=%q base=%q head=%q", index, pr.Number, pr.Title, pr.State, pr.Base.Ref, pr.Head.SHA)
	}
	return pr
}

func normalizePullRequest(pr *pullRequest) {
	pr.Title = strings.TrimSpace(pr.Title)
	pr.State = strings.ToLower(strings.TrimSpace(pr.State))
	pr.HTMLURL = strings.TrimSpace(pr.HTMLURL)
	pr.Base.Ref = strings.TrimSpace(pr.Base.Ref)
	pr.Head.SHA = strings.ToLower(strings.TrimSpace(pr.Head.SHA))
}

func proveRestartPersistenceAndReconciliation(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, cfg e2eConfig, repositoryID int64, pr pullRequest) {
	t.Helper()
	repositoryValue := strconv.FormatInt(repositoryID, 10)
	repositoriesBefore := requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(repositoriesBefore, fixtureOwner+"/"+fixtureRepository) {
		t.Fatal("authenticated repository page is missing the configured repository before restart")
	}
	csrfBefore := requireHiddenInput(t, repositoriesBefore, "csrf_token")
	freezeBefore := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"))
	if freezeBefore.id <= 0 || freezeBefore.branch != "main" || freezeBefore.reason != "Fictional release verification" || freezeBefore.status != "active" {
		t.Fatalf("active freeze has unexpected pre-restart evidence: id=%d branch=%q reason=%q status=%q", freezeBefore.id, freezeBefore.branch, freezeBefore.reason, freezeBefore.status)
	}
	activityBefore := requirePage(t, ctx, browser, "/activity")
	freezeHistoryBefore := requireLatestActivityRow(t, activityBefore, "Branch freeze")
	evidenceBefore := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, pr.Head.SHA)
	if len(evidenceBefore.freezeStatuses) == 0 {
		t.Fatal("missing pre-restart Thawguard freeze status")
	}
	oldFailure := evidenceBefore.freezeStatuses[len(evidenceBefore.freezeStatuses)-1]
	if oldFailure.Context != requiredContext || oldFailure.Status != "failure" || oldFailure.Description != "Branch is frozen; merge is blocked by Thawguard" {
		t.Fatalf("unexpected pre-restart required status: id=%d context=%q state=%q description=%q", oldFailure.ID, oldFailure.Context, oldFailure.Status, oldFailure.Description)
	}

	deleteForgejoBranchProtection(t, ctx, forgejo, fixtureReleaseBranch)
	failedResponse, err := browser.postFormResponse(ctx, "/repositories/reconcile", url.Values{
		"csrf_token":    {csrfBefore},
		"repository_id": {repositoryValue},
	})
	if err != nil {
		t.Fatalf("submit Thawguard reconciliation with failed readiness: %v", err)
	}
	if failedResponse.statusCode != http.StatusBadRequest {
		t.Fatalf("failed-readiness reconciliation returned HTTP %d, want 400", failedResponse.statusCode)
	}

	controlThawguardService(t, ctx, cfg, "stop")
	failedBody := string(failedResponse.body)
	for _, want := range []string{
		"Reconciliation stopped: readiness checks did not pass, so nothing was synchronized or published.",
		"Enforcement is unhealthy: readiness checks failed",
		"Automatic recovery is pending",
	} {
		if !strings.Contains(failedBody, want) {
			t.Fatalf("failed-readiness reconciliation response is missing %q", want)
		}
	}

	createForgejoBranchProtection(t, ctx, forgejo, fixtureReleaseBranch)
	injected := postInjectedDriftStatus(t, ctx, forgejo, pr.Head.SHA)
	if injected.ID <= oldFailure.ID {
		t.Fatalf("injected drift status ID %d did not follow old Thawguard failure ID %d", injected.ID, oldFailure.ID)
	}

	controlThawguardService(t, ctx, cfg, "start")
	waitFor(t, 45*time.Second, "restarted Thawguard HTTP readiness", func() (bool, error) {
		_, err := browser.get(ctx, "/healthz")
		return err == nil, err
	})

	repositoriesAfterStart := requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(repositoriesAfterStart, fixtureOwner+"/"+fixtureRepository) {
		t.Fatal("restarted browser session is not authenticated to the configured repository")
	}
	if csrfAfter := requireHiddenInput(t, repositoriesAfterStart, "csrf_token"); csrfAfter != csrfBefore {
		t.Fatal("authenticated session CSRF token changed across Thawguard restart")
	}
	freezeAfterStart := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"))
	if freezeAfterStart != freezeBefore {
		t.Fatalf("active freeze changed across Thawguard restart: before=%+v after=%+v", freezeBefore, freezeAfterStart)
	}

	waitFor(t, 75*time.Second, "persisted repository recovery work to converge frozen policy", func() (bool, error) {
		repositoriesPage, err := browser.get(ctx, "/repositories")
		if err != nil {
			return false, err
		}
		activityPage, err := browser.get(ctx, "/activity")
		if err != nil {
			return false, err
		}
		statuses, err := listForgejoFreezeStatuses(ctx, forgejo, pr.Head.SHA)
		if err != nil {
			return false, err
		}
		if len(statuses) == 0 {
			return false, nil
		}
		latest := statuses[len(statuses)-1]
		return latest.ID > injected.ID &&
			latest.Status == "failure" &&
			latest.Description == "Branch is frozen; merge is blocked by Thawguard" &&
			strings.Contains(repositoriesPage, `<span class="tg-badge status-ok">enforcement active</span>`) &&
			!strings.Contains(repositoriesPage, "Enforcement is unhealthy") &&
			!strings.Contains(repositoriesPage, "Automatic recovery is pending") &&
			strings.Contains(activityPage, `<td data-label="Actor">Reconciliation runner</td>`) &&
			strings.Contains(activityPage, `<td data-label="Action">Enforcement recovery</td>`) &&
			strings.Contains(activityPage, "1 open PRs evaluated; 1 statuses posted and 0 failed."), nil
	})

	repositoriesAfter := requirePage(t, ctx, browser, "/repositories")
	if csrfAfter := requireHiddenInput(t, repositoriesAfter, "csrf_token"); csrfAfter != csrfBefore {
		t.Fatal("authenticated session CSRF token changed after restarted recovery")
	}
	for _, want := range []string{
		"<strong>Webhook secret</strong>",
		"Stored encrypted. Hidden until you intentionally rotate it.",
		"<strong>Status token</strong>",
		"Stored encrypted. Hidden until rotation.",
	} {
		if !strings.Contains(repositoriesAfter, want) {
			t.Fatalf("restarted repository page is missing encrypted credential evidence %q", want)
		}
	}
	if strings.Contains(repositoriesAfter, "Enforcement is unhealthy") || strings.Contains(repositoriesAfter, "Automatic recovery is pending") || strings.Contains(repositoriesAfter, "Recovery in progress") {
		t.Fatal("restarted repository still reports unhealthy or pending recovery after convergence")
	}
	requireRepairedReleaseReadiness(t, ctx, browser)
	if freezeAfter := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); freezeAfter != freezeBefore {
		t.Fatalf("active freeze changed after restarted recovery: before=%+v after=%+v", freezeBefore, freezeAfter)
	}

	activityAfter := requirePage(t, ctx, browser, "/activity")
	recoveryRow := requireLatestActivityRow(t, activityAfter, "Enforcement recovery")
	for _, want := range []string{
		`<td data-label="Actor">Reconciliation runner</td>`,
		`<td data-label="Outcome"><span class="status status-ok">Succeeded</span></td>`,
		"1 open PRs evaluated; 1 statuses posted and 0 failed.",
	} {
		if !strings.Contains(recoveryRow, want) {
			t.Fatalf("automatic recovery activity row is missing %q", want)
		}
	}
	if !strings.Contains(activityAfter, freezeHistoryBefore) {
		t.Fatal("pre-restart branch-freeze history row did not survive restart")
	}

	evidenceAfter := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, pr.Head.SHA)
	if evidenceAfter.webhookRows != evidenceBefore.webhookRows {
		t.Fatalf("restart recovery changed webhook rows from %d to %d", evidenceBefore.webhookRows, evidenceAfter.webhookRows)
	}
	if evidenceAfter.publicationIntents != evidenceBefore.publicationIntents {
		t.Fatalf("restart recovery changed publication intents from %d to %d, want existing intent reused", evidenceBefore.publicationIntents, evidenceAfter.publicationIntents)
	}
	if evidenceAfter.publicationAttempts != evidenceBefore.publicationAttempts+1 {
		t.Fatalf("restart recovery changed publication attempts by %d, want 1", evidenceAfter.publicationAttempts-evidenceBefore.publicationAttempts)
	}
	publicationRow := requireLatestPublicationAttemptRow(t, requirePage(t, ctx, browser, "/publications"))
	for _, want := range []string{pr.Head.SHA, requiredContext, ">failure</span>", ">posted</span>", "Branch is frozen; merge is blocked by Thawguard"} {
		if !strings.Contains(publicationRow, want) {
			t.Fatalf("restart recovery publication attempt is missing %q", want)
		}
	}

	if len(evidenceAfter.freezeStatuses) != len(evidenceBefore.freezeStatuses)+2 {
		t.Fatalf("restart drift and recovery added %d Forgejo statuses, want 2", len(evidenceAfter.freezeStatuses)-len(evidenceBefore.freezeStatuses))
	}
	recovered := evidenceAfter.freezeStatuses[len(evidenceAfter.freezeStatuses)-1]
	if !(oldFailure.ID < injected.ID && injected.ID < recovered.ID) {
		t.Fatalf("required status ID ordering is %d < %d < %d, want strict old-failure < injected-success < recovered-failure", oldFailure.ID, injected.ID, recovered.ID)
	}
	if injected.Context != requiredContext || injected.Status != "success" || injected.Description != injectedDriftDescription {
		t.Fatalf("unexpected injected drift status: id=%d context=%q state=%q description=%q", injected.ID, injected.Context, injected.Status, injected.Description)
	}
	if recovered.Context != requiredContext || recovered.Status != "failure" || recovered.Description != "Branch is frozen; merge is blocked by Thawguard" {
		t.Fatalf("unexpected recovered required status: id=%d context=%q state=%q description=%q", recovered.ID, recovered.Context, recovered.Status, recovered.Description)
	}
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, pr.Number)
}

func postInjectedDriftStatus(t *testing.T, ctx context.Context, forgejo *forgejoAPI, headSHA string) commitStatus {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("statuses", headSHA), map[string]string{
		"context":     requiredContext,
		"state":       "success",
		"description": injectedDriftDescription,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "post fictional Forgejo status drift")
	var status commitStatus
	decodeJSON(t, response.body, &status, "decode fictional Forgejo status drift")
	if status.ID <= 0 || status.Context != requiredContext || status.Status != "success" || status.Description != injectedDriftDescription {
		t.Fatalf("Forgejo returned invalid fictional drift status: id=%d context=%q state=%q description=%q", status.ID, status.Context, status.Status, status.Description)
	}
	return status
}

func revokePrimaryStatusToken(t *testing.T, ctx context.Context, forgejo *forgejoAPI, ownerPassword string) {
	t.Helper()
	path := "/api/v1/users/" + url.PathEscape(fixtureOwner) + "/tokens/" + url.PathEscape(primaryStatusTokenName)
	response, err := forgejo.doBasicAuth(ctx, http.MethodDelete, path, fixtureOwner, ownerPassword)
	requireAPIStatus(t, response, err, http.StatusNoContent, "revoke primary Forgejo status token by name")
}

func advanceFeatureBranch(t *testing.T, ctx context.Context, forgejo *forgejoAPI, pullRequestIndex int, expectedPreviousSHA, fixtureFilename, commitMessage, content, evidenceLabel string) string {
	t.Helper()
	if fixtureFilename != "token-loss.txt" && fixtureFilename != "stale-head-thaw.txt" {
		t.Fatalf("branch-advance fixture filename %q is not allowlisted", fixtureFilename)
	}
	evidenceLabel = strings.TrimSpace(evidenceLabel)
	if evidenceLabel == "" || strings.ContainsAny(evidenceLabel, "\r\n") {
		t.Fatal("branch-advance evidence label must be non-empty and single-line")
	}
	expectedPreviousSHA = strings.ToLower(strings.TrimSpace(expectedPreviousSHA))
	if expectedPreviousSHA == "" {
		t.Fatalf("%s branch advance requires an expected previous SHA", evidenceLabel)
	}

	response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("pulls", strconv.Itoa(pullRequestIndex)), nil)
	requireAPIStatus(t, response, err, http.StatusOK, "read "+evidenceLabel+" pull request before branch advance")
	var previous pullRequest
	decodeJSON(t, response.body, &previous, "decode "+evidenceLabel+" pull request before branch advance")
	actualPreviousSHA := strings.ToLower(strings.TrimSpace(previous.Head.SHA))
	if actualPreviousSHA != expectedPreviousSHA {
		t.Fatalf("%s branch advance found current SHA %q, want exact previous SHA %q", evidenceLabel, actualPreviousSHA, expectedPreviousSHA)
	}

	response, err = forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("contents", url.PathEscape(fixtureFilename)), map[string]any{
		"branch":  fixtureFeatureBranch,
		"message": commitMessage,
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo "+evidenceLabel+" fixture commit")
	var created struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	decodeJSON(t, response.body, &created, "decode Forgejo "+evidenceLabel+" fixture commit")
	newHeadSHA := strings.ToLower(strings.TrimSpace(created.Commit.SHA))
	if newHeadSHA == "" || newHeadSHA == expectedPreviousSHA {
		t.Fatalf("Forgejo %s fixture did not create a distinct commit SHA", evidenceLabel)
	}

	waitFor(t, 30*time.Second, "Forgejo "+evidenceLabel+" pull request head advance", func() (bool, error) {
		response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("pulls", strconv.Itoa(pullRequestIndex)), nil)
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

func waitForOneNewProcessedPullRequestDelivery(t *testing.T, ctx context.Context, browser *thawguardBrowser, repositoryID int64, beforeRows int, action string) {
	t.Helper()
	if action != "opened" && action != "synchronized" {
		t.Fatalf("pull request delivery action %q is not allowlisted", action)
	}
	webhookPath := "/webhooks?" + url.Values{
		"repository_id": {strconv.FormatInt(repositoryID, 10)},
		"event":         {"pull_request"},
		"limit":         {"100"},
	}.Encode()
	expectedRows := beforeRows + 1
	waitFor(t, 30*time.Second, "one new verified and processed "+action+" delivery", func() (bool, error) {
		page, err := browser.get(ctx, webhookPath)
		if err != nil {
			return false, err
		}
		rows := requirePageCount(t, page, webhookRowsPattern, "webhook rows")
		if rows > expectedRows {
			t.Fatalf("%s pull request delivery changed webhook rows from %d to %d, want exactly %d", action, beforeRows, rows, expectedRows)
		}
		if rows != expectedRows {
			return false, nil
		}
		latestRow := requireLatestWebhookDeliveryRow(t, page)
		for _, want := range []string{
			`<code>` + fixtureOwner + `/` + fixtureRepository + `</code>`,
			`<td data-label="Event"><code>pull_request</code><small class="tg-muted">` + action + `</small></td>`,
			`>verified</span>`,
			`>processed</span>`,
			`<td data-label="Details">No processing error</td>`,
		} {
			if !strings.Contains(latestRow, want) {
				return false, nil
			}
		}
		return true, nil
	})
}

func requireLatestWebhookDeliveryRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := "<h2>Signed webhook deliveries</h2>"
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("webhook page is missing signed deliveries")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("signed webhook deliveries are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], `<tr id="delivery-`)
	if rowStartOffset < 0 {
		t.Fatal("signed webhook deliveries are missing their latest row")
	}
	rowStart := tbodyStart + rowStartOffset
	rowEndOffset := strings.Index(page[rowStart:], "</tr>")
	if rowEndOffset < 0 {
		t.Fatal("latest signed webhook delivery row is incomplete")
	}
	return page[rowStart : rowStart+rowEndOffset+len("</tr>")]
}

func countOpenPullRequestSyncEvents(page string) int {
	return strings.Count(page, `<td data-label="Action">Open pull request sync</td>`)
}

func countSharedHeadThawEvents(page string) int {
	return strings.Count(page, `<td data-label="Action">Shared-head thaw</td>`)
}

func countEligibleDecisionRows(page string) int {
	return strings.Count(page, `<span class="status status-success">Eligible</span>`)
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

func requireLatestOpenPullRequestSync(t *testing.T, page string, expectedOpen int) {
	t.Helper()
	row := requireLatestActivityRow(t, page, "Open pull request sync")
	want := strconv.Itoa(expectedOpen) + " open PRs synchronized; 0 cached PRs marked closed."
	if !strings.Contains(row, want) {
		t.Fatalf("latest forge sync did not contain %q", want)
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

func requireUnprotectedReleaseReadinessFailure(t *testing.T, ctx context.Context, browser *thawguardBrowser, repositoryID int64) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/repositories")
	requirePostForm(t, ctx, browser, "/repositories/setup-check", url.Values{
		"csrf_token":    {requireHiddenInput(t, page, "csrf_token")},
		"repository_id": {strconv.FormatInt(repositoryID, 10)},
	}, "run readiness checks with release unprotected")

	page = requirePage(t, ctx, browser, "/repositories")
	releaseRow := requireManagedBranchRow(t, page, fixtureReleaseBranch)
	for _, want := range []string{
		`<span class="tg-badge status-failed">failed</span>`,
		`<span class="status status-ok">passed</span><div><strong>Branch protection readable</strong><small>The forge confirmed that this exact managed branch has no branch protection configuration.`,
		`<span class="status status-failed">failed</span><div><strong>Branch protection enabled</strong>`,
		`<span class="status status-failed">failed</span><div><strong>Required status checks enabled</strong>`,
		`<span class="status status-failed">failed</span><div><strong>Required thawguard/freeze context configured</strong>`,
	} {
		if !strings.Contains(releaseRow, want) {
			t.Fatalf("unprotected release readiness row is missing %q", want)
		}
	}
	for _, absent := range []string{
		`action="/repositories/status-verification"`,
		`action="/repositories/activate"`,
	} {
		if strings.Contains(page, absent) {
			t.Fatalf("failed readiness unexpectedly offered form %s", absent)
		}
	}
	for _, want := range []string{
		`<span class="tg-badge status-warning">setup incomplete</span>`,
		`disabled>Verify status posting</button>`,
		`Fix the failing readiness checks and rerun them. Verification is offered once every mandatory read-only check passes.`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("failed readiness page is missing %q", want)
		}
	}

	activityRow := requireLatestActivityRow(t, requirePage(t, ctx, browser, "/activity"), "Readiness check")
	if want := "8 passed, 1 warnings, 3 failed across 2 managed branches; webhook evidence fresh."; !strings.Contains(activityRow, want) {
		t.Fatalf("failed readiness activity is missing %q", want)
	}
}

func requireRepairedReleaseReadiness(t *testing.T, ctx context.Context, browser *thawguardBrowser) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/repositories")
	releaseRow := requireManagedBranchRow(t, page, fixtureReleaseBranch)
	for _, want := range []string{
		`<span class="tg-badge status-ok">passed</span>`,
		`<span class="status status-ok">passed</span><div><strong>Branch protection readable</strong>`,
		`<span class="status status-ok">passed</span><div><strong>Branch protection enabled</strong>`,
		`<span class="status status-ok">passed</span><div><strong>Required status checks enabled</strong>`,
		`<span class="status status-ok">passed</span><div><strong>Required thawguard/freeze context configured</strong>`,
	} {
		if !strings.Contains(releaseRow, want) {
			t.Fatalf("repaired release readiness row is missing %q", want)
		}
	}
	if !strings.Contains(page, `<span class="tg-badge status-ok">enforcement active</span>`) {
		t.Fatal("repaired repository did not reach enforcement-active state")
	}

	activityRow := requireLatestActivityRow(t, requirePage(t, ctx, browser, "/activity"), "Readiness check")
	if want := "11 passed, 1 warnings, 0 failed across 2 managed branches; webhook evidence fresh."; !strings.Contains(activityRow, want) {
		t.Fatalf("successful readiness activity is missing %q", want)
	}
}

func requireManagedBranchRow(t *testing.T, page, branch string) string {
	t.Helper()
	marker := `<code class="tg-branch">` + html.EscapeString(branch) + `</code>`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("managed branch %q is missing from repositories page", branch)
	}
	rowStart := strings.LastIndex(page[:markerIndex], `<li class="tg-branch-row">`)
	rowEndOffset := strings.Index(page[markerIndex:], "</li>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("managed branch %q is missing its branch row", branch)
	}
	return page[rowStart : markerIndex+rowEndOffset+len("</li>")]
}

func requireLatestActivityRow(t *testing.T, page, action string) string {
	t.Helper()
	marker := `<td data-label="Action">` + html.EscapeString(action) + `</td>`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("activity is missing a %q event", action)
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr>")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("latest %q event is missing its activity row", action)
	}
	return page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func requireActiveFreezeEvidence(t *testing.T, page string) activeFreezeEvidence {
	t.Helper()
	marker := `<form method="post" action="/freezes/end"`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatal("active freeze is missing its desktop action row")
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr>")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatal("active freeze is missing its desktop table row")
	}
	row := page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
	id, err := strconv.ParseInt(requireHiddenInput(t, row, "freeze_id"), 10, 64)
	if err != nil || id <= 0 {
		t.Fatalf("parse active freeze ID: %v", err)
	}
	return activeFreezeEvidence{
		id:     id,
		branch: requirePatternText(t, row, activeFreezeBranchPattern, "active freeze branch"),
		reason: requirePatternText(t, row, activeFreezeReasonPattern, "active freeze reason"),
		status: requirePatternText(t, row, activeFreezeStatusPattern, "active freeze status"),
	}
}

func requireNoActiveFreezeEvidence(t *testing.T, page string, freeze activeFreezeEvidence) {
	t.Helper()
	for _, want := range []string{`<span class="tg-badge">0 active</span>`, "No active freezes yet"} {
		if !strings.Contains(page, want) {
			t.Fatalf("freezes page is missing inactive evidence %q for freeze %d", want, freeze.id)
		}
	}
	for _, absent := range []string{
		`name="freeze_id" value="` + strconv.FormatInt(freeze.id, 10) + `"`,
		html.EscapeString(freeze.reason),
		`action="/freezes/end"`,
		`action="/freezes/cancel"`,
	} {
		if strings.Contains(page, absent) {
			t.Fatalf("inactive freeze %d still renders active evidence %q", freeze.id, absent)
		}
	}
}

func requireBranchFreezeActivityEvidence(t *testing.T, row string, freeze activeFreezeEvidence, outcome, outcomeClass string) {
	t.Helper()
	for _, want := range []string{
		`<td data-label="Actor">E2E Admin</td>`,
		`<td data-label="Action">Branch freeze</td>`,
		`<td data-label="Target">` + fixtureOwner + `/` + fixtureRepository + ` → ` + html.EscapeString(freeze.branch) + `</td>`,
		`<td data-label="Outcome"><span class="status status-` + outcomeClass + `">` + outcome + `</span></td>`,
		`<td data-label="Details">Reason: ` + html.EscapeString(freeze.reason),
	} {
		if !strings.Contains(row, want) {
			t.Fatalf("branch-freeze activity for freeze %d is missing %q", freeze.id, want)
		}
	}
}

func requireLatestPublicationIntentRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := "<h2>Latest desired statuses</h2>"
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("publications page is missing latest desired statuses")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("latest desired statuses are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr>")
	if rowStartOffset < 0 {
		t.Fatal("latest desired statuses are missing their latest row")
	}
	rowStart := tbodyStart + rowStartOffset
	rowEndOffset := strings.Index(page[rowStart:], "</tr>")
	if rowEndOffset < 0 {
		t.Fatal("latest desired status row is incomplete")
	}
	return page[rowStart : rowStart+rowEndOffset+len("</tr>")]
}

func requireLatestPublicationAttemptRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := "<h2>Recent publication attempts</h2>"
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("publications page is missing recent publication attempts")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("recent publication attempts are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr>")
	if rowStartOffset < 0 {
		t.Fatal("recent publication attempts are missing their latest row")
	}
	rowStart := tbodyStart + rowStartOffset
	rowEndOffset := strings.Index(page[rowStart:], "</tr>")
	if rowEndOffset < 0 {
		t.Fatal("latest publication attempt row is incomplete")
	}
	return page[rowStart : rowStart+rowEndOffset+len("</tr>")]
}

func requireLatestDecisionResultRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := "<h2>Thaw approval results</h2>"
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("decisions page is missing thaw approval results")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("thaw approval results are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr>")
	if rowStartOffset < 0 {
		t.Fatal("thaw approval results are missing their latest row")
	}
	rowStart := tbodyStart + rowStartOffset
	rowEndOffset := strings.Index(page[rowStart:], "</tr>")
	if rowEndOffset < 0 {
		t.Fatal("latest thaw approval result row is incomplete")
	}
	return page[rowStart : rowStart+rowEndOffset+len("</tr>")]
}

func requireDecisionResultRowForHead(t *testing.T, page, headSHA string) string {
	t.Helper()
	sectionMarker := "<h2>Thaw approval results</h2>"
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("decisions page is missing thaw approval results")
	}
	marker := `<code>` + html.EscapeString(headSHA) + `</code>`
	markerOffset := strings.Index(page[sectionStart:], marker)
	if markerOffset < 0 {
		t.Fatalf("thaw approval results are missing head %q", headSHA)
	}
	markerIndex := sectionStart + markerOffset
	rowStart := strings.LastIndex(page[sectionStart:markerIndex], "<tr>")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("thaw approval result for head %q is incomplete", headSHA)
	}
	rowStart += sectionStart
	return page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func waitForLatestPostedPublicationAttempt(t *testing.T, ctx context.Context, browser *thawguardBrowser, headSHA, state, description string) {
	t.Helper()
	wants := []string{
		headSHA,
		`<small class="tg-muted">` + requiredContext + `</small>`,
		`<td data-label="State"><span class="status status-` + state + `">` + state + `</span></td>`,
		`<td data-label="Mode"><code>forgejo_status</code></td>`,
		`<td data-label="Result"><span class="status status-ok">posted</span></td>`,
		description,
	}
	waitFor(t, 30*time.Second, "recorded "+requiredContext+"="+state+" Forgejo publication attempt", func() (bool, error) {
		page, err := browser.get(ctx, "/publications")
		if err != nil {
			return false, err
		}
		row := requireLatestPublicationAttemptRow(t, page)
		for _, want := range wants {
			if !strings.Contains(row, want) {
				return false, nil
			}
		}
		return true, nil
	})
}

func requirePatternText(t *testing.T, value string, pattern *regexp.Regexp, label string) string {
	t.Helper()
	match := pattern.FindStringSubmatch(value)
	if len(match) != 2 {
		t.Fatalf("could not read %s", label)
	}
	return html.UnescapeString(strings.TrimSpace(match[1]))
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

func createFreeze(t *testing.T, ctx context.Context, browser *thawguardBrowser, repositoryID int64, reason string) activeFreezeEvidence {
	t.Helper()
	page := requirePage(t, ctx, browser, "/freezes")
	csrf := requireHiddenInput(t, page, "csrf_token")
	requirePostForm(t, ctx, browser, "/freezes", url.Values{
		"csrf_token":              {csrf},
		"repository_id":           {strconv.FormatInt(repositoryID, 10)},
		"branch":                  {"main"},
		"reason":                  {reason},
		"timezone_offset_minutes": {"0"},
	}, "create Thawguard freeze")
	created := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"))
	if created.branch != "main" || created.reason != reason || created.status != "active" {
		t.Fatalf("created freeze has unexpected rendered evidence: id=%d branch=%q reason=%q status=%q", created.id, created.branch, created.reason, created.status)
	}
	return created
}

func liftFreeze(t *testing.T, ctx context.Context, browser *thawguardBrowser, freeze activeFreezeEvidence) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/freezes")
	if active := requireActiveFreezeEvidence(t, page); active != freeze {
		t.Fatalf("refusing to lift the wrong freeze: want=%+v rendered=%+v", freeze, active)
	}
	csrf := requireHiddenInput(t, page, "csrf_token")
	requirePostForm(t, ctx, browser, "/freezes/end", url.Values{
		"csrf_token": {csrf},
		"freeze_id":  {strconv.FormatInt(freeze.id, 10)},
	}, "lift Thawguard freeze")
}

func cancelFreeze(t *testing.T, ctx context.Context, browser *thawguardBrowser, freeze activeFreezeEvidence) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/freezes")
	if active := requireActiveFreezeEvidence(t, page); active != freeze {
		t.Fatalf("refusing to cancel the wrong freeze: want=%+v rendered=%+v", freeze, active)
	}
	if !strings.Contains(page, `action="/freezes/cancel"`) {
		t.Fatalf("active freeze %d is missing its cancel action", freeze.id)
	}
	requirePostForm(t, ctx, browser, "/freezes/cancel", url.Values{
		"csrf_token": {requireHiddenInput(t, page, "csrf_token")},
		"freeze_id":  {strconv.FormatInt(freeze.id, 10)},
	}, "cancel active Thawguard freeze")
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

func (b *thawguardBrowser) postFormNoRedirect(ctx context.Context, path string, values url.Values) (apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return apiResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", b.baseURL)
	client := *b.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return apiResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return apiResponse{}, err
	}
	return apiResponse{statusCode: resp.StatusCode, body: body, location: resp.Header.Get("Location")}, nil
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

func requireRenderedForm(t *testing.T, page, marker, label string) string {
	t.Helper()
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatalf("page is missing the %s form", label)
	}
	endOffset := strings.Index(page[start:], "</form>")
	if endOffset < 0 {
		t.Fatalf("%s form is incomplete", label)
	}
	return page[start : start+endOffset+len("</form>")]
}

func requireSharedHeadConfirmationRow(t *testing.T, page string, pullRequestIndex int) string {
	t.Helper()
	marker := `<td class="tg-shared-head-index">#` + strconv.Itoa(pullRequestIndex)
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("shared-head confirmation is missing PR #%d", pullRequestIndex)
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr>")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("shared-head confirmation PR #%d row is incomplete", pullRequestIndex)
	}
	return page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func requireOnlyFormInputNames(t *testing.T, form string, expected []string) {
	t.Helper()
	matches := formInputNamePattern.FindAllStringSubmatch(form, -1)
	totalInputs := strings.Count(strings.ToLower(form), "<input")
	if len(matches) != len(expected) || totalInputs != len(expected) {
		t.Fatalf("confirmation form rendered %d named inputs and %d total inputs, want %d", len(matches), totalInputs, len(expected))
	}
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, html.UnescapeString(match[1]))
	}
	want := slices.Clone(expected)
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("confirmation form inputs are %q, want only %q", names, want)
	}
}

var (
	nonzeroMatchingRows        = regexp.MustCompile(`Showing [1-9][0-9]* of [1-9][0-9]* matching rows`)
	webhookRowsPattern         = regexp.MustCompile(`Showing ([0-9]+) of [0-9]+ matching rows`)
	statusResultsPattern       = regexp.MustCompile(`Thaw approval results</h2><span[^>]*>([0-9]+) status results</span>`)
	publicationIntentsPattern  = regexp.MustCompile(`Latest desired statuses</h2><span[^>]*>([0-9]+) shown</span>`)
	publicationAttemptsPattern = regexp.MustCompile(`Recent publication attempts</h2><span[^>]*>([0-9]+) shown</span>`)
	activityEventsPattern      = regexp.MustCompile(`Recent activity</h2><span[^>]*>([0-9]+) shown</span>`)
	activeFreezeBranchPattern  = regexp.MustCompile(`<code class="tg-branch">([^<]+)</code>`)
	activeFreezeReasonPattern  = regexp.MustCompile(`<td class="tg-freeze-reason">([^<]+)</td>`)
	activeFreezeStatusPattern  = regexp.MustCompile(`<span class="status status-frozen">([^<]+)</span>`)
	formInputNamePattern       = regexp.MustCompile(`(?i)<input\b[^>]*\bname="([^"]+)"[^>]*>`)
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
