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
	fixtureScheduledBranch   = "scheduled-transition"
	fixturePrimaryPRTitle    = "Fictional release check"
	fixtureSharedHeadPRTitle = "Fictional shared-head confirmation"
	fixtureScheduledPRTitle  = "Fictional scheduled release transition"
	fixtureScheduledFilename = "scheduled-transition.txt"
	fixtureRoleThawFilename  = "role-boundary-thaw.txt"
	primaryStatusTokenName   = "thawguard-e2e-status-primary"
	requiredContext          = "thawguard/freeze"
	e2eComposeProject        = "thawguard-e2e"
	thawguardSessionCookie   = "thawguard_session"
	injectedDriftDescription = "E2E injected status drift while Thawguard was stopped"
	invalidDeliveryID        = "e2e-invalid-signature-fixture"
	duplicateDeliveryID      = "e2e-duplicate-delivery-fixture"
	invalidSignatureSecret   = "invalid-e2e-signing-secret"
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
	Merged  bool   `json:"merged"`
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

type scheduledFreezeRowEvidence struct {
	id            int64
	branch        string
	reason        string
	startsAt      string
	plannedEndsAt string
	status        string
	endedAt       string
	row           string
}

type scheduledFreezeLifecycleFixture struct {
	freezeID                       int64
	releasePullRequestIndex        int
	releaseHeadSHA                 string
	plannedEndsAt                  time.Time
	activeScheduleA                scheduledFreezeRowEvidence
	cancelledScheduleB             scheduledFreezeRowEvidence
	activeReleaseFreeze            activeFreezeEvidence
	activeMainFreeze               activeFreezeEvidence
	primaryPullRequestIndex        int
	sharedHeadPullRequestIndex     int
	sharedHeadSHA                  string
	mainSharedHeadStatuses         []commitStatus
	historicalThawedHeadSHA        string
	historicalThawedHeadStatuses   []commitStatus
	historicalEligibleDecisionRow  string
	historicalSinglePRThawActivity string
}

type roleBoundarySession struct {
	displayName   string
	email         string
	roleLabel     string
	browser       *thawguardBrowser
	csrfToken     string
	sessionCookie string
}

type roleBoundaryEvidence struct {
	userCount        int
	repositoryCount  int
	activeFreezes    int
	scheduledCount   int
	usersPage        string
	repositoriesPage string
	mainFreeze       activeFreezeEvidence
	schedules        []scheduledFreezeRowEvidence
	sideEffects      webhookSideEffectEvidence
	statusHistories  [][]commitStatus
}

type terminalActivityEvidence struct {
	sharedHeadThaw     string
	plannedUnfreeze    string
	scheduleCCreated   string
	scheduleCEdited    string
	scheduleCStarted   string
	scheduleCCancelled string
	roleBoundaryThaw   string
}

type terminalDiagnosticsFixture struct {
	uniqueHeadSHA           string
	roleSessions            []roleBoundarySession
	scheduleReasons         []string
	expectedSideEffects     webhookSideEffectEvidence
	activity                terminalActivityEvidence
	allowedDecision         string
	terminalReleaseDelivery string
	roleBoundaryDelivery    string
}

type terminalReadOnlySnapshot struct {
	evidence        roleBoundaryEvidence
	roleSessions    []roleBoundarySession
	pullRequests    []pullRequest
	diagnosticPages [4]string
}

type webhookPageSummary struct {
	showing int
	total   int
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
	pr := createForgejoPullRequest(t, ctx, forgejo, fixtureFeatureBranch, "main", fixturePrimaryPRTitle)

	waitFor(t, 30*time.Second, "verified Forgejo webhook delivery", func() (bool, error) {
		page, err := browser.get(ctx, "/webhooks?processing=processed")
		if err != nil {
			return false, err
		}
		return strings.Contains(page, fixtureOwner+"/"+fixtureRepository) &&
			strings.Contains(page, "pull_request · opened") &&
			strings.Contains(page, ">Verified</span>") &&
			nonzeroDeliveryCountPattern.MatchString(page), nil
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

	openPullRequestSyncsBeforeProbes := countOpenPullRequestSyncEvents(requireAllActivityPages(t, ctx, browser))

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
	sharedHeadPR := proveSharedHeadConfirmation(t, ctx, forgejo, browser, repositoryID, pr.Number, historicalThawedHeadSHA, newHeadSHA)
	scanRenderedTokenSurfaces(t, ctx, browser)
	plannedUnfreezeFixture := proveScheduledFreezeLifecycle(t, ctx, forgejo, browser, repositoryID, pr.Number, sharedHeadPR, historicalThawedHeadSHA, newHeadSHA)
	if plannedUnfreezeFixture.freezeID <= 0 || plannedUnfreezeFixture.releasePullRequestIndex <= 0 || plannedUnfreezeFixture.releaseHeadSHA == "" || !plannedUnfreezeFixture.plannedEndsAt.After(time.Now().UTC()) || plannedUnfreezeFixture.activeReleaseFreeze.id != plannedUnfreezeFixture.freezeID || len(plannedUnfreezeFixture.mainSharedHeadStatuses) == 0 {
		t.Fatalf("scheduled lifecycle did not retain a complete planned-unfreeze fixture: %+v", plannedUnfreezeFixture)
	}
	provePlannedUnfreezeAcrossRestart(t, ctx, forgejo, browser, cfg, repositoryID, plannedUnfreezeFixture)
	roleBoundaryFixture := proveRoleBoundaries(t, ctx, forgejo, browser, cfg, repositoryID, plannedUnfreezeFixture)
	proveAuditAndDiagnosticsEvidence(t, ctx, forgejo, cfg, repositoryID, plannedUnfreezeFixture, roleBoundaryFixture)
}

func proveActiveFreezeCancellation(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, pullRequestIndex int, headSHA string, firstFreeze activeFreezeEvidence) {
	t.Helper()
	const cancellationReason = "Fictional cancellation verification."

	requireNoActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"), firstFreeze)
	firstLiftRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Branch freeze")
	requireBranchFreezeActivityEvidence(t, firstLiftRow, firstFreeze, "Lifted")

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
	activityBefore := requireAllActivityPages(t, ctx, browser)
	createdRow := requireLatestActivityRow(t, activityBefore, "Branch freeze")
	requireBranchFreezeActivityEvidence(t, createdRow, secondFreeze, "Frozen")
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

	activityAfter := requireAllActivityPages(t, ctx, browser)
	cancelledRow := requireLatestActivityRow(t, activityAfter, "Branch freeze")
	requireBranchFreezeActivityEvidence(t, cancelledRow, secondFreeze, "Cancelled")
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
	openPullRequestSyncsBefore := countOpenPullRequestSyncEvents(requireAllActivityPages(t, ctx, browser))

	decisionsPage := requirePage(t, ctx, browser, "/decisions")
	renderedThawForm := requireRenderedForm(t, decisionsPage, `<form method="post" action="/decisions"`, "immediate thaw")
	if !strings.Contains(renderedThawForm, `name="pull_request_index"`) {
		t.Fatal("decisions page is missing the immediate thaw form")
	}
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
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/decisions?notice=thaw-approved" {
		t.Fatalf("immediate per-PR thaw returned HTTP %d with Location %q, want 303 to /decisions?notice=thaw-approved", response.StatusCode, response.Header.Get("Location"))
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

	decisionsAfter := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsAfter, `>`+requiredContext+`</code>`) {
		t.Fatalf("decisions page no longer displays the required context %q", requiredContext)
	}
	decisionRow := requireLatestDecisionResultRow(t, decisionsAfter)
	for _, want := range []string{
		`>#` + strconv.Itoa(pullRequestIndex) + `</code>`,
		fixtureOwner + `/` + fixtureRepository,
		`>main</code>`,
		`title="` + headSHA + `"`,
		explicitThaw,
		`>Eligible</span>`,
	} {
		if !strings.Contains(decisionRow, want) {
			t.Fatalf("latest immediate-thaw decision row is missing %q", want)
		}
	}

	thawActivityRow := requireLatestActivityRow(t, activityPage, "Single-PR thaw")
	for _, want := range []string{
		`>E2E Admin</td>`,
		`>` + fixtureOwner + `/` + fixtureRepository + ` → PR #` + strconv.Itoa(pullRequestIndex) + `</td>`,
		`>Approved</span>`,
		`Branch main; head ` + strings.ToLower(headSHA[:12]) + `. Reason: ` + thawReason + `.`,
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
		`>#` + strconv.Itoa(pullRequestIndex) + `</code>`,
		fixtureOwner + `/` + fixtureRepository,
		`>main</code>`,
		`title="` + oldHeadSHA + `"`,
		explicitThaw,
		`>Eligible</span>`,
	} {
		if !strings.Contains(oldDecisionRow, want) {
			t.Fatalf("old exact-head decision row is missing %q", want)
		}
	}

	activityBefore := requireAllActivityPages(t, ctx, browser)
	oldThawActivityRow := requireLatestActivityRow(t, activityBefore, "Single-PR thaw")
	if want := `Branch main; head ` + oldHeadSHA[:12] + `.`; !strings.Contains(oldThawActivityRow, want) {
		t.Fatalf("old Single-PR thaw activity row is missing %q", want)
	}

	thirdFreeze := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes"))
	if thirdFreeze.branch != "main" || thirdFreeze.reason != freezeReason || thirdFreeze.status != "Frozen" {
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
		`>#` + strconv.Itoa(pullRequestIndex) + `</code>`,
		fixtureOwner + `/` + fixtureRepository,
		`>main</code>`,
		`title="` + newHeadSHA + `"`,
		frozenReason,
		`>Blocked</span>`,
	} {
		if !strings.Contains(newDecisionRow, want) {
			t.Fatalf("latest stale-head decision row is missing %q", want)
		}
	}

	activityAfter := requireAllActivityPages(t, ctx, browser)
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
			`PR #` + strconv.Itoa(pullRequestIndex) + ` · main`,
			`title="` + newHeadSHA + `"`,
			`>` + requiredContext + `</code>`,
			frozenReason,
		} {
			if !strings.Contains(row, want) {
				t.Fatalf("latest stale-head publication %s is missing %q", label, want)
			}
		}
	}
	for _, want := range []string{`>failure</span>`, `>forgejo_status</code>`} {
		if !strings.Contains(newIntentRow, want) {
			t.Fatalf("latest stale-head publication intent is missing %q", want)
		}
	}
	for _, want := range []string{`>posted</span>`, `>failure · forgejo_status</code>`} {
		if !strings.Contains(newAttemptRow, want) {
			t.Fatalf("latest stale-head publication attempt is missing %q", want)
		}
	}

	if active := requireActiveFreezeEvidence(t, requirePage(t, ctx, browser, "/freezes")); active != thirdFreeze {
		t.Fatalf("third active freeze changed after stale-head reevaluation: before=%+v after=%+v", thirdFreeze, active)
	}
	return newHeadSHA
}

func proveSharedHeadConfirmation(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, primaryPullRequestIndex int, historicalThawedHeadSHA, sharedHeadSHA string) pullRequest {
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
	if activeFreeze.branch != "main" || activeFreeze.status != "Frozen" {
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
	historicalActivityPage := requireAllActivityPages(t, ctx, browser)
	historicalThawRow := requireLatestActivityRow(t, historicalActivityPage, "Single-PR thaw")
	if !strings.Contains(historicalThawRow, "head "+historicalThawedHeadSHA[:12]+".") {
		t.Fatalf("historical Single-PR thaw row is missing head %q", historicalThawedHeadSHA[:12])
	}
	historicalDecisionRow := requireDecisionResultRowForHead(t, requirePage(t, ctx, browser, "/decisions"), historicalThawedHeadSHA)
	for _, want := range []string{explicitThaw, `>Eligible</span>`} {
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

	secondaryPR := createForgejoPullRequest(t, ctx, forgejo, fixtureSharedHeadBranch, "main", fixtureSharedHeadPRTitle)
	if secondaryPR.Number == primaryPullRequestIndex {
		t.Fatalf("second Forgejo pull request reused primary number %d", primaryPullRequestIndex)
	}
	if secondaryPR.Head.SHA != sharedHeadSHA {
		t.Fatalf("second Forgejo pull request head %q does not equal primary shared SHA %q", secondaryPR.Head.SHA, sharedHeadSHA)
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, primaryPullRequestIndex, "main", fixturePrimaryPRTitle, sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, secondaryPR.Number, "main", fixtureSharedHeadPRTitle, sharedHeadSHA)

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
	ordinaryForm := requireRenderedForm(t, decisionsPage, `<form method="post" action="/decisions"`, "ordinary thaw")
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
	beforeConflictActivity := requireAllActivityPages(t, ctx, browser)
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
	confirmationForm := requireRenderedForm(t, conflictBody, `<form method="post" action="/decisions"`, "shared-head confirmation")
	if !strings.Contains(confirmationForm, `name="confirm_shared_head"`) {
		t.Fatal("409 response rendered the ordinary thaw form instead of the shared-head confirmation form")
	}
	shortSharedHead := sharedHeadSHA[:10]
	for _, want := range []string{
		"These pull requests share one commit SHA",
		"Nothing has been approved yet.",
		"for shared head ",
		">" + shortSharedHead + "</code>",
		"Approve thaw for all 2 PRs",
	} {
		if !strings.Contains(conflictBody, want) {
			t.Fatalf("shared-head confirmation response is missing %q", want)
		}
	}
	primaryRow := requireSharedHeadConfirmationRow(t, conflictBody, primaryPullRequestIndex)
	secondaryRow := requireSharedHeadConfirmationRow(t, conflictBody, secondaryPR.Number)
	for _, want := range []string{fixturePrimaryPRTitle, `>main</code>`, `>` + shortSharedHead + `</code>`, `>your selection</span>`} {
		if !strings.Contains(primaryRow, want) {
			t.Fatalf("selected shared-head confirmation row is missing %q", want)
		}
	}
	for _, want := range []string{fixtureSharedHeadPRTitle, `>main</code>`, `>` + shortSharedHead + `</code>`} {
		if !strings.Contains(secondaryRow, want) {
			t.Fatalf("second shared-head confirmation row is missing %q", want)
		}
	}
	if strings.Contains(secondaryRow, "your selection") || fixturePrimaryPRTitle == fixtureSharedHeadPRTitle {
		t.Fatal("shared-head confirmation did not preserve one selected PR and two distinct titles")
	}

	confirmationFieldNames := []string{
		"csrf_token",
		"state",
		"repo",
		"page",
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
	if strings.Contains(conflictBody, `>`+affectedFingerprint+`<`) || strings.Contains(conflictBody, affectedFingerprint+`</`) {
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
	beforeConfirmationActivity := requireAllActivityPages(t, ctx, browser)
	beforeConfirmationSyncs := countOpenPullRequestSyncEvents(beforeConfirmationActivity)
	beforeConfirmationSharedThaws := countSharedHeadThawEvents(beforeConfirmationActivity)
	latestBeforeConfirmation := beforeConfirmation.freezeStatuses[len(beforeConfirmation.freezeStatuses)-1]

	confirmedResponse, err := browser.postFormNoRedirect(ctx, "/decisions", confirmationValues)
	if err != nil {
		t.Fatalf("submit explicit shared-head confirmation: %v", err)
	}
	if confirmedResponse.statusCode != http.StatusSeeOther || confirmedResponse.location != "/decisions?notice=thaw-approved-shared" {
		t.Fatalf("explicit shared-head confirmation returned HTTP %d with Location %q, want 303 to /decisions?notice=thaw-approved-shared", confirmedResponse.statusCode, confirmedResponse.location)
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
		`>#` + strconv.Itoa(primaryPullRequestIndex) + `</code>`,
		fixtureOwner + `/` + fixtureRepository,
		`>main</code>`,
		`title="` + sharedHeadSHA + `"`,
		explicitThaw,
		`>Eligible</span>`,
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
			`PR #` + strconv.Itoa(primaryPullRequestIndex) + ` · main`,
			`title="` + sharedHeadSHA + `"`,
			`>` + requiredContext + `</code>`,
			explicitThaw,
		} {
			if !strings.Contains(row, want) {
				t.Fatalf("latest shared-head publication %s is missing %q", label, want)
			}
		}
	}
	for _, want := range []string{`>success</span>`, `>forgejo_status</code>`} {
		if !strings.Contains(intentRow, want) {
			t.Fatalf("latest shared-head publication intent is missing %q", want)
		}
	}
	for _, want := range []string{`>posted</span>`, `>success · forgejo_status</code>`} {
		if !strings.Contains(attemptRow, want) {
			t.Fatalf("latest shared-head publication attempt is missing %q", want)
		}
	}

	sharedThawRow := requireLatestActivityRow(t, activityAfterConfirmation, "Shared-head thaw")
	for _, want := range []string{
		`>E2E Admin</td>`,
		`>` + fixtureOwner + `/` + fixtureRepository + ` → shared head ` + sharedHeadSHA[:12] + `</td>`,
		`>Approved</span>`,
		`New exceptions: #` + strconv.Itoa(primaryPullRequestIndex) + `, #` + strconv.Itoa(secondaryPR.Number) + `; already covered: none. Confirmation reason: ` + thawReason + `.`,
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
	requireOpenForgejoPullRequest(t, ctx, forgejo, primaryPullRequestIndex, "main", fixturePrimaryPRTitle, sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, secondaryPR.Number, "main", fixtureSharedHeadPRTitle, sharedHeadSHA)
	return secondaryPR
}

func proveScheduledFreezeLifecycle(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, primaryPullRequestIndex int, sharedHeadPR pullRequest, historicalThawedHeadSHA, sharedHeadSHA string) scheduledFreezeLifecycleFixture {
	t.Helper()
	const (
		noFreezeReason        = "No active freeze applies to this PR"
		frozenReason          = "Branch is frozen; merge is blocked by Thawguard"
		explicitThaw          = "PR is explicitly thawed during an active freeze"
		scheduleAReason       = "Fictional scheduled release freeze"
		scheduleAEditedReason = "Fictional edited scheduled release freeze"
		scheduleBReason       = "Fictional cancelled scheduled release freeze"
	)
	historicalThawedHeadSHA = strings.ToLower(strings.TrimSpace(historicalThawedHeadSHA))
	sharedHeadSHA = strings.ToLower(strings.TrimSpace(sharedHeadSHA))
	if len(historicalThawedHeadSHA) < 12 || len(sharedHeadSHA) < 12 || historicalThawedHeadSHA == sharedHeadSHA {
		t.Fatalf("scheduled lifecycle requires distinct historical and shared full SHAs: historical=%q shared=%q", historicalThawedHeadSHA, sharedHeadSHA)
	}

	freezesBefore := requirePage(t, ctx, browser, "/freezes")
	mainFreezeBefore, _ := requireActiveFreezeEvidenceForBranch(t, freezesBefore, "main")
	mainSharedStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, sharedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(mainSharedStatuses) == 0 {
		t.Fatal("shared main head has no status history before the scheduled lifecycle")
	}
	mainSharedStatuses = slices.Clone(mainSharedStatuses)
	mainLatest := mainSharedStatuses[len(mainSharedStatuses)-1]
	if mainLatest.Context != requiredContext || mainLatest.Status != "success" || mainLatest.Description != explicitThaw {
		t.Fatalf("unexpected shared-main status before scheduled lifecycle: %+v", mainLatest)
	}
	historicalStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, historicalThawedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if len(historicalStatuses) == 0 {
		t.Fatal("historical thawed head has no retained status before scheduled lifecycle")
	}
	historicalStatuses = slices.Clone(historicalStatuses)
	historicalDecisionRow := requireDecisionResultRowForHead(t, requirePage(t, ctx, browser, "/decisions"), historicalThawedHeadSHA)
	historicalThawRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Single-PR thaw")
	requireOpenForgejoPullRequest(t, ctx, forgejo, primaryPullRequestIndex, "main", fixturePrimaryPRTitle, sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, sharedHeadPR.Number, "main", fixtureSharedHeadPRTitle, sharedHeadSHA)
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "scheduled lifecycle baseline")

	releaseBaseSHA := createForgejoBranch(t, ctx, forgejo, fixtureScheduledBranch, fixtureReleaseBranch)
	releaseHeadSHA := createScheduledTransitionCommit(t, ctx, forgejo, releaseBaseSHA)
	if releaseHeadSHA == releaseBaseSHA || releaseHeadSHA == sharedHeadSHA {
		t.Fatalf("scheduled release head must differ from release base and shared main head: release=%q shared=%q scheduled=%q", releaseBaseSHA, sharedHeadSHA, releaseHeadSHA)
	}
	requireForgejoBranchProtection(t, ctx, forgejo, fixtureReleaseBranch)

	beforeOpened := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
	if len(beforeOpened.freezeStatuses) != 0 {
		t.Fatalf("new scheduled release head has %d pre-PR %s statuses, want none", len(beforeOpened.freezeStatuses), requiredContext)
	}
	releasePR := createForgejoPullRequest(t, ctx, forgejo, fixtureScheduledBranch, fixtureReleaseBranch, fixtureScheduledPRTitle)
	if releasePR.Head.SHA != releaseHeadSHA {
		t.Fatalf("scheduled release PR head %q does not equal contents-API commit %q", releasePR.Head.SHA, releaseHeadSHA)
	}
	if releasePR.Number == primaryPullRequestIndex || releasePR.Number == sharedHeadPR.Number {
		t.Fatalf("scheduled release PR reused an existing main PR number: release=%d main=%d shared=%d", releasePR.Number, primaryPullRequestIndex, sharedHeadPR.Number)
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, releasePR.Number, fixtureReleaseBranch, fixtureScheduledPRTitle, releaseHeadSHA)
	waitForOneNewProcessedPullRequestDelivery(t, ctx, browser, repositoryID, beforeOpened.webhookRows, "opened")

	var afterOpened webhookSideEffectEvidence
	waitFor(t, 30*time.Second, "scheduled release PR opened side effects and status ID advancement", func() (bool, error) {
		afterOpened = collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
		if afterOpened.webhookRows > beforeOpened.webhookRows+1 ||
			afterOpened.statusResults > beforeOpened.statusResults+1 ||
			afterOpened.publicationIntents > beforeOpened.publicationIntents+1 ||
			afterOpened.publicationAttempts > beforeOpened.publicationAttempts+1 ||
			afterOpened.activityEvents > beforeOpened.activityEvents ||
			len(afterOpened.freezeStatuses) > 1 {
			t.Fatal("scheduled release PR opened webhook exceeded its expected side-effect deltas")
		}
		return afterOpened.webhookRows == beforeOpened.webhookRows+1 &&
			afterOpened.statusResults == beforeOpened.statusResults+1 &&
			afterOpened.publicationIntents == beforeOpened.publicationIntents+1 &&
			afterOpened.publicationAttempts == beforeOpened.publicationAttempts+1 &&
			afterOpened.activityEvents == beforeOpened.activityEvents &&
			len(afterOpened.freezeStatuses) == 1 &&
			afterOpened.freezeStatuses[0].ID > 0, nil
	})
	openedStatus := afterOpened.freezeStatuses[0]
	if openedStatus.Context != requiredContext || openedStatus.Status != "success" || openedStatus.Description != noFreezeReason {
		t.Fatalf("unexpected scheduled release opened status: %+v", openedStatus)
	}
	waitForLatestPostedPublicationAttempt(t, ctx, browser, releaseHeadSHA, "success", noFreezeReason)
	openedDecisionRow := requireLatestDecisionResultRow(t, requirePage(t, ctx, browser, "/decisions"))
	for _, want := range []string{
		`>#` + strconv.Itoa(releasePR.Number) + `</code>`,
		fixtureOwner + `/` + fixtureRepository,
		`>` + fixtureReleaseBranch + `</code>`,
		`title="` + releaseHeadSHA + `"`,
		`>Eligible</span>`,
		noFreezeReason,
	} {
		if !strings.Contains(openedDecisionRow, want) {
			t.Fatalf("scheduled release opened status result is missing %q", want)
		}
	}
	openedPublications := requirePage(t, ctx, browser, "/publications")
	openedIntentRow := requireLatestPublicationIntentRow(t, openedPublications)
	openedAttemptRow := requireLatestPublicationAttemptRow(t, openedPublications)
	for label, row := range map[string]string{"intent": openedIntentRow, "attempt": openedAttemptRow} {
		for _, want := range []string{
			fixtureOwner + `/` + fixtureRepository,
			`PR #` + strconv.Itoa(releasePR.Number) + ` · ` + fixtureReleaseBranch,
			`title="` + releaseHeadSHA + `"`,
			`>` + requiredContext + `</code>`,
			noFreezeReason,
		} {
			if !strings.Contains(row, want) {
				t.Fatalf("scheduled release opened publication %s is missing %q", label, want)
			}
		}
	}
	for _, want := range []string{`>success</span>`, `>forgejo_status</code>`} {
		if !strings.Contains(openedIntentRow, want) {
			t.Fatalf("scheduled release opened publication intent is missing %q", want)
		}
	}
	for _, want := range []string{`>posted</span>`, `>success · forgejo_status</code>`} {
		if !strings.Contains(openedAttemptRow, want) {
			t.Fatalf("scheduled release opened publication attempt is missing %q", want)
		}
	}
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "release PR opening")

	initialScheduleTime := time.Now().UTC().Truncate(time.Second)
	scheduleAStartsAt := initialScheduleTime.Add(10 * time.Minute)
	scheduleAPlannedEndsAt := initialScheduleTime.Add(20 * time.Minute)
	beforeScheduleA := afterOpened
	requireRawScheduledFreezeMutation(t, ctx, browser, "/scheduled-freezes", url.Values{
		"repository_id":           {strconv.FormatInt(repositoryID, 10)},
		"branch":                  {fixtureReleaseBranch},
		"reason":                  {scheduleAReason},
		"starts_at":               {scheduleAStartsAt.Format(time.RFC3339)},
		"planned_ends_at":         {scheduleAPlannedEndsAt.Format(time.RFC3339)},
		"timezone_offset_minutes": {"0"},
	}, "create Schedule A")
	schedulesPage := requirePage(t, ctx, browser, "/scheduled-freezes")
	scheduleA := requireScheduledFreezeRow(t, schedulesPage, 0, scheduleAReason)
	if scheduleA.id <= 0 || scheduleA.branch != fixtureReleaseBranch || scheduleA.status != "Upcoming" || scheduleA.startsAt != scheduleTime(scheduleAStartsAt) || scheduleA.plannedEndsAt != scheduleTime(scheduleAPlannedEndsAt) || scheduleA.endedAt != "—" {
		t.Fatalf("Schedule A has unexpected initial rendered evidence: %+v", scheduleA)
	}
	requirePendingScheduleActions(t, schedulesPage, scheduleA, scheduleAStartsAt, scheduleAPlannedEndsAt)
	scheduleACreatedRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Freeze schedule")
	requireScheduleActivityEvidence(t, scheduleACreatedRow, "Freeze schedule", "Scheduled", scheduleAReason)
	for _, want := range []string{"Starts " + scheduleTime(scheduleAStartsAt), "planned unfreeze " + scheduleTime(scheduleAPlannedEndsAt)} {
		if !strings.Contains(scheduleACreatedRow, want) {
			t.Fatalf("Schedule A creation activity is missing %q", want)
		}
	}
	afterScheduleA := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
	requireScheduleOnlyActivityDelta(t, beforeScheduleA, afterScheduleA, 1, "Schedule A creation")
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "Schedule A creation")

	scheduleBStartsAt := initialScheduleTime.Add(15 * time.Minute)
	scheduleBPlannedEndsAt := initialScheduleTime.Add(25 * time.Minute)
	beforeScheduleB := afterScheduleA
	requireRawScheduledFreezeMutation(t, ctx, browser, "/scheduled-freezes", url.Values{
		"repository_id":           {strconv.FormatInt(repositoryID, 10)},
		"branch":                  {fixtureReleaseBranch},
		"reason":                  {scheduleBReason},
		"starts_at":               {scheduleBStartsAt.Format(time.RFC3339)},
		"planned_ends_at":         {scheduleBPlannedEndsAt.Format(time.RFC3339)},
		"timezone_offset_minutes": {"0"},
	}, "create Schedule B")
	schedulesPage = requirePage(t, ctx, browser, "/scheduled-freezes")
	scheduleB := requireScheduledFreezeRow(t, schedulesPage, 0, scheduleBReason)
	if scheduleB.id <= 0 || scheduleB.id == scheduleA.id || scheduleB.branch != fixtureReleaseBranch || scheduleB.status != "Upcoming" || scheduleB.startsAt != scheduleTime(scheduleBStartsAt) || scheduleB.plannedEndsAt != scheduleTime(scheduleBPlannedEndsAt) || scheduleB.endedAt != "—" {
		t.Fatalf("Schedule B has unexpected initial rendered evidence: %+v", scheduleB)
	}
	requirePendingScheduleActions(t, schedulesPage, scheduleB, scheduleBStartsAt, scheduleBPlannedEndsAt)
	scheduleAAfterBCreate := requireScheduledFreezeRow(t, schedulesPage, scheduleA.id, scheduleAReason)
	requireUnchangedPendingSchedule(t, scheduleA, scheduleAAfterBCreate, "Schedule B creation")
	scheduleBCreatedRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Freeze schedule")
	requireScheduleActivityEvidence(t, scheduleBCreatedRow, "Freeze schedule", "Scheduled", scheduleBReason)
	afterScheduleB := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
	requireScheduleOnlyActivityDelta(t, beforeScheduleB, afterScheduleB, 1, "Schedule B creation")
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "Schedule B creation")

	beforeScheduleBCancel := afterScheduleB
	if !strings.Contains(scheduleB.row, `aria-controls="cancel-scheduled-`+strconv.FormatInt(scheduleB.id, 10)+`"`) || strings.Contains(scheduleB.row, `action="/freezes/end"`) {
		t.Fatal("Schedule B pending row confused scheduled cancellation with active-freeze cancellation")
	}
	requireRawScheduledFreezeMutation(t, ctx, browser, "/scheduled-freezes/cancel", url.Values{
		"freeze_id": {strconv.FormatInt(scheduleB.id, 10)},
	}, "cancel pending Schedule B")
	schedulesPage = requirePage(t, ctx, browser, "/scheduled-freezes")
	cancelledScheduleB := requireScheduledFreezeRow(t, schedulesPage, 0, scheduleBReason)
	if cancelledScheduleB.branch != fixtureReleaseBranch || cancelledScheduleB.status != "Cancelled" || cancelledScheduleB.endedAt == "—" || cancelledScheduleB.endedAt == "" {
		t.Fatalf("Schedule B has unexpected cancelled evidence: %+v", cancelledScheduleB)
	}
	requireNoPendingScheduleActions(t, cancelledScheduleB)
	scheduleAAfterBCancel := requireScheduledFreezeRow(t, schedulesPage, scheduleA.id, scheduleAReason)
	requireUnchangedPendingSchedule(t, scheduleAAfterBCreate, scheduleAAfterBCancel, "Schedule B cancellation")
	scheduleBCancelledRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Freeze schedule")
	requireScheduleActivityEvidence(t, scheduleBCancelledRow, "Freeze schedule", "Cancelled", scheduleBReason)
	if strings.Contains(scheduleBCancelledRow, `>Branch freeze</span>`) {
		t.Fatal("pending Schedule B cancellation was rendered as an active branch-freeze cancellation")
	}
	afterScheduleBCancel := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
	requireScheduleOnlyActivityDelta(t, beforeScheduleBCancel, afterScheduleBCancel, 1, "Schedule B cancellation")
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "Schedule B cancellation")

	editedAt := time.Now().UTC().Truncate(time.Second)
	editedStartsAt := editedAt.Add(60 * time.Second)
	editedPlannedEndsAt := editedAt.Add(90 * time.Second)
	beforeScheduleAEdit := afterScheduleBCancel
	requireRawScheduledFreezeMutation(t, ctx, browser, "/scheduled-freezes/edit", url.Values{
		"freeze_id":               {strconv.FormatInt(scheduleA.id, 10)},
		"reason":                  {scheduleAEditedReason},
		"starts_at":               {editedStartsAt.Format(time.RFC3339)},
		"planned_ends_at":         {editedPlannedEndsAt.Format(time.RFC3339)},
		"timezone_offset_minutes": {"0"},
	}, "edit Schedule A")
	schedulesPage = requirePage(t, ctx, browser, "/scheduled-freezes")
	editedScheduleA := requireScheduledFreezeRow(t, schedulesPage, scheduleA.id, scheduleAEditedReason)
	if editedScheduleA.id != scheduleA.id || editedScheduleA.branch != fixtureReleaseBranch || editedScheduleA.status != "Upcoming" || editedScheduleA.startsAt != scheduleTime(editedStartsAt) || editedScheduleA.plannedEndsAt != scheduleTime(editedPlannedEndsAt) || editedScheduleA.endedAt != "—" {
		t.Fatalf("Schedule A has unexpected edited evidence: before=%+v after=%+v", scheduleA, editedScheduleA)
	}
	requirePendingScheduleActions(t, schedulesPage, editedScheduleA, editedStartsAt, editedPlannedEndsAt)
	scheduleAUpdatedRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Freeze schedule")
	requireScheduleActivityEvidence(t, scheduleAUpdatedRow, "Freeze schedule", "Changed", scheduleAEditedReason)
	wantUpdateDetail := "Reason " + scheduleAReason + " → " + scheduleAEditedReason + "; starts " + scheduleTime(scheduleAStartsAt) + " → " + scheduleTime(editedStartsAt) + "; planned unfreeze " + scheduleTime(scheduleAPlannedEndsAt) + " → " + scheduleTime(editedPlannedEndsAt) + "."
	if !strings.Contains(scheduleAUpdatedRow, wantUpdateDetail) {
		t.Fatalf("Schedule A update activity is missing truthful before/after detail %q", wantUpdateDetail)
	}
	afterScheduleAEdit := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
	requireScheduleOnlyActivityDelta(t, beforeScheduleAEdit, afterScheduleAEdit, 1, "Schedule A edit")
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "Schedule A edit")

	if !time.Now().UTC().Before(editedStartsAt) {
		t.Fatalf("Schedule A edited start %s arrived before Start Now submission", editedStartsAt.Format(time.RFC3339))
	}
	beforeStartNow := afterScheduleAEdit
	beforeStartActivityPage := requireAllActivityPages(t, ctx, browser)
	beforeStartNowEvents := countActivityEvents(beforeStartActivityPage, "Scheduled freeze Start Now")
	beforeStartSyncs := countOpenPullRequestSyncEvents(beforeStartActivityPage)
	beforeStartStatus := beforeStartNow.freezeStatuses[len(beforeStartNow.freezeStatuses)-1]
	requireRawScheduledFreezeMutation(t, ctx, browser, "/scheduled-freezes/start-now", url.Values{
		"freeze_id": {strconv.FormatInt(scheduleA.id, 10)},
	}, "Start Now Schedule A")

	var afterStartNow webhookSideEffectEvidence
	waitFor(t, 30*time.Second, "Schedule A Start Now convergence", func() (bool, error) {
		afterStartNow = collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, releaseHeadSHA)
		if afterStartNow.webhookRows > beforeStartNow.webhookRows ||
			afterStartNow.statusResults > beforeStartNow.statusResults+1 ||
			afterStartNow.publicationIntents > beforeStartNow.publicationIntents ||
			afterStartNow.publicationAttempts > beforeStartNow.publicationAttempts+1 ||
			afterStartNow.activityEvents > beforeStartNow.activityEvents+2 ||
			len(afterStartNow.freezeStatuses) > len(beforeStartNow.freezeStatuses)+1 {
			t.Fatal("Schedule A Start Now exceeded its expected side-effect deltas")
		}
		return afterStartNow.webhookRows == beforeStartNow.webhookRows &&
			afterStartNow.statusResults == beforeStartNow.statusResults+1 &&
			afterStartNow.publicationIntents == beforeStartNow.publicationIntents &&
			afterStartNow.publicationAttempts == beforeStartNow.publicationAttempts+1 &&
			afterStartNow.activityEvents == beforeStartNow.activityEvents+2 &&
			len(afterStartNow.freezeStatuses) == len(beforeStartNow.freezeStatuses)+1, nil
	})
	waitForLatestPostedPublicationAttempt(t, ctx, browser, releaseHeadSHA, "failure", frozenReason)
	latestReleaseStatus := afterStartNow.freezeStatuses[len(afterStartNow.freezeStatuses)-1]
	if latestReleaseStatus.ID <= beforeStartStatus.ID || latestReleaseStatus.Context != requiredContext || latestReleaseStatus.Status != "failure" || latestReleaseStatus.Description != frozenReason {
		t.Fatalf("unexpected Schedule A Start Now required status: before=%+v after=%+v", beforeStartStatus, latestReleaseStatus)
	}

	activityAfterStart := requireAllActivityPages(t, ctx, browser)
	if countActivityEvents(activityAfterStart, "Scheduled freeze Start Now") != beforeStartNowEvents+1 || countOpenPullRequestSyncEvents(activityAfterStart) != beforeStartSyncs+1 {
		t.Fatal("Schedule A Start Now did not add exactly one Start Now event and one open-PR sync event")
	}
	startNowRow := requireLatestActivityRow(t, activityAfterStart, "Scheduled freeze Start Now")
	requireScheduleActivityEvidence(t, startNowRow, "Scheduled freeze Start Now", "Started", scheduleAEditedReason)
	if !strings.Contains(startNowRow, "planned unfreeze "+scheduleTime(editedPlannedEndsAt)) {
		t.Fatalf("Schedule A Start Now activity is missing retained planned unfreeze %q", scheduleTime(editedPlannedEndsAt))
	}
	requireLatestOpenPullRequestSync(t, activityAfterStart, 3)

	startPublications := requirePage(t, ctx, browser, "/publications")
	startIntentRow := requireLatestPublicationIntentRow(t, startPublications)
	startAttemptRow := requireLatestPublicationAttemptRow(t, startPublications)
	for label, row := range map[string]string{"intent": startIntentRow, "attempt": startAttemptRow} {
		for _, want := range []string{
			fixtureOwner + `/` + fixtureRepository,
			`PR #` + strconv.Itoa(releasePR.Number) + ` · ` + fixtureReleaseBranch,
			`title="` + releaseHeadSHA + `"`,
			`>` + requiredContext + `</code>`,
			frozenReason,
		} {
			if !strings.Contains(row, want) {
				t.Fatalf("Schedule A Start Now publication %s is missing %q", label, want)
			}
		}
	}
	for _, want := range []string{`>failure</span>`, `>forgejo_status</code>`} {
		if !strings.Contains(startIntentRow, want) {
			t.Fatalf("Schedule A reused publication intent is missing %q", want)
		}
	}
	for _, want := range []string{`>posted</span>`, `>failure · forgejo_status</code>`} {
		if !strings.Contains(startAttemptRow, want) {
			t.Fatalf("Schedule A newest publication attempt is missing %q", want)
		}
	}
	decisionsAfterStart := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsAfterStart, `>`+requiredContext+`</code>`) {
		t.Fatalf("decisions page no longer displays the required context %q", requiredContext)
	}
	startDecisionRow := requireLatestDecisionResultRow(t, decisionsAfterStart)
	for _, want := range []string{
		`>#` + strconv.Itoa(releasePR.Number) + `</code>`,
		`>` + fixtureReleaseBranch + `</code>`,
		`title="` + releaseHeadSHA + `"`,
		`>Blocked</span>`,
		frozenReason,
	} {
		if !strings.Contains(startDecisionRow, want) {
			t.Fatalf("Schedule A Start Now status result is missing %q", want)
		}
	}

	schedulesPage = requirePage(t, ctx, browser, "/scheduled-freezes")
	activeScheduleA := requireScheduledFreezeRow(t, schedulesPage, 0, scheduleAEditedReason)
	if activeScheduleA.branch != fixtureReleaseBranch || activeScheduleA.status != "Active" || activeScheduleA.plannedEndsAt != scheduleTime(editedPlannedEndsAt) || activeScheduleA.endedAt != "—" {
		t.Fatalf("Schedule A has unexpected active rendered evidence: %+v", activeScheduleA)
	}
	requireNoPendingScheduleActions(t, activeScheduleA)
	cancelledScheduleBAfterStart := requireScheduledFreezeRow(t, schedulesPage, 0, scheduleBReason)
	if cancelledScheduleBAfterStart.status != "Cancelled" || cancelledScheduleBAfterStart.endedAt == "—" {
		t.Fatalf("Schedule B cancelled history changed after Schedule A Start Now: %+v", cancelledScheduleBAfterStart)
	}
	requireNoPendingScheduleActions(t, cancelledScheduleBAfterStart)
	if strings.Contains(schedulesPage, `>Upcoming</span>`) || strings.Contains(schedulesPage, `action="/scheduled-freezes/edit"`) || strings.Contains(schedulesPage, `action="/scheduled-freezes/start-now"`) || strings.Contains(schedulesPage, `action="/scheduled-freezes/cancel"`) {
		t.Fatal("scheduled lifecycle left a pending schedule or pending-only action")
	}

	freezesAfter := requirePage(t, ctx, browser, "/freezes")
	if !strings.Contains(freezesAfter, `>2 active</span>`) {
		t.Fatal("freezes page does not show both active main and scheduled release freezes")
	}
	mainFreezeAfter, _ := requireActiveFreezeEvidenceForBranch(t, freezesAfter, "main")
	if mainFreezeAfter != mainFreezeBefore {
		t.Fatalf("original main freeze changed during scheduled lifecycle: before=%+v after=%+v", mainFreezeBefore, mainFreezeAfter)
	}
	activeReleaseFreeze, activeReleaseRow := requireActiveFreezeEvidenceForBranch(t, freezesAfter, fixtureReleaseBranch)
	if activeReleaseFreeze.id != scheduleA.id || activeReleaseFreeze.branch != fixtureReleaseBranch || activeReleaseFreeze.reason != scheduleAEditedReason || activeReleaseFreeze.status != "Frozen" || activeReleaseFreeze.id == mainFreezeAfter.id {
		t.Fatalf("active scheduled release freeze has unexpected evidence: schedule=%+v active=%+v", activeScheduleA, activeReleaseFreeze)
	}
	if !strings.Contains(activeReleaseRow, scheduleTime(editedPlannedEndsAt)) {
		t.Fatalf("active release freeze is missing planned unfreeze %q", scheduleTime(editedPlannedEndsAt))
	}

	repositoriesPage := requirePage(t, ctx, browser, "/repositories")
	if !strings.Contains(repositoriesPage, `>enforcement active</span>`) || strings.Contains(repositoriesPage, "Enforcement is unhealthy") || strings.Contains(repositoriesPage, "Automatic recovery is pending") || strings.Contains(repositoriesPage, "Recovery in progress") || strings.Contains(repositoriesPage, `action="/repositories/recover"`) {
		t.Fatal("repository did not remain enforcement-active and healthy after Schedule A Start Now convergence")
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, releasePR.Number, fixtureReleaseBranch, fixtureScheduledPRTitle, releaseHeadSHA)
	assertMergeBlockedByRequiredStatus(t, ctx, forgejo, releasePR.Number)
	requireOpenForgejoPullRequest(t, ctx, forgejo, primaryPullRequestIndex, "main", fixturePrimaryPRTitle, sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, sharedHeadPR.Number, "main", fixtureSharedHeadPRTitle, sharedHeadSHA)
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, mainFreezeBefore, sharedHeadSHA, mainSharedStatuses, "Schedule A Start Now")

	historicalStatusesAfter, err := listForgejoFreezeStatuses(ctx, forgejo, historicalThawedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(historicalStatusesAfter, historicalStatuses) {
		t.Fatalf("historical thawed-head status evidence changed during scheduled lifecycle: before=%+v after=%+v", historicalStatuses, historicalStatusesAfter)
	}
	decisionsAfter := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsAfter, historicalDecisionRow) || requireDecisionResultRowForHead(t, decisionsAfter, historicalThawedHeadSHA) != historicalDecisionRow {
		t.Fatal("historical thawed-head Eligible decision evidence changed during scheduled lifecycle")
	}
	activityAfter := requireAllActivityPages(t, ctx, browser)
	if !strings.Contains(activityAfter, historicalThawRow) || requireLatestActivityRow(t, activityAfter, "Single-PR thaw") != historicalThawRow {
		t.Fatal("historical Single-PR thaw activity changed during scheduled lifecycle")
	}
	if !editedPlannedEndsAt.After(time.Now().UTC()) {
		t.Fatalf("Schedule A planned unfreeze %s did not remain pending for the retained fixture", editedPlannedEndsAt.Format(time.RFC3339))
	}

	return scheduledFreezeLifecycleFixture{
		freezeID:                       scheduleA.id,
		releasePullRequestIndex:        releasePR.Number,
		releaseHeadSHA:                 releaseHeadSHA,
		plannedEndsAt:                  editedPlannedEndsAt,
		activeScheduleA:                activeScheduleA,
		cancelledScheduleB:             cancelledScheduleBAfterStart,
		activeReleaseFreeze:            activeReleaseFreeze,
		activeMainFreeze:               mainFreezeBefore,
		primaryPullRequestIndex:        primaryPullRequestIndex,
		sharedHeadPullRequestIndex:     sharedHeadPR.Number,
		sharedHeadSHA:                  sharedHeadSHA,
		mainSharedHeadStatuses:         slices.Clone(mainSharedStatuses),
		historicalThawedHeadSHA:        historicalThawedHeadSHA,
		historicalThawedHeadStatuses:   slices.Clone(historicalStatuses),
		historicalEligibleDecisionRow:  historicalDecisionRow,
		historicalSinglePRThawActivity: historicalThawRow,
	}
}

func provePlannedUnfreezeAcrossRestart(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, cfg e2eConfig, repositoryID int64, fixture scheduledFreezeLifecycleFixture) {
	t.Helper()
	const (
		frozenDescription = "Branch is frozen; merge is blocked by Thawguard"
		thawedDescription = "No active freeze applies to this PR"
	)
	sliceStartedAt := time.Now().UTC()
	plannedEndsAt := fixture.plannedEndsAt.UTC()
	contextDeadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		t.Fatal("planned-unfreeze restart proof requires a bounded test context")
	}
	remainingBeforeStop := plannedEndsAt.Sub(sliceStartedAt)
	contextAfterPlannedEnd := contextDeadline.Sub(plannedEndsAt)
	if remainingBeforeStop < 50*time.Second {
		t.Fatalf("planned-unfreeze restart proof has only %s before the retained due time, want at least 50s", remainingBeforeStop.Round(time.Millisecond))
	}
	if contextAfterPlannedEnd < 120*time.Second {
		t.Fatalf("planned-unfreeze restart proof has only %s of test context after the retained due time, want at least 120s", contextAfterPlannedEnd.Round(time.Millisecond))
	}
	if fixture.freezeID <= 0 || fixture.releasePullRequestIndex <= 0 || len(fixture.releaseHeadSHA) < 12 || fixture.activeReleaseFreeze.id != fixture.freezeID || fixture.activeMainFreeze.id <= 0 || fixture.activeMainFreeze.id == fixture.freezeID || fixture.primaryPullRequestIndex <= 0 || fixture.sharedHeadPullRequestIndex <= 0 || fixture.primaryPullRequestIndex == fixture.sharedHeadPullRequestIndex || len(fixture.sharedHeadSHA) < 12 || len(fixture.mainSharedHeadStatuses) == 0 || len(fixture.historicalThawedHeadSHA) < 12 || len(fixture.historicalThawedHeadStatuses) == 0 || fixture.historicalEligibleDecisionRow == "" || fixture.historicalSinglePRThawActivity == "" {
		t.Fatalf("planned-unfreeze restart proof received an incomplete retained fixture: %+v", fixture)
	}
	t.Logf("planned-unfreeze pre-stop timing: due in %s; test context extends %s beyond due", remainingBeforeStop.Round(time.Millisecond), contextAfterPlannedEnd.Round(time.Millisecond))

	releasePR := requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	if releasePR.Merged {
		t.Fatalf("release PR #%d is already merged before the planned-unfreeze restart proof", fixture.releasePullRequestIndex)
	}
	repositoriesBefore := requirePage(t, ctx, browser, "/repositories")
	requireHealthyActiveRepository(t, repositoriesBefore)
	csrfBefore := requireHiddenInput(t, repositoriesBefore, "csrf_token")
	if csrfBefore == "" {
		t.Fatal("authenticated session has an empty CSRF token before planned-unfreeze downtime")
	}

	baseline := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, fixture.releaseHeadSHA)
	if len(baseline.freezeStatuses) < 2 {
		t.Fatalf("release head has only %d required-context statuses before planned-unfreeze downtime, want complete success/failure history", len(baseline.freezeStatuses))
	}
	scheduleAFailure := baseline.freezeStatuses[len(baseline.freezeStatuses)-1]
	if scheduleAFailure.Context != requiredContext || scheduleAFailure.Status != "failure" || scheduleAFailure.Description != frozenDescription {
		t.Fatalf("unexpected newest release status before planned-unfreeze downtime: %+v", scheduleAFailure)
	}

	schedulesBefore := requirePage(t, ctx, browser, "/scheduled-freezes")
	scheduleABefore := requireScheduledFreezeRow(t, schedulesBefore, 0, fixture.activeScheduleA.reason)
	if scheduleABefore != fixture.activeScheduleA || scheduleABefore.id != 0 || scheduleABefore.branch != fixtureReleaseBranch || scheduleABefore.status != "Active" || scheduleABefore.plannedEndsAt != scheduleTime(plannedEndsAt) || scheduleABefore.endedAt != "—" {
		t.Fatalf("Schedule A changed before planned-unfreeze downtime: retained=%+v rendered=%+v", fixture.activeScheduleA, scheduleABefore)
	}
	requireNoPendingScheduleActions(t, scheduleABefore)
	scheduleBBefore := requireScheduledFreezeRow(t, schedulesBefore, 0, fixture.cancelledScheduleB.reason)
	if scheduleBBefore != fixture.cancelledScheduleB || scheduleBBefore.status != "Cancelled" || scheduleBBefore.endedAt == "" || scheduleBBefore.endedAt == "—" {
		t.Fatalf("cancelled Schedule B changed before planned-unfreeze downtime: retained=%+v rendered=%+v", fixture.cancelledScheduleB, scheduleBBefore)
	}
	requireNoPendingScheduleActions(t, scheduleBBefore)

	freezesBefore := requirePage(t, ctx, browser, "/freezes")
	requireActiveFreezeCount(t, freezesBefore, 2)
	mainFreezeBefore, _ := requireActiveFreezeEvidenceForBranch(t, freezesBefore, "main")
	if mainFreezeBefore != fixture.activeMainFreeze {
		t.Fatalf("active main freeze changed before planned-unfreeze downtime: retained=%+v rendered=%+v", fixture.activeMainFreeze, mainFreezeBefore)
	}
	releaseFreezeBefore, _ := requireActiveFreezeEvidenceForBranch(t, freezesBefore, fixtureReleaseBranch)
	if releaseFreezeBefore != fixture.activeReleaseFreeze || releaseFreezeBefore.id != fixture.freezeID {
		t.Fatalf("active release freeze changed before planned-unfreeze downtime: retained=%+v rendered=%+v", fixture.activeReleaseFreeze, releaseFreezeBefore)
	}
	requireRetainedPlannedUnfreezeFixtureState(t, ctx, forgejo, browser, fixture, "planned-unfreeze pre-stop baseline")

	decisionsBefore := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsBefore, `>`+requiredContext+`</code>`) {
		t.Fatalf("decisions page no longer displays the required context %q", requiredContext)
	}
	failureDecisionRow := requireDecisionResultRowForHead(t, decisionsBefore, fixture.releaseHeadSHA)
	for _, want := range []string{
		`>#` + strconv.Itoa(fixture.releasePullRequestIndex) + `</code>`,
		`>` + fixtureReleaseBranch + `</code>`,
		`title="` + fixture.releaseHeadSHA + `"`,
		`>Blocked</span>`,
		frozenDescription,
	} {
		if !strings.Contains(failureDecisionRow, want) {
			t.Fatalf("pre-stop release failure decision is missing %q", want)
		}
	}
	publicationsBefore := requirePage(t, ctx, browser, "/publications")
	failureIntentRow := requirePublicationIntentRowForHead(t, publicationsBefore, fixture.releaseHeadSHA)
	for _, want := range []string{
		fixtureOwner + `/` + fixtureRepository,
		`PR #` + strconv.Itoa(fixture.releasePullRequestIndex) + ` · ` + fixtureReleaseBranch,
		`title="` + fixture.releaseHeadSHA + `"`,
		`>` + requiredContext + `</code>`,
		`>failure</span>`,
		`>forgejo_status</code>`,
		frozenDescription,
	} {
		if !strings.Contains(failureIntentRow, want) {
			t.Fatalf("pre-stop release desired-status intent is missing %q", want)
		}
	}
	activityBefore := requireAllActivityPages(t, ctx, browser)
	plannedUnfreezesBefore := countActivityEvents(activityBefore, "Scheduled planned unfreeze")
	if plannedUnfreezesBefore != 0 {
		t.Fatalf("planned-unfreeze restart fixture already has %d Scheduled planned unfreeze activities, want none", plannedUnfreezesBefore)
	}
	openPullRequestSyncsBefore := countOpenPullRequestSyncEvents(activityBefore)

	controlThawguardService(t, ctx, cfg, "stop")
	stoppedAt := time.Now().UTC()
	stopCompletionMargin := plannedEndsAt.Sub(stoppedAt)
	if stopCompletionMargin <= 0 {
		t.Fatalf("Thawguard stop completed %s after Schedule A was due", (-stopCompletionMargin).Round(time.Millisecond))
	}
	t.Logf("Thawguard-only stop completed %s before planned unfreeze", stopCompletionMargin.Round(time.Millisecond))

	downtimePR := requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	if downtimePR.Merged {
		t.Fatalf("release PR #%d merged while Thawguard was stopped", fixture.releasePullRequestIndex)
	}
	downtimeStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, fixture.releaseHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(downtimeStatuses, baseline.freezeStatuses) {
		t.Fatalf("release status history changed immediately after Thawguard-only stop: before=%+v after=%+v", baseline.freezeStatuses, downtimeStatuses)
	}

	waitUntilContext(t, ctx, plannedEndsAt.Add(time.Second), "Schedule A planned unfreeze to become overdue while Thawguard is down")
	overduePR := requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	if overduePR.Merged {
		t.Fatalf("release PR #%d merged while the planned unfreeze was overdue and Thawguard was stopped", fixture.releasePullRequestIndex)
	}
	overdueStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, fixture.releaseHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(overdueStatuses, baseline.freezeStatuses) {
		t.Fatalf("release status history changed while planned unfreeze was overdue and Thawguard was stopped: before=%+v after=%+v", baseline.freezeStatuses, overdueStatuses)
	}

	controlThawguardService(t, ctx, cfg, "start")
	restartedAt := time.Now().UTC()
	waitFor(t, 45*time.Second, "restarted Thawguard HTTP health", func() (bool, error) {
		_, err := browser.get(ctx, "/healthz")
		return err == nil, err
	})
	repositoriesAfterStart := requirePage(t, ctx, browser, "/repositories")
	requireHealthyActiveRepository(t, repositoriesAfterStart)
	if csrfAfter := requireHiddenInput(t, repositoriesAfterStart, "csrf_token"); csrfAfter != csrfBefore {
		t.Fatalf("authenticated session CSRF token changed across planned-unfreeze restart")
	}

	var converged webhookSideEffectEvidence
	waitFor(t, 45*time.Second, "startup planned-unfreeze lifecycle convergence", func() (bool, error) {
		current := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, fixture.releaseHeadSHA)
		if current.webhookRows > baseline.webhookRows ||
			current.statusResults > baseline.statusResults+1 ||
			current.publicationIntents > baseline.publicationIntents ||
			current.publicationAttempts > baseline.publicationAttempts+1 ||
			current.activityEvents > baseline.activityEvents+2 ||
			len(current.freezeStatuses) > len(baseline.freezeStatuses)+1 {
			t.Fatalf("startup planned unfreeze overshot its exact deltas: webhooks %d→%d, status results %d→%d, intents %d→%d, attempts %d→%d, activity %d→%d, release statuses %d→%d",
				baseline.webhookRows, current.webhookRows,
				baseline.statusResults, current.statusResults,
				baseline.publicationIntents, current.publicationIntents,
				baseline.publicationAttempts, current.publicationAttempts,
				baseline.activityEvents, current.activityEvents,
				len(baseline.freezeStatuses), len(current.freezeStatuses))
		}
		converged = current
		return current.webhookRows == baseline.webhookRows &&
			current.statusResults == baseline.statusResults+1 &&
			current.publicationIntents == baseline.publicationIntents &&
			current.publicationAttempts == baseline.publicationAttempts+1 &&
			current.activityEvents == baseline.activityEvents+2 &&
			len(current.freezeStatuses) == len(baseline.freezeStatuses)+1, nil
	})

	if !slices.Equal(converged.freezeStatuses[:len(baseline.freezeStatuses)], baseline.freezeStatuses) {
		t.Fatalf("startup planned unfreeze rewrote the existing release status history: before=%+v after=%+v", baseline.freezeStatuses, converged.freezeStatuses)
	}
	startupSuccess := converged.freezeStatuses[len(converged.freezeStatuses)-1]
	if startupSuccess.ID <= scheduleAFailure.ID || startupSuccess.Context != requiredContext || startupSuccess.Status != "success" || startupSuccess.Description != thawedDescription {
		t.Fatalf("unexpected startup planned-unfreeze status for full head %s: failure=%+v success=%+v", fixture.releaseHeadSHA, scheduleAFailure, startupSuccess)
	}

	decisionsAfter := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsAfter, failureDecisionRow) {
		t.Fatal("startup planned unfreeze removed the retained release failure decision history")
	}
	successDecisionRow := requireDecisionResultRowForHead(t, decisionsAfter, fixture.releaseHeadSHA)
	for _, want := range []string{
		`>#` + strconv.Itoa(fixture.releasePullRequestIndex) + `</code>`,
		`>` + fixtureReleaseBranch + `</code>`,
		`title="` + fixture.releaseHeadSHA + `"`,
		`>Eligible</span>`,
		thawedDescription,
	} {
		if !strings.Contains(successDecisionRow, want) {
			t.Fatalf("startup planned-unfreeze success decision is missing %q", want)
		}
	}
	publicationsAfter := requirePage(t, ctx, browser, "/publications")
	successIntentRow := requirePublicationIntentRowForHead(t, publicationsAfter, fixture.releaseHeadSHA)
	for _, want := range []string{
		fixtureOwner + `/` + fixtureRepository,
		`PR #` + strconv.Itoa(fixture.releasePullRequestIndex) + ` · ` + fixtureReleaseBranch,
		`title="` + fixture.releaseHeadSHA + `"`,
		`>` + requiredContext + `</code>`,
		`>success</span>`,
		`>forgejo_status</code>`,
		thawedDescription,
	} {
		if !strings.Contains(successIntentRow, want) {
			t.Fatalf("startup planned-unfreeze reused desired-status intent is missing %q", want)
		}
	}
	if failureIntentRow == successIntentRow {
		t.Fatal("startup planned unfreeze did not update the existing desired-status intent from failure to success")
	}
	startupAttemptRow := requireLatestPublicationAttemptRow(t, publicationsAfter)
	for _, want := range []string{
		fixtureOwner + `/` + fixtureRepository,
		`PR #` + strconv.Itoa(fixture.releasePullRequestIndex) + ` · ` + fixtureReleaseBranch,
		`title="` + fixture.releaseHeadSHA + `"`,
		`>` + requiredContext + `</code>`,
		`>posted</span>`,
		`>success · forgejo_status</code>`,
		thawedDescription,
	} {
		if !strings.Contains(startupAttemptRow, want) {
			t.Fatalf("startup planned-unfreeze publication attempt is missing %q", want)
		}
	}

	activityAfter := requireAllActivityPages(t, ctx, browser)
	if got := countActivityEvents(activityAfter, "Scheduled planned unfreeze"); got != plannedUnfreezesBefore+1 || got != 1 {
		t.Fatalf("startup lifecycle rendered %d Scheduled planned unfreeze activities, want exactly one", got)
	}
	if got := countOpenPullRequestSyncEvents(activityAfter); got != openPullRequestSyncsBefore+1 {
		t.Fatalf("startup lifecycle changed open-PR sync activities from %d to %d, want exactly one new row", openPullRequestSyncsBefore, got)
	}
	plannedUnfreezeRow := requireLatestActivityRow(t, activityAfter, "Scheduled planned unfreeze")
	for _, want := range []string{
		`>Scheduler</td>`,
		`<span class="font-medium text-text">Scheduled planned unfreeze</span>`,
		`>` + fixtureOwner + `/` + fixtureRepository + ` → ` + fixtureReleaseBranch + `</td>`,
		`>Completed</span>`,
		`Planned unfreeze ` + scheduleTime(plannedEndsAt) + `. Reason: ` + html.EscapeString(fixture.activeScheduleA.reason) + `.`,
	} {
		if !strings.Contains(plannedUnfreezeRow, want) {
			t.Fatalf("Scheduled planned unfreeze activity is missing %q", want)
		}
	}
	startupSyncRow := requireLatestActivityRow(t, activityAfter, "Open pull request sync")
	for _, want := range []string{
		`>Unknown system actor</td>`,
		`<span class="font-medium text-text">Open pull request sync</span>`,
		`>` + fixtureOwner + `/` + fixtureRepository + ` → all managed branches</td>`,
		`>Succeeded</span>`,
		`3 open PRs synchronized; 0 cached PRs marked closed.`,
	} {
		if !strings.Contains(startupSyncRow, want) {
			t.Fatalf("startup open-PR sync activity is missing %q", want)
		}
	}

	schedulesAfter := requirePage(t, ctx, browser, "/scheduled-freezes")
	completedScheduleA := requireScheduledFreezeRow(t, schedulesAfter, 0, fixture.activeScheduleA.reason)
	if completedScheduleA.id != 0 || completedScheduleA.branch != fixture.activeScheduleA.branch || completedScheduleA.reason != fixture.activeScheduleA.reason || completedScheduleA.startsAt != fixture.activeScheduleA.startsAt || completedScheduleA.plannedEndsAt != fixture.activeScheduleA.plannedEndsAt || completedScheduleA.status != "Completed" || completedScheduleA.endedAt == "" || completedScheduleA.endedAt == "—" {
		t.Fatalf("Schedule A has unexpected completed evidence after startup planned unfreeze: before=%+v after=%+v", fixture.activeScheduleA, completedScheduleA)
	}
	requireNoPendingScheduleActions(t, completedScheduleA)
	cancelledScheduleBAfter := requireScheduledFreezeRow(t, schedulesAfter, 0, fixture.cancelledScheduleB.reason)
	if cancelledScheduleBAfter != scheduleBBefore {
		t.Fatalf("cancelled Schedule B history changed during startup planned unfreeze: before=%+v after=%+v", scheduleBBefore, cancelledScheduleBAfter)
	}
	requireNoPendingScheduleActions(t, cancelledScheduleBAfter)
	for _, absent := range []string{`action="/scheduled-freezes/edit"`, `action="/scheduled-freezes/start-now"`, `action="/scheduled-freezes/cancel"`} {
		if strings.Contains(schedulesAfter, absent) {
			t.Fatalf("completed/cancelled schedule history still renders pending control %q", absent)
		}
	}

	freezesAfter := requirePage(t, ctx, browser, "/freezes")
	requireActiveFreezeCount(t, freezesAfter, 1)
	mainFreezeAfter, _ := requireActiveFreezeEvidenceForBranch(t, freezesAfter, "main")
	if mainFreezeAfter != fixture.activeMainFreeze {
		t.Fatalf("startup planned unfreeze changed the active main freeze: before=%+v after=%+v", fixture.activeMainFreeze, mainFreezeAfter)
	}
	requireNoActiveFreezeForBranch(t, freezesAfter, fixture.activeReleaseFreeze)
	repositoriesAfter := requirePage(t, ctx, browser, "/repositories")
	requireHealthyActiveRepository(t, repositoriesAfter)
	if csrfAfter := requireHiddenInput(t, repositoriesAfter, "csrf_token"); csrfAfter != csrfBefore {
		t.Fatal("authenticated session CSRF token changed after startup planned-unfreeze convergence")
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	requireRetainedPlannedUnfreezeFixtureState(t, ctx, forgejo, browser, fixture, "startup planned-unfreeze convergence")
	scanRenderedTokenSurfaces(t, ctx, browser)

	quietBefore := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, fixture.releaseHeadSHA)
	requireIdenticalWebhookEvidence(t, converged, quietBefore, "post-restart observation before quiet lifecycle pass")
	waitUntilContext(t, ctx, time.Now().UTC().Add(16*time.Second), "one quiet freeze lifecycle interval")
	quietAfter := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, fixture.releaseHeadSHA)
	requireIdenticalWebhookEvidence(t, quietBefore, quietAfter, "quiet freeze lifecycle pass")

	quietSchedules := requirePage(t, ctx, browser, "/scheduled-freezes")
	quietScheduleA := requireScheduledFreezeRow(t, quietSchedules, 0, fixture.activeScheduleA.reason)
	quietScheduleB := requireScheduledFreezeRow(t, quietSchedules, 0, fixture.cancelledScheduleB.reason)
	if quietScheduleA != completedScheduleA || quietScheduleB != cancelledScheduleBAfter {
		t.Fatalf("quiet lifecycle pass changed schedule history: Schedule A %+v→%+v, Schedule B %+v→%+v", completedScheduleA, quietScheduleA, cancelledScheduleBAfter, quietScheduleB)
	}
	quietFreezes := requirePage(t, ctx, browser, "/freezes")
	requireActiveFreezeCount(t, quietFreezes, 1)
	quietMainFreeze, _ := requireActiveFreezeEvidenceForBranch(t, quietFreezes, "main")
	if quietMainFreeze != fixture.activeMainFreeze {
		t.Fatalf("quiet lifecycle pass changed the active main freeze: before=%+v after=%+v", fixture.activeMainFreeze, quietMainFreeze)
	}
	requireNoActiveFreezeForBranch(t, quietFreezes, fixture.activeReleaseFreeze)
	quietActivity := requireAllActivityPages(t, ctx, browser)
	if requireLatestActivityRow(t, quietActivity, "Scheduled planned unfreeze") != plannedUnfreezeRow || requireLatestActivityRow(t, quietActivity, "Open pull request sync") != startupSyncRow {
		t.Fatal("quiet lifecycle pass changed planned-unfreeze or open-PR sync activity evidence")
	}
	quietRepositories := requirePage(t, ctx, browser, "/repositories")
	requireHealthyActiveRepository(t, quietRepositories)
	if csrfAfter := requireHiddenInput(t, quietRepositories, "csrf_token"); csrfAfter != csrfBefore {
		t.Fatal("authenticated session CSRF token changed during the quiet lifecycle pass")
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	requireRetainedPlannedUnfreezeFixtureState(t, ctx, forgejo, browser, fixture, "quiet lifecycle pass")

	mergeBaseline := quietAfter
	closedDeliveriesBefore := countPullRequestDeliveryActions(mergeBaseline.webhookPage, "closed")
	mergeForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex)
	requireMergedForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	waitForOneNewProcessedPullRequestDelivery(t, ctx, browser, repositoryID, mergeBaseline.webhookRows, "closed")

	var afterMerge webhookSideEffectEvidence
	waitFor(t, 30*time.Second, "terminal release merge webhook with no policy side effects", func() (bool, error) {
		current := collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, fixture.releaseHeadSHA)
		if current.webhookRows > mergeBaseline.webhookRows+1 ||
			current.statusResults > mergeBaseline.statusResults ||
			current.publicationIntents > mergeBaseline.publicationIntents ||
			current.publicationAttempts > mergeBaseline.publicationAttempts ||
			current.activityEvents > mergeBaseline.activityEvents ||
			len(current.freezeStatuses) > len(mergeBaseline.freezeStatuses) {
			t.Fatalf("terminal release merge overshot its exact deltas: webhooks %d→%d, status results %d→%d, intents %d→%d, attempts %d→%d, activity %d→%d, release statuses %d→%d",
				mergeBaseline.webhookRows, current.webhookRows,
				mergeBaseline.statusResults, current.statusResults,
				mergeBaseline.publicationIntents, current.publicationIntents,
				mergeBaseline.publicationAttempts, current.publicationAttempts,
				mergeBaseline.activityEvents, current.activityEvents,
				len(mergeBaseline.freezeStatuses), len(current.freezeStatuses))
		}
		afterMerge = current
		return current.webhookRows == mergeBaseline.webhookRows+1 &&
			current.statusResults == mergeBaseline.statusResults &&
			current.publicationIntents == mergeBaseline.publicationIntents &&
			current.publicationAttempts == mergeBaseline.publicationAttempts &&
			current.activityEvents == mergeBaseline.activityEvents &&
			slices.Equal(current.freezeStatuses, mergeBaseline.freezeStatuses), nil
	})
	if got := countPullRequestDeliveryActions(afterMerge.webhookPage, "closed"); got != closedDeliveriesBefore+1 {
		t.Fatalf("terminal release merge changed processed pull_request/closed rows from %d to %d, want exactly one", closedDeliveriesBefore, got)
	}
	latestDelivery := requireLatestWebhookDeliveryRow(t, afterMerge.webhookPage)
	for _, want := range []string{
		`>` + fixtureOwner + `/` + fixtureRepository + `</span>`,
		`>pull_request · closed</span>`,
		`>Verified</span>`,
		`>Processed</span>`,
		`>No processing error</span>`,
	} {
		if !strings.Contains(latestDelivery, want) {
			t.Fatalf("terminal release merge webhook is missing %q", want)
		}
	}

	finalSchedules := requirePage(t, ctx, browser, "/scheduled-freezes")
	if finalScheduleA := requireScheduledFreezeRow(t, finalSchedules, 0, fixture.activeScheduleA.reason); finalScheduleA != quietScheduleA {
		t.Fatalf("terminal release merge changed completed Schedule A: before=%+v after=%+v", quietScheduleA, finalScheduleA)
	}
	if finalScheduleB := requireScheduledFreezeRow(t, finalSchedules, 0, fixture.cancelledScheduleB.reason); finalScheduleB != quietScheduleB {
		t.Fatalf("terminal release merge changed cancelled Schedule B: before=%+v after=%+v", quietScheduleB, finalScheduleB)
	}
	finalFreezes := requirePage(t, ctx, browser, "/freezes")
	requireActiveFreezeCount(t, finalFreezes, 1)
	finalMainFreeze, _ := requireActiveFreezeEvidenceForBranch(t, finalFreezes, "main")
	if finalMainFreeze != fixture.activeMainFreeze {
		t.Fatalf("terminal release merge changed the active main freeze: before=%+v after=%+v", fixture.activeMainFreeze, finalMainFreeze)
	}
	requireNoActiveFreezeForBranch(t, finalFreezes, fixture.activeReleaseFreeze)
	finalRepositories := requirePage(t, ctx, browser, "/repositories")
	requireHealthyActiveRepository(t, finalRepositories)
	requireRetainedPlannedUnfreezeFixtureState(t, ctx, forgejo, browser, fixture, "terminal release merge")
	requireMergedForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	scanRenderedTokenSurfaces(t, ctx, browser)

	t.Logf("planned-unfreeze restart slice passed: stop margin %s; restart began %s overdue; slice runtime %s", stopCompletionMargin.Round(time.Millisecond), restartedAt.Sub(plannedEndsAt).Round(time.Millisecond), time.Since(sliceStartedAt).Round(time.Millisecond))
}

func proveRoleBoundaries(t *testing.T, ctx context.Context, forgejo *forgejoAPI, allRoleBrowser *thawguardBrowser, cfg e2eConfig, repositoryID int64, fixture scheduledFreezeLifecycleFixture) terminalDiagnosticsFixture {
	t.Helper()
	const (
		adminEmail              = "admin-only@thawguard.test"
		freezerEmail            = "freezer@thawguard.test"
		thawApproverEmail       = "thaw-approver@thawguard.test"
		viewerEmail             = "viewer@thawguard.test"
		scheduleCReason         = "Fictional role-boundary Schedule C"
		scheduleCEditedReason   = "Fictional role-boundary Schedule C edited"
		roleThawReason          = "Fictional role-boundary unique-head thaw"
		frozenDescription       = "Branch is frozen; merge is blocked by Thawguard"
		explicitThawDescription = "PR is explicitly thawed during an active freeze"
	)
	sliceStartedAt := time.Now().UTC()
	if fixture.primaryPullRequestIndex <= 0 || fixture.sharedHeadPullRequestIndex <= 0 || fixture.releasePullRequestIndex <= 0 || len(fixture.sharedHeadSHA) < 12 || len(fixture.releaseHeadSHA) < 12 || fixture.activeMainFreeze.id <= 0 {
		t.Fatalf("role-boundary proof received an incomplete fixture: %+v", fixture)
	}

	completedScheduleA := requireScheduledFreezeRow(t, requirePage(t, ctx, allRoleBrowser, "/scheduled-freezes"), 0, fixture.activeScheduleA.reason)
	if completedScheduleA.branch != fixtureReleaseBranch || completedScheduleA.status != "Completed" || completedScheduleA.endedAt == "" || completedScheduleA.endedAt == "—" {
		t.Fatalf("role-boundary baseline has unexpected completed Schedule A: %+v", completedScheduleA)
	}
	cancelledScheduleB := requireScheduledFreezeRow(t, requirePage(t, ctx, allRoleBrowser, "/scheduled-freezes"), 0, fixture.cancelledScheduleB.reason)
	if cancelledScheduleB.branch != fixtureReleaseBranch || cancelledScheduleB.status != "Cancelled" || cancelledScheduleB.endedAt == "" || cancelledScheduleB.endedAt == "—" {
		t.Fatalf("role-boundary baseline has unexpected cancelled Schedule B: %+v", cancelledScheduleB)
	}
	baselineFreezes := requirePage(t, ctx, allRoleBrowser, "/freezes")
	requireActiveFreezeCount(t, baselineFreezes, 1)
	mainFreeze, _ := requireActiveFreezeEvidenceForBranch(t, baselineFreezes, "main")
	if mainFreeze != fixture.activeMainFreeze {
		t.Fatalf("role-boundary baseline changed the retained main freeze: fixture=%+v rendered=%+v", fixture.activeMainFreeze, mainFreeze)
	}
	requireNoActiveFreezeForBranch(t, baselineFreezes, fixture.activeReleaseFreeze)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.primaryPullRequestIndex, "main", fixturePrimaryPRTitle, fixture.sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.sharedHeadPullRequestIndex, "main", fixtureSharedHeadPRTitle, fixture.sharedHeadSHA)
	requireMergedForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	sharedStatusesBeforeRoles, err := listForgejoFreezeStatuses(ctx, forgejo, fixture.sharedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sharedStatusesBeforeRoles, fixture.mainSharedHeadStatuses) {
		t.Fatalf("role-boundary baseline changed shared-main status history: retained=%+v current=%+v", fixture.mainSharedHeadStatuses, sharedStatusesBeforeRoles)
	}
	releaseStatusesBeforeRoles, err := listForgejoFreezeStatuses(ctx, forgejo, fixture.releaseHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	activityHistory := requireAllActivityPages(t, ctx, allRoleBrowser)
	sharedThawHistory := requireLatestActivityRow(t, activityHistory, "Shared-head thaw")
	plannedUnfreezeHistory := requireLatestActivityRow(t, activityHistory, "Scheduled planned unfreeze")
	terminalReleaseDelivery := requireLatestWebhookDeliveryRow(t, requirePage(t, ctx, allRoleBrowser, "/webhooks"))
	if !strings.Contains(terminalReleaseDelivery, `>pull_request · closed</span>`) {
		t.Fatal("role-boundary baseline did not retain the terminal release closed webhook")
	}

	createRoleBoundaryUser(t, ctx, allRoleBrowser, adminEmail, "E2E Admin Only", "admin", cfg.thawguardPassword, 1)
	createRoleBoundaryUser(t, ctx, allRoleBrowser, freezerEmail, "E2E Freezer", "freezer", cfg.thawguardPassword, 2)
	createRoleBoundaryUser(t, ctx, allRoleBrowser, thawApproverEmail, "E2E Thaw Approver", "thaw_approver", cfg.thawguardPassword, 3)

	adminSession := loginRoleBoundaryUser(t, ctx, cfg, adminEmail, "E2E Admin Only", "Admin")
	freezerSession := loginRoleBoundaryUser(t, ctx, cfg, freezerEmail, "E2E Freezer", "Freezer")
	thawApproverSession := loginRoleBoundaryUser(t, ctx, cfg, thawApproverEmail, "E2E Thaw Approver", "Thaw approver")
	viewerUserID := createRoleBoundaryUser(t, ctx, adminSession.browser, viewerEmail, "E2E Viewer", "viewer", cfg.thawguardPassword, 4)
	viewerSession := loginRoleBoundaryUser(t, ctx, cfg, viewerEmail, "E2E Viewer", "Viewer")
	allRoleSession := currentRoleBoundarySession(t, ctx, allRoleBrowser, "admin@thawguard.test", "E2E Admin", "Admin, Freezer, Thaw approver, Viewer")
	roleSessions := []roleBoundarySession{adminSession, freezerSession, thawApproverSession, viewerSession}
	requireRoleSessionsIsolated(t, ctx, append([]roleBoundarySession{allRoleSession}, roleSessions...))

	adminPages := requireRoleBoundaryReadAccess(t, ctx, adminSession, true)
	freezerPages := requireRoleBoundaryReadAccess(t, ctx, freezerSession, false)
	thawPages := requireRoleBoundaryReadAccess(t, ctx, thawApproverSession, false)
	viewerPages := requireRoleBoundaryReadAccess(t, ctx, viewerSession, false)
	requireRoleBoundaryControls(t, adminPages, true, false, false)
	requireRoleBoundaryControls(t, freezerPages, false, true, false)
	requireRoleBoundaryControls(t, thawPages, false, false, true)
	requireRoleBoundaryControls(t, viewerPages, false, false, false)

	scheduleReasons := []string{completedScheduleA.reason, cancelledScheduleB.reason}
	trackedHeads := []string{fixture.sharedHeadSHA, fixture.releaseHeadSHA}
	beforeDenied := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, scheduleReasons, trackedHeads)
	if beforeDenied.userCount != 5 || beforeDenied.repositoryCount != 1 || beforeDenied.activeFreezes != 1 || beforeDenied.scheduledCount != 2 {
		t.Fatalf("unexpected role-boundary baseline counts: users=%d repositories=%d active=%d schedules=%d", beforeDenied.userCount, beforeDenied.repositoryCount, beforeDenied.activeFreezes, beforeDenied.scheduledCount)
	}
	repositoryValue := strconv.FormatInt(repositoryID, 10)
	viewerUserValue := strconv.FormatInt(viewerUserID, 10)
	adminOnlyRouteProbes := []struct {
		path   string
		values url.Values
		label  string
	}{
		{path: "/repositories/branches", values: url.Values{"repository_id": {repositoryValue}, "branch": {fixtureScheduledBranch}}, label: "managed-branch addition"},
		{path: "/repositories/branches/remove", values: url.Values{"repository_id": {repositoryValue}, "branch": {fixtureReleaseBranch}}, label: "managed-branch removal"},
		{path: "/repositories/webhook-secret", values: url.Values{"repository_id": {repositoryValue}, "webhook_secret": {cfg.webhookSecret}}, label: "webhook-secret rotation"},
		{path: "/repositories/status-token", values: url.Values{"repository_id": {repositoryValue}, "status_token": {cfg.replacementStatusToken}}, label: "status-token rotation"},
		{path: "/repositories/setup-check", values: url.Values{"repository_id": {repositoryValue}}, label: "readiness check"},
		{path: "/repositories/status-verification", values: url.Values{"repository_id": {repositoryValue}}, label: "status verification"},
		{path: "/repositories/activate", values: url.Values{"repository_id": {repositoryValue}}, label: "enforcement activation"},
		{path: "/repositories/deactivate", values: url.Values{"repository_id": {repositoryValue}}, label: "enforcement deactivation"},
		{path: "/repositories/reconcile", values: url.Values{"repository_id": {repositoryValue}}, label: "enforcement reconciliation"},
		{path: "/repositories/recover", values: url.Values{"repository_id": {repositoryValue}}, label: "enforcement recovery"},
		{path: "/users/roles", values: url.Values{"user_id": {viewerUserValue}, "roles": {"freezer"}}, label: "user role update"},
		{path: "/users/disable", values: url.Values{"user_id": {viewerUserValue}}, label: "user disable"},
		{path: "/users/enable", values: url.Values{"user_id": {viewerUserValue}}, label: "user enable"},
		{path: "/users/reset-password", values: url.Values{
			"user_id":                         {viewerUserValue},
			"temporary_password":              {cfg.thawguardPassword},
			"temporary_password_confirmation": {cfg.thawguardPassword},
		}, label: "user password reset"},
	}

	for _, session := range []roleBoundarySession{freezerSession, thawApproverSession, viewerSession} {
		slug := roleBoundarySlug(session.roleLabel)
		requireForbiddenRoleMutation(t, ctx, session, "/repositories", url.Values{
			"forge":          {"forgejo"},
			"base_url":       {cfg.forgejoURL},
			"owner":          {fixtureOwner},
			"name":           {"denied-" + slug},
			"default_branch": {"main"},
		}, session.roleLabel+" repository creation")
		requireForbiddenRoleMutation(t, ctx, session, "/users", url.Values{
			"email":        {"denied-" + slug + "@thawguard.test"},
			"display_name": {"Denied " + session.roleLabel},
			"password":     {cfg.thawguardPassword},
			"roles":        {"viewer"},
		}, session.roleLabel+" user creation")
		for _, probe := range adminOnlyRouteProbes {
			requireForbiddenRoleMutation(t, ctx, session, probe.path, probe.values, session.roleLabel+" "+probe.label)
		}
	}
	deniedScheduleStartsAt := time.Now().UTC().Truncate(time.Second).Add(45 * time.Minute)
	deniedScheduleEndsAt := deniedScheduleStartsAt.Add(15 * time.Minute)
	for _, session := range []roleBoundarySession{adminSession, thawApproverSession, viewerSession} {
		slug := roleBoundarySlug(session.roleLabel)
		requireForbiddenRoleMutation(t, ctx, session, "/freezes", url.Values{
			"repository_id":           {strconv.FormatInt(repositoryID, 10)},
			"branch":                  {fixtureReleaseBranch},
			"reason":                  {"Denied active freeze by " + session.displayName},
			"timezone_offset_minutes": {"0"},
		}, session.roleLabel+" active-freeze creation")
		for _, path := range []string{"/freezes/end", "/freezes/cancel"} {
			requireForbiddenRoleMutation(t, ctx, session, path, url.Values{
				"freeze_id": {strconv.FormatInt(mainFreeze.id, 10)},
			}, session.roleLabel+" active-freeze close via "+path)
		}
		requireForbiddenRoleMutation(t, ctx, session, "/scheduled-freezes", url.Values{
			"repository_id":           {strconv.FormatInt(repositoryID, 10)},
			"branch":                  {fixtureReleaseBranch},
			"reason":                  {"Denied schedule by " + slug},
			"starts_at":               {deniedScheduleStartsAt.Format(time.RFC3339)},
			"planned_ends_at":         {deniedScheduleEndsAt.Format(time.RFC3339)},
			"timezone_offset_minutes": {"0"},
		}, session.roleLabel+" scheduled-freeze creation")
	}
	afterDenied := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, scheduleReasons, trackedHeads)
	requireUnchangedRoleBoundaryEvidence(t, beforeDenied, afterDenied, "initial wrong-role probes")
	requireRoleSessionsIsolated(t, ctx, append([]roleBoundarySession{allRoleSession}, roleSessions...))

	scheduleCBase := time.Now().UTC().Truncate(time.Second)
	scheduleCStartsAt := scheduleCBase.Add(20 * time.Minute)
	scheduleCPlannedEndsAt := scheduleCBase.Add(30 * time.Minute)
	beforeScheduleCCreate := afterDenied
	requireRawScheduledFreezeMutation(t, ctx, freezerSession.browser, "/scheduled-freezes", url.Values{
		"repository_id":           {strconv.FormatInt(repositoryID, 10)},
		"branch":                  {fixtureReleaseBranch},
		"reason":                  {scheduleCReason},
		"starts_at":               {scheduleCStartsAt.Format(time.RFC3339)},
		"planned_ends_at":         {scheduleCPlannedEndsAt.Format(time.RFC3339)},
		"timezone_offset_minutes": {"0"},
	}, "Freezer creates Schedule C")
	scheduleCPage := requirePage(t, ctx, freezerSession.browser, "/scheduled-freezes")
	scheduleC := requireScheduledFreezeRow(t, scheduleCPage, 0, scheduleCReason)
	if scheduleC.id <= 0 || scheduleC.branch != fixtureReleaseBranch || scheduleC.status != "Upcoming" || scheduleC.startsAt != scheduleTime(scheduleCStartsAt) || scheduleC.plannedEndsAt != scheduleTime(scheduleCPlannedEndsAt) || scheduleC.endedAt != "—" {
		t.Fatalf("Schedule C has unexpected creation evidence: %+v", scheduleC)
	}
	requirePendingScheduleActions(t, scheduleCPage, scheduleC, scheduleCStartsAt, scheduleCPlannedEndsAt)
	scheduleCCreatedActivity := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, allRoleBrowser), "Freeze schedule")
	requireRoleBoundaryActivity(t, scheduleCCreatedActivity, "E2E Freezer", "Freeze schedule", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Scheduled", scheduleCReason, "Starts "+scheduleTime(scheduleCStartsAt), "planned unfreeze "+scheduleTime(scheduleCPlannedEndsAt))
	afterScheduleCCreate := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, append(scheduleReasons, scheduleCReason), trackedHeads)
	if afterScheduleCCreate.scheduledCount != beforeScheduleCCreate.scheduledCount+1 || afterScheduleCCreate.activeFreezes != beforeScheduleCCreate.activeFreezes || afterScheduleCCreate.userCount != beforeScheduleCCreate.userCount || afterScheduleCCreate.repositoryCount != beforeScheduleCCreate.repositoryCount || afterScheduleCCreate.mainFreeze != beforeScheduleCCreate.mainFreeze {
		t.Fatal("Schedule C creation changed non-schedule state or the wrong schedule count")
	}
	requireScheduleOnlyActivityDelta(t, beforeScheduleCCreate.sideEffects, afterScheduleCCreate.sideEffects, 1, "Schedule C creation")
	requireRoleStatusHistoriesUnchanged(t, beforeScheduleCCreate.statusHistories, afterScheduleCCreate.statusHistories, "Schedule C creation")
	requireSameScheduleEvidence(t, completedScheduleA, afterScheduleCCreate.schedules[0], "Schedule C creation changed completed Schedule A")
	requireSameScheduleEvidence(t, cancelledScheduleB, afterScheduleCCreate.schedules[1], "Schedule C creation changed cancelled Schedule B")

	requireScheduleRoleControls(t, ctx, adminSession, scheduleCReason, false, true, true, false)
	requireScheduleRoleControls(t, ctx, freezerSession, scheduleCReason, true, true, true, true)
	requireScheduleRoleControls(t, ctx, thawApproverSession, scheduleCReason, false, false, false, false)
	requireScheduleRoleControls(t, ctx, viewerSession, scheduleCReason, false, false, false, false)

	beforeDeniedScheduleActions := afterScheduleCCreate
	requireForbiddenRoleMutation(t, ctx, adminSession, "/scheduled-freezes/cancel", url.Values{"freeze_id": {strconv.FormatInt(scheduleC.id, 10)}}, "Admin-only pending schedule cancellation")
	for _, session := range []roleBoundarySession{thawApproverSession, viewerSession} {
		requireForbiddenRoleMutation(t, ctx, session, "/scheduled-freezes/edit", url.Values{
			"freeze_id":               {strconv.FormatInt(scheduleC.id, 10)},
			"reason":                  {scheduleCReason},
			"starts_at":               {scheduleCStartsAt.Format(time.RFC3339)},
			"planned_ends_at":         {scheduleCPlannedEndsAt.Format(time.RFC3339)},
			"timezone_offset_minutes": {"0"},
		}, session.roleLabel+" pending schedule edit")
		requireForbiddenRoleMutation(t, ctx, session, "/scheduled-freezes/start-now", url.Values{"freeze_id": {strconv.FormatInt(scheduleC.id, 10)}}, session.roleLabel+" pending schedule Start Now")
		requireForbiddenRoleMutation(t, ctx, session, "/scheduled-freezes/cancel", url.Values{"freeze_id": {strconv.FormatInt(scheduleC.id, 10)}}, session.roleLabel+" pending schedule cancellation")
	}
	afterDeniedScheduleActions := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, append(scheduleReasons, scheduleCReason), trackedHeads)
	requireUnchangedRoleBoundaryEvidence(t, beforeDeniedScheduleActions, afterDeniedScheduleActions, "wrong-role pending schedule probes")

	editedScheduleCStartsAt := scheduleCBase.Add(25 * time.Minute)
	editedScheduleCPlannedEndsAt := scheduleCBase.Add(35 * time.Minute)
	beforeScheduleCEdit := afterDeniedScheduleActions
	requireRawScheduledFreezeMutation(t, ctx, adminSession.browser, "/scheduled-freezes/edit", url.Values{
		"freeze_id":               {strconv.FormatInt(scheduleC.id, 10)},
		"reason":                  {scheduleCEditedReason},
		"starts_at":               {editedScheduleCStartsAt.Format(time.RFC3339)},
		"planned_ends_at":         {editedScheduleCPlannedEndsAt.Format(time.RFC3339)},
		"timezone_offset_minutes": {"0"},
	}, "Admin-only edits Schedule C")
	editedScheduleC := requireScheduledFreezeRow(t, requirePage(t, ctx, adminSession.browser, "/scheduled-freezes"), scheduleC.id, scheduleCEditedReason)
	if editedScheduleC.id != scheduleC.id || editedScheduleC.branch != fixtureReleaseBranch || editedScheduleC.status != "Upcoming" || editedScheduleC.startsAt != scheduleTime(editedScheduleCStartsAt) || editedScheduleC.plannedEndsAt != scheduleTime(editedScheduleCPlannedEndsAt) || editedScheduleC.endedAt != "—" {
		t.Fatalf("Schedule C has unexpected edit evidence: before=%+v after=%+v", scheduleC, editedScheduleC)
	}
	requireScheduleRoleControls(t, ctx, adminSession, scheduleCEditedReason, false, true, true, false)
	scheduleCEditedActivity := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, allRoleBrowser), "Freeze schedule")
	wantScheduleCEdit := "Reason " + scheduleCReason + " → " + scheduleCEditedReason + "; starts " + scheduleTime(scheduleCStartsAt) + " → " + scheduleTime(editedScheduleCStartsAt) + "; planned unfreeze " + scheduleTime(scheduleCPlannedEndsAt) + " → " + scheduleTime(editedScheduleCPlannedEndsAt) + "."
	requireRoleBoundaryActivity(t, scheduleCEditedActivity, "E2E Admin Only", "Freeze schedule", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Changed", scheduleCEditedReason, wantScheduleCEdit)
	afterScheduleCEdit := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, trackedHeads)
	requireScheduleOnlyActivityDelta(t, beforeScheduleCEdit.sideEffects, afterScheduleCEdit.sideEffects, 1, "Schedule C edit")
	if afterScheduleCEdit.userCount != beforeScheduleCEdit.userCount || afterScheduleCEdit.repositoryCount != beforeScheduleCEdit.repositoryCount || afterScheduleCEdit.activeFreezes != beforeScheduleCEdit.activeFreezes || afterScheduleCEdit.scheduledCount != beforeScheduleCEdit.scheduledCount || afterScheduleCEdit.mainFreeze != beforeScheduleCEdit.mainFreeze {
		t.Fatal("Schedule C edit changed unrelated role-boundary state")
	}
	requireRoleStatusHistoriesUnchanged(t, beforeScheduleCEdit.statusHistories, afterScheduleCEdit.statusHistories, "Schedule C edit")
	requireSameScheduleEvidence(t, completedScheduleA, afterScheduleCEdit.schedules[0], "Schedule C edit changed completed Schedule A")
	requireSameScheduleEvidence(t, cancelledScheduleB, afterScheduleCEdit.schedules[1], "Schedule C edit changed cancelled Schedule B")

	beforeStartNow := afterScheduleCEdit
	activityBeforeStartNow := requireAllActivityPages(t, ctx, allRoleBrowser)
	startNowEventsBefore := countActivityEvents(activityBeforeStartNow, "Scheduled freeze Start Now")
	openSyncsBeforeStartNow := countOpenPullRequestSyncEvents(activityBeforeStartNow)
	requireRawScheduledFreezeMutation(t, ctx, adminSession.browser, "/scheduled-freezes/start-now", url.Values{"freeze_id": {strconv.FormatInt(scheduleC.id, 10)}}, "Admin-only starts Schedule C now")
	afterStartNow := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, trackedHeads)
	if afterStartNow.activeFreezes != beforeStartNow.activeFreezes+1 || afterStartNow.scheduledCount != beforeStartNow.scheduledCount || afterStartNow.userCount != beforeStartNow.userCount || afterStartNow.repositoryCount != beforeStartNow.repositoryCount || afterStartNow.mainFreeze != beforeStartNow.mainFreeze {
		t.Fatal("Schedule C Start Now changed unrelated state or the wrong active-freeze count")
	}
	requireScheduleOnlyActivityDelta(t, beforeStartNow.sideEffects, afterStartNow.sideEffects, 2, "Schedule C Start Now without an open release PR")
	requireRoleStatusHistoriesUnchanged(t, beforeStartNow.statusHistories, afterStartNow.statusHistories, "Schedule C Start Now")
	activeScheduleC := afterStartNow.schedules[2]
	if activeScheduleC.id != 0 || activeScheduleC.branch != fixtureReleaseBranch || activeScheduleC.reason != scheduleCEditedReason || activeScheduleC.status != "Active" || activeScheduleC.plannedEndsAt != scheduleTime(editedScheduleCPlannedEndsAt) || activeScheduleC.endedAt != "—" {
		t.Fatalf("Schedule C has unexpected Start Now evidence: %+v", activeScheduleC)
	}
	requireNoPendingScheduleActions(t, activeScheduleC)
	activeReleaseFreeze, _ := requireActiveFreezeEvidenceForBranch(t, requirePage(t, ctx, allRoleBrowser, "/freezes"), fixtureReleaseBranch)
	if activeReleaseFreeze.id != scheduleC.id || activeReleaseFreeze.reason != scheduleCEditedReason || activeReleaseFreeze.status != "Frozen" {
		t.Fatalf("Schedule C Start Now created the wrong active release freeze: schedule=%+v active=%+v", editedScheduleC, activeReleaseFreeze)
	}
	adminFreezesAfterStart := requirePage(t, ctx, adminSession.browser, "/freezes")
	for _, absent := range []string{`action="/freezes"`, `action="/freezes/end"`, `action="/freezes/cancel"`} {
		if strings.Contains(adminFreezesAfterStart, absent) {
			t.Fatalf("Admin-only active-freeze view unexpectedly renders %q", absent)
		}
	}
	activityAfterStartNow := requireAllActivityPages(t, ctx, allRoleBrowser)
	if countActivityEvents(activityAfterStartNow, "Scheduled freeze Start Now") != startNowEventsBefore+1 || countOpenPullRequestSyncEvents(activityAfterStartNow) != openSyncsBeforeStartNow+1 {
		t.Fatal("Schedule C Start Now did not add exactly one Start Now and one open-PR sync activity")
	}
	scheduleCStartedActivity := requireLatestActivityRow(t, activityAfterStartNow, "Scheduled freeze Start Now")
	requireRoleBoundaryActivity(t, scheduleCStartedActivity, "E2E Admin Only", "Scheduled freeze Start Now", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Started", scheduleCEditedReason, "planned unfreeze "+scheduleTime(editedScheduleCPlannedEndsAt))
	requireLatestOpenPullRequestSync(t, activityAfterStartNow, 2)
	requireMergedForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.primaryPullRequestIndex, "main", fixturePrimaryPRTitle, fixture.sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.sharedHeadPullRequestIndex, "main", fixtureSharedHeadPRTitle, fixture.sharedHeadSHA)

	beforeAdminActiveCancel := afterStartNow
	requireForbiddenRoleMutation(t, ctx, adminSession, "/freezes/cancel", url.Values{"freeze_id": {strconv.FormatInt(activeReleaseFreeze.id, 10)}}, "Admin-only active Schedule C cancellation")
	afterAdminActiveCancel := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, trackedHeads)
	requireUnchangedRoleBoundaryEvidence(t, beforeAdminActiveCancel, afterAdminActiveCancel, "Admin-only active Schedule C cancellation probe")

	activityBeforeFreezerCancel := requireAllActivityPages(t, ctx, allRoleBrowser)
	openSyncsBeforeFreezerCancel := countOpenPullRequestSyncEvents(activityBeforeFreezerCancel)
	freezerFreezePage := requirePage(t, ctx, freezerSession.browser, "/freezes")
	if !strings.Contains(freezerFreezePage, `name="freeze_id" value="`+strconv.FormatInt(activeReleaseFreeze.id, 10)+`"`) || !strings.Contains(freezerFreezePage, `action="/freezes/cancel"`) {
		t.Fatal("Freezer session is missing the exact active Schedule C cancellation control")
	}
	response, err := freezerSession.browser.postFormNoRedirect(ctx, "/freezes/cancel", url.Values{
		"csrf_token": {freezerSession.csrfToken},
		"freeze_id":  {strconv.FormatInt(activeReleaseFreeze.id, 10)},
	})
	if err != nil {
		t.Fatalf("Freezer cancels active Schedule C: %v", err)
	}
	if response.statusCode != http.StatusSeeOther || response.location != "/freezes?notice=freeze-cancelled" {
		t.Fatalf("Freezer active Schedule C cancellation returned HTTP %d with Location %q, want 303 to /freezes?notice=freeze-cancelled", response.statusCode, response.location)
	}
	afterFreezerCancel := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, fixture.sharedHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, trackedHeads)
	if afterFreezerCancel.activeFreezes != afterAdminActiveCancel.activeFreezes-1 || afterFreezerCancel.scheduledCount != afterAdminActiveCancel.scheduledCount || afterFreezerCancel.userCount != afterAdminActiveCancel.userCount || afterFreezerCancel.repositoryCount != afterAdminActiveCancel.repositoryCount || afterFreezerCancel.mainFreeze != afterAdminActiveCancel.mainFreeze {
		t.Fatal("Freezer active Schedule C cancellation changed unrelated state or the wrong active-freeze count")
	}
	requireScheduleOnlyActivityDelta(t, afterAdminActiveCancel.sideEffects, afterFreezerCancel.sideEffects, 2, "Freezer active Schedule C cancellation without an open release PR")
	requireRoleStatusHistoriesUnchanged(t, afterAdminActiveCancel.statusHistories, afterFreezerCancel.statusHistories, "Freezer active Schedule C cancellation")
	cancelledScheduleC := afterFreezerCancel.schedules[2]
	if cancelledScheduleC.id != 0 || cancelledScheduleC.branch != fixtureReleaseBranch || cancelledScheduleC.reason != scheduleCEditedReason || cancelledScheduleC.status != "Cancelled" || cancelledScheduleC.endedAt == "" || cancelledScheduleC.endedAt == "—" {
		t.Fatalf("Schedule C has unexpected active-cancellation evidence: %+v", cancelledScheduleC)
	}
	requireNoPendingScheduleActions(t, cancelledScheduleC)
	finalFreezesAfterScheduleC := requirePage(t, ctx, allRoleBrowser, "/freezes")
	requireActiveFreezeCount(t, finalFreezesAfterScheduleC, 1)
	requireNoActiveFreezeForBranch(t, finalFreezesAfterScheduleC, activeReleaseFreeze)
	activityAfterFreezerCancel := requireAllActivityPages(t, ctx, allRoleBrowser)
	if countOpenPullRequestSyncEvents(activityAfterFreezerCancel) != openSyncsBeforeFreezerCancel+1 {
		t.Fatal("Freezer active Schedule C cancellation did not add exactly one open-PR sync activity")
	}
	scheduleCCancelledActivity := requireLatestActivityRow(t, activityAfterFreezerCancel, "Branch freeze")
	requireRoleBoundaryActivity(t, scheduleCCancelledActivity, "E2E Freezer", "Branch freeze", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Cancelled", scheduleCEditedReason)
	requireLatestOpenPullRequestSync(t, activityAfterFreezerCancel, 2)

	beforeUniqueHead := afterFreezerCancel
	sharedStatusesBeforeAdvance := slices.Clone(beforeUniqueHead.statusHistories[0])
	webhookRowsBeforeAdvance := beforeUniqueHead.sideEffects.webhookRows
	uniqueHeadSHA := advanceFeatureBranch(
		t,
		ctx,
		forgejo,
		fixture.primaryPullRequestIndex,
		fixture.sharedHeadSHA,
		fixtureRoleThawFilename,
		"Advance fictional role-boundary thaw head",
		"unique head for role-boundary thaw proof\n",
		"role-boundary thaw",
	)
	waitForOneNewProcessedPullRequestDelivery(t, ctx, allRoleBrowser, repositoryID, webhookRowsBeforeAdvance, "synchronized")
	waitForStatusWithDescription(t, ctx, forgejo, uniqueHeadSHA, "failure", frozenDescription)
	afterUniqueHead := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, uniqueHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, []string{uniqueHeadSHA, fixture.sharedHeadSHA, fixture.releaseHeadSHA})
	roleBoundaryDelivery := requireLatestWebhookDeliveryRow(t, afterUniqueHead.sideEffects.webhookPage)
	requireProcessedWebhookRowEvidence(t, roleBoundaryDelivery, "synchronized")
	if afterUniqueHead.sideEffects.webhookRows != beforeUniqueHead.sideEffects.webhookRows+1 ||
		afterUniqueHead.sideEffects.statusResults != beforeUniqueHead.sideEffects.statusResults+2 ||
		afterUniqueHead.sideEffects.publicationIntents != beforeUniqueHead.sideEffects.publicationIntents+1 ||
		afterUniqueHead.sideEffects.publicationAttempts != beforeUniqueHead.sideEffects.publicationAttempts+2 ||
		afterUniqueHead.sideEffects.activityEvents != beforeUniqueHead.sideEffects.activityEvents {
		t.Fatalf("unique-head synchronized webhook had unexpected global deltas: webhooks %d→%d results %d→%d intents %d→%d attempts %d→%d activity %d→%d",
			beforeUniqueHead.sideEffects.webhookRows, afterUniqueHead.sideEffects.webhookRows,
			beforeUniqueHead.sideEffects.statusResults, afterUniqueHead.sideEffects.statusResults,
			beforeUniqueHead.sideEffects.publicationIntents, afterUniqueHead.sideEffects.publicationIntents,
			beforeUniqueHead.sideEffects.publicationAttempts, afterUniqueHead.sideEffects.publicationAttempts,
			beforeUniqueHead.sideEffects.activityEvents, afterUniqueHead.sideEffects.activityEvents)
	}
	if len(afterUniqueHead.statusHistories[0]) != 1 {
		t.Fatalf("new unique head has %d Forgejo required-context statuses, want exactly one", len(afterUniqueHead.statusHistories[0]))
	}
	uniqueFailure := afterUniqueHead.statusHistories[0][0]
	if uniqueFailure.Context != requiredContext || uniqueFailure.Status != "failure" || uniqueFailure.Description != frozenDescription {
		t.Fatalf("new unique head has unexpected synchronized status: %+v", uniqueFailure)
	}
	sharedStatusesAfterAdvance := afterUniqueHead.statusHistories[1]
	if len(sharedStatusesAfterAdvance) != len(sharedStatusesBeforeAdvance)+1 || !slices.Equal(sharedStatusesAfterAdvance[:len(sharedStatusesBeforeAdvance)], sharedStatusesBeforeAdvance) {
		t.Fatalf("old shared-head history was not retained with exactly one old-head recomputation: before=%+v after=%+v", sharedStatusesBeforeAdvance, sharedStatusesAfterAdvance)
	}
	oldHeadRecomputed := sharedStatusesAfterAdvance[len(sharedStatusesAfterAdvance)-1]
	if oldHeadRecomputed.Context != requiredContext || oldHeadRecomputed.Status != "success" || oldHeadRecomputed.Description != explicitThawDescription {
		t.Fatalf("secondary PR old-head recomputation has unexpected status: %+v", oldHeadRecomputed)
	}
	if !slices.Equal(afterUniqueHead.statusHistories[2], releaseStatusesBeforeRoles) {
		t.Fatal("unique-head synchronized webhook changed the merged release head status history")
	}
	uniqueDecision := requireDecisionResultRowForHead(t, requirePage(t, ctx, allRoleBrowser, "/decisions"), uniqueHeadSHA)
	for _, want := range []string{`>#` + strconv.Itoa(fixture.primaryPullRequestIndex) + `</code>`, `>main</code>`, `title="` + uniqueHeadSHA + `"`, `>Blocked</span>`, frozenDescription} {
		if !strings.Contains(uniqueDecision, want) {
			t.Fatalf("unique-head synchronized decision is missing %q", want)
		}
	}
	uniqueIntent := requirePublicationIntentRowForHead(t, requirePage(t, ctx, allRoleBrowser, "/publications"), uniqueHeadSHA)
	uniqueAttempt := requirePublicationAttemptRowForHead(t, requirePage(t, ctx, allRoleBrowser, "/publications"), uniqueHeadSHA)
	for label, row := range map[string]string{"intent": uniqueIntent, "attempt": uniqueAttempt} {
		for _, want := range []string{uniqueHeadSHA, requiredContext, "failure", "forgejo_status", frozenDescription} {
			if !strings.Contains(row, want) {
				t.Fatalf("unique-head synchronized %s evidence is missing %q", label, want)
			}
		}
	}
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.primaryPullRequestIndex, "main", fixturePrimaryPRTitle, uniqueHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.sharedHeadPullRequestIndex, "main", fixtureSharedHeadPRTitle, fixture.sharedHeadSHA)
	if currentMain, _ := requireActiveFreezeEvidenceForBranch(t, requirePage(t, ctx, allRoleBrowser, "/freezes"), "main"); currentMain != mainFreeze {
		t.Fatalf("unique-head synchronized webhook changed the active main freeze: before=%+v after=%+v", mainFreeze, currentMain)
	}

	beforeDeniedThaws := afterUniqueHead
	deniedThawValues := url.Values{
		"repository_id":      {strconv.FormatInt(repositoryID, 10)},
		"pull_request_index": {strconv.Itoa(fixture.primaryPullRequestIndex)},
		"target_branch":      {"main"},
		"reason":             {roleThawReason},
	}
	for _, session := range []roleBoundarySession{adminSession, freezerSession, viewerSession} {
		requireForbiddenRoleMutation(t, ctx, session, "/decisions", deniedThawValues, session.roleLabel+" unique-head thaw approval")
	}
	afterDeniedThaws := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, uniqueHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, []string{uniqueHeadSHA, fixture.sharedHeadSHA, fixture.releaseHeadSHA})
	requireUnchangedRoleBoundaryEvidence(t, beforeDeniedThaws, afterDeniedThaws, "wrong-role unique-head thaw probes")

	decisionsPage := requirePage(t, ctx, thawApproverSession.browser, "/decisions")
	thawForm := requireRenderedForm(t, decisionsPage, `<form method="post" action="/decisions"`, "role-boundary thaw")
	if strings.Contains(thawForm, `name="head_sha"`) {
		t.Fatal("role-boundary thaw form must not submit a client-provided head SHA")
	}
	openSyncsBeforeThaw := countOpenPullRequestSyncEvents(requireAllActivityPages(t, ctx, allRoleBrowser))
	beforeAllowedThaw := afterDeniedThaws
	response, err = thawApproverSession.browser.postFormNoRedirect(ctx, "/decisions", url.Values{
		"csrf_token":         {thawApproverSession.csrfToken},
		"repository_id":      {strconv.FormatInt(repositoryID, 10)},
		"pull_request_index": {strconv.Itoa(fixture.primaryPullRequestIndex)},
		"target_branch":      {"main"},
		"reason":             {roleThawReason},
	})
	if err != nil {
		t.Fatalf("Thaw approver unique-head thaw: %v", err)
	}
	if response.statusCode == http.StatusConflict || bytes.Contains(response.body, []byte("These pull requests share one commit SHA")) {
		t.Fatal("unique-head role-boundary thaw unexpectedly requested shared-head confirmation")
	}
	if response.statusCode != http.StatusSeeOther || response.location != "/decisions?notice=thaw-approved" {
		t.Fatalf("Thaw approver unique-head thaw returned HTTP %d with Location %q, want 303 to /decisions?notice=thaw-approved", response.statusCode, response.location)
	}
	waitForStatusWithDescription(t, ctx, forgejo, uniqueHeadSHA, "success", explicitThawDescription)
	afterAllowedThaw := collectRoleBoundaryEvidence(t, ctx, forgejo, allRoleBrowser, repositoryID, uniqueHeadSHA, []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason}, []string{uniqueHeadSHA, fixture.sharedHeadSHA, fixture.releaseHeadSHA})
	if afterAllowedThaw.sideEffects.webhookRows != beforeAllowedThaw.sideEffects.webhookRows ||
		afterAllowedThaw.sideEffects.statusResults != beforeAllowedThaw.sideEffects.statusResults+1 ||
		afterAllowedThaw.sideEffects.publicationIntents != beforeAllowedThaw.sideEffects.publicationIntents ||
		afterAllowedThaw.sideEffects.publicationAttempts != beforeAllowedThaw.sideEffects.publicationAttempts+1 ||
		afterAllowedThaw.sideEffects.activityEvents != beforeAllowedThaw.sideEffects.activityEvents+2 ||
		len(afterAllowedThaw.statusHistories[0]) != len(beforeAllowedThaw.statusHistories[0])+1 {
		t.Fatalf("allowed role-boundary thaw had unexpected deltas: webhooks %d→%d results %d→%d intents %d→%d attempts %d→%d activity %d→%d statuses %d→%d",
			beforeAllowedThaw.sideEffects.webhookRows, afterAllowedThaw.sideEffects.webhookRows,
			beforeAllowedThaw.sideEffects.statusResults, afterAllowedThaw.sideEffects.statusResults,
			beforeAllowedThaw.sideEffects.publicationIntents, afterAllowedThaw.sideEffects.publicationIntents,
			beforeAllowedThaw.sideEffects.publicationAttempts, afterAllowedThaw.sideEffects.publicationAttempts,
			beforeAllowedThaw.sideEffects.activityEvents, afterAllowedThaw.sideEffects.activityEvents,
			len(beforeAllowedThaw.statusHistories[0]), len(afterAllowedThaw.statusHistories[0]))
	}
	if !slices.Equal(afterAllowedThaw.statusHistories[0][:len(beforeAllowedThaw.statusHistories[0])], beforeAllowedThaw.statusHistories[0]) {
		t.Fatal("allowed role-boundary thaw rewrote the new-head failure history")
	}
	allowedThawStatus := afterAllowedThaw.statusHistories[0][len(afterAllowedThaw.statusHistories[0])-1]
	if allowedThawStatus.ID <= uniqueFailure.ID || allowedThawStatus.Context != requiredContext || allowedThawStatus.Status != "success" || allowedThawStatus.Description != explicitThawDescription {
		t.Fatalf("allowed role-boundary thaw has unexpected Forgejo status: before=%+v after=%+v", uniqueFailure, allowedThawStatus)
	}
	if !slices.Equal(afterAllowedThaw.statusHistories[1], sharedStatusesAfterAdvance) || !slices.Equal(afterAllowedThaw.statusHistories[2], releaseStatusesBeforeRoles) {
		t.Fatal("allowed unique-head thaw changed the secondary shared head or merged release status history")
	}
	activityAfterAllowedThaw := requireAllActivityPages(t, ctx, allRoleBrowser)
	if countOpenPullRequestSyncEvents(activityAfterAllowedThaw) != openSyncsBeforeThaw+1 {
		t.Fatal("allowed role-boundary thaw did not add exactly one open-PR sync activity")
	}
	requireLatestOpenPullRequestSync(t, activityAfterAllowedThaw, 2)
	allowedThawActivity := requireLatestActivityRow(t, activityAfterAllowedThaw, "Single-PR thaw")
	requireRoleBoundaryActivity(t, allowedThawActivity, "E2E Thaw Approver", "Single-PR thaw", fixtureOwner+"/"+fixtureRepository+" → PR #"+strconv.Itoa(fixture.primaryPullRequestIndex), "Approved", "Branch main; head "+strings.ToLower(uniqueHeadSHA[:12])+". Reason: "+roleThawReason+".")
	allowedDecision := requireDecisionResultRowForHead(t, requirePage(t, ctx, allRoleBrowser, "/decisions"), uniqueHeadSHA)
	for _, want := range []string{`>#` + strconv.Itoa(fixture.primaryPullRequestIndex) + `</code>`, `title="` + uniqueHeadSHA + `"`, `>Eligible</span>`, explicitThawDescription} {
		if !strings.Contains(allowedDecision, want) {
			t.Fatalf("allowed role-boundary thaw decision is missing %q", want)
		}
	}
	allowedIntent := requirePublicationIntentRowForHead(t, requirePage(t, ctx, allRoleBrowser, "/publications"), uniqueHeadSHA)
	allowedAttempt := requirePublicationAttemptRowForHead(t, requirePage(t, ctx, allRoleBrowser, "/publications"), uniqueHeadSHA)
	for label, row := range map[string]string{"intent": allowedIntent, "attempt": allowedAttempt} {
		for _, want := range []string{uniqueHeadSHA, requiredContext, "success", "forgejo_status", explicitThawDescription} {
			if !strings.Contains(row, want) {
				t.Fatalf("allowed role-boundary thaw %s evidence is missing %q", label, want)
			}
		}
	}
	if strings.Contains(requirePage(t, ctx, thawApproverSession.browser, "/decisions"), "These pull requests share one commit SHA") {
		t.Fatal("unique-head role-boundary thaw rendered shared-head confirmation after approval")
	}

	finalFreezes := requirePage(t, ctx, allRoleBrowser, "/freezes")
	requireActiveFreezeCount(t, finalFreezes, 1)
	finalMainFreeze, _ := requireActiveFreezeEvidenceForBranch(t, finalFreezes, "main")
	if finalMainFreeze != mainFreeze {
		t.Fatalf("role-boundary slice changed the retained main freeze: before=%+v after=%+v", mainFreeze, finalMainFreeze)
	}
	requireNoActiveFreezeForBranch(t, finalFreezes, activeReleaseFreeze)
	finalSchedules := requirePage(t, ctx, allRoleBrowser, "/scheduled-freezes")
	finalScheduleA := requireScheduledFreezeRow(t, finalSchedules, 0, completedScheduleA.reason)
	finalScheduleB := requireScheduledFreezeRow(t, finalSchedules, 0, cancelledScheduleB.reason)
	finalScheduleC := requireScheduledFreezeRow(t, finalSchedules, 0, scheduleCEditedReason)
	requireSameScheduleEvidence(t, completedScheduleA, finalScheduleA, "final role-boundary state changed completed Schedule A")
	requireSameScheduleEvidence(t, cancelledScheduleB, finalScheduleB, "final role-boundary state changed cancelled Schedule B")
	requireSameScheduleEvidence(t, cancelledScheduleC, finalScheduleC, "final role-boundary state changed cancelled Schedule C")
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.primaryPullRequestIndex, "main", fixturePrimaryPRTitle, uniqueHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.sharedHeadPullRequestIndex, "main", fixtureSharedHeadPRTitle, fixture.sharedHeadSHA)
	requireMergedForgejoPullRequest(t, ctx, forgejo, fixture.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, fixture.releaseHeadSHA)
	requireHealthyActiveRepository(t, requirePage(t, ctx, allRoleBrowser, "/repositories"))
	finalActivity := requireAllActivityPages(t, ctx, allRoleBrowser)
	for label, retained := range map[string]string{
		"historical single-PR thaw": fixture.historicalSinglePRThawActivity,
		"shared-head thaw":          sharedThawHistory,
		"planned unfreeze":          plannedUnfreezeHistory,
		"Schedule C creation":       scheduleCCreatedActivity,
		"Schedule C edit":           scheduleCEditedActivity,
		"Schedule C Start Now":      scheduleCStartedActivity,
		"Schedule C cancellation":   scheduleCCancelledActivity,
		"role-boundary thaw":        allowedThawActivity,
	} {
		if !strings.Contains(finalActivity, retained) {
			t.Fatalf("final activity did not retain %s evidence", label)
		}
	}
	finalDecisions := requirePage(t, ctx, allRoleBrowser, "/decisions")
	if !strings.Contains(finalDecisions, fixture.historicalEligibleDecisionRow) || !strings.Contains(finalDecisions, allowedDecision) {
		t.Fatal("final decisions did not retain historical and role-boundary thaw evidence")
	}
	historicalThawedStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, fixture.historicalThawedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(historicalThawedStatuses, fixture.historicalThawedHeadStatuses) {
		t.Fatal("role-boundary slice changed the historical unique-head thaw status history")
	}
	finalWebhookPage := requirePage(t, ctx, allRoleBrowser, "/webhooks")
	if !strings.Contains(finalWebhookPage, terminalReleaseDelivery) || countPullRequestDeliveryActions(finalWebhookPage, "synchronized") != countPullRequestDeliveryActions(beforeUniqueHead.sideEffects.webhookPage, "synchronized")+1 {
		t.Fatal("final webhook evidence did not retain the release close and exactly one role-boundary synchronized delivery")
	}

	for _, session := range roleSessions {
		scanRenderedTokenSurfaces(t, ctx, session.browser)
	}
	_ = requirePage(t, ctx, adminSession.browser, "/users")
	requireRoleSessionsIsolated(t, ctx, append([]roleBoundarySession{allRoleSession}, roleSessions...))
	t.Logf("role-boundary slice passed in %s: four isolated single-role sessions, Schedule C lifecycle, and unique-head thaw", time.Since(sliceStartedAt).Round(time.Millisecond))
	return terminalDiagnosticsFixture{
		uniqueHeadSHA:       uniqueHeadSHA,
		roleSessions:        append([]roleBoundarySession{allRoleSession}, roleSessions...),
		scheduleReasons:     []string{completedScheduleA.reason, cancelledScheduleB.reason, scheduleCEditedReason},
		expectedSideEffects: afterAllowedThaw.sideEffects,
		activity: terminalActivityEvidence{
			sharedHeadThaw:     sharedThawHistory,
			plannedUnfreeze:    plannedUnfreezeHistory,
			scheduleCCreated:   scheduleCCreatedActivity,
			scheduleCEdited:    scheduleCEditedActivity,
			scheduleCStarted:   scheduleCStartedActivity,
			scheduleCCancelled: scheduleCCancelledActivity,
			roleBoundaryThaw:   allowedThawActivity,
		},
		allowedDecision:         allowedDecision,
		terminalReleaseDelivery: terminalReleaseDelivery,
		roleBoundaryDelivery:    roleBoundaryDelivery,
	}
}

func proveAuditAndDiagnosticsEvidence(t *testing.T, ctx context.Context, forgejo *forgejoAPI, cfg e2eConfig, repositoryID int64, lifecycle scheduledFreezeLifecycleFixture, fixture terminalDiagnosticsFixture) {
	t.Helper()
	const (
		frozenDescription       = "Branch is frozen; merge is blocked by Thawguard"
		noFreezeDescription     = "No active freeze applies to this PR"
		explicitThawDescription = "PR is explicitly thawed during an active freeze"
		statusDiagnosticLimit   = 25
	)
	sliceStartedAt := time.Now().UTC()
	if len(fixture.uniqueHeadSHA) < 12 || len(fixture.roleSessions) != 5 || len(fixture.scheduleReasons) != 3 || fixture.expectedSideEffects.webhookRows <= 0 {
		t.Fatalf("terminal diagnostics proof received an incomplete fixture: unique head length=%d sessions=%d schedules=%d webhooks=%d", len(fixture.uniqueHeadSHA), len(fixture.roleSessions), len(fixture.scheduleReasons), fixture.expectedSideEffects.webhookRows)
	}

	before := collectTerminalReadOnlySnapshot(t, ctx, forgejo, repositoryID, lifecycle, fixture)
	if before.evidence.userCount != 5 || before.evidence.repositoryCount != 1 || before.evidence.activeFreezes != 1 || before.evidence.scheduledCount != 3 {
		t.Fatalf("terminal diagnostics baseline has unexpected durable counts: users=%d repositories=%d active=%d schedules=%d", before.evidence.userCount, before.evidence.repositoryCount, before.evidence.activeFreezes, before.evidence.scheduledCount)
	}
	if before.evidence.mainFreeze != lifecycle.activeMainFreeze {
		t.Fatalf("terminal diagnostics baseline changed the retained main freeze: lifecycle=%+v terminal=%+v", lifecycle.activeMainFreeze, before.evidence.mainFreeze)
	}
	requireIdenticalWebhookEvidence(t, fixture.expectedSideEffects, before.evidence.sideEffects, "terminal diagnostics baseline")
	if fixture.expectedSideEffects.webhookPage != before.evidence.sideEffects.webhookPage {
		t.Fatal("terminal diagnostics baseline changed the complete retained webhook snapshot")
	}
	if !slices.Equal(fixture.roleSessions, before.roleSessions) {
		t.Fatal("terminal diagnostics baseline changed role-session identity")
	}

	activityPage := requireAllActivityPages(t, ctx, fixture.roleSessions[0].browser)
	activityCount := requirePageCount(t, activityPage, activityEventsPattern, "activity events")
	if activityCount != before.evidence.sideEffects.activityEvents || activityCount <= 0 || activityCount >= 100 {
		t.Fatalf("terminal activity count=%d, want persisted count %d in the untruncated range 1..99", activityCount, before.evidence.sideEffects.activityEvents)
	}
	repositoryAdded := requireActivityRowEvidence(t, activityPage, "E2E Admin", "Repository added", fixtureOwner+"/"+fixtureRepository, "Added", "Default branch main.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Webhook secret configuration", fixtureOwner+"/"+fixtureRepository, "Configured", "Webhook secret set; the value remains hidden.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Status token configuration", fixtureOwner+"/"+fixtureRepository, "Configured", "Status token set; the value remains hidden.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Readiness check", fixtureOwner+"/"+fixtureRepository, "Checked", "11 passed, 1 warnings, 0 failed across 2 managed branches; webhook evidence fresh.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Status-post verification", fixtureOwner+"/"+fixtureRepository+" → main", "Succeeded", "Controlled thawguard/setup post verified at head ")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Enforcement activation", fixtureOwner+"/"+fixtureRepository, "Succeeded", "1 open PRs evaluated; 1 statuses posted and 0 failed.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Enforcement reconciliation", fixtureOwner+"/"+fixtureRepository, "Failed", "readiness checks failed; state unhealthy.")
	requireActivityRowEvidence(t, activityPage, "Runtime process", "Runtime convergence", fixtureOwner+"/"+fixtureRepository, "Failed", "status publication failed; state unhealthy. Automatic recovery remains pending.")
	requireActivityRowEvidence(t, activityPage, "Reconciliation runner", "Enforcement recovery", fixtureOwner+"/"+fixtureRepository, "Succeeded", "1 open PRs evaluated; 1 statuses posted and 0 failed.")
	requireActivityRowEvidence(t, activityPage, "Unknown system actor", "Open pull request sync", fixtureOwner+"/"+fixtureRepository+" → all managed branches", "Succeeded", "3 open PRs synchronized; 0 cached PRs marked closed.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Branch freeze", fixtureOwner+"/"+fixtureRepository+" → main", "Frozen", "Reason: Fictional release verification.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Branch freeze", fixtureOwner+"/"+fixtureRepository+" → main", "Lifted", "Reason: Fictional release verification.")
	requireActivityRowEvidence(t, activityPage, "E2E Admin", "Branch freeze", fixtureOwner+"/"+fixtureRepository+" → main", "Cancelled", "Reason: Fictional cancellation verification..")

	requireRoleBoundaryActivity(t, lifecycle.historicalSinglePRThawActivity, "E2E Admin", "Single-PR thaw", fixtureOwner+"/"+fixtureRepository+" → PR #"+strconv.Itoa(lifecycle.primaryPullRequestIndex), "Approved", "Branch main; head "+lifecycle.historicalThawedHeadSHA[:12]+". Reason: Fictional immediate per-PR thaw verification.")
	requireRoleBoundaryActivity(t, fixture.activity.sharedHeadThaw, "E2E Admin", "Shared-head thaw", fixtureOwner+"/"+fixtureRepository+" → shared head "+lifecycle.sharedHeadSHA[:12], "Approved", "New exceptions: #"+strconv.Itoa(lifecycle.primaryPullRequestIndex)+", #"+strconv.Itoa(lifecycle.sharedHeadPullRequestIndex), "Confirmation reason: Fictional shared-head thaw confirmation.")
	requireRoleBoundaryActivity(t, fixture.activity.plannedUnfreeze, "Scheduler", "Scheduled planned unfreeze", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Completed", "Planned unfreeze "+scheduleTime(lifecycle.plannedEndsAt)+". Reason: "+lifecycle.activeScheduleA.reason+".")
	requireRoleBoundaryActivity(t, fixture.activity.scheduleCCreated, "E2E Freezer", "Freeze schedule", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Scheduled", "Fictional role-boundary Schedule C")
	requireRoleBoundaryActivity(t, fixture.activity.scheduleCEdited, "E2E Admin Only", "Freeze schedule", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Changed", "Reason Fictional role-boundary Schedule C → Fictional role-boundary Schedule C edited")
	requireRoleBoundaryActivity(t, fixture.activity.scheduleCStarted, "E2E Admin Only", "Scheduled freeze Start Now", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Started", "Fictional role-boundary Schedule C edited")
	requireRoleBoundaryActivity(t, fixture.activity.scheduleCCancelled, "E2E Freezer", "Branch freeze", fixtureOwner+"/"+fixtureRepository+" → "+fixtureReleaseBranch, "Cancelled", "Reason: Fictional role-boundary Schedule C edited.")
	requireRoleBoundaryActivity(t, fixture.activity.roleBoundaryThaw, "E2E Thaw Approver", "Single-PR thaw", fixtureOwner+"/"+fixtureRepository+" → PR #"+strconv.Itoa(lifecycle.primaryPullRequestIndex), "Approved", "Branch main; head "+fixture.uniqueHeadSHA[:12]+". Reason: Fictional role-boundary unique-head thaw.")
	for _, retained := range []struct {
		label string
		row   string
	}{
		{label: "historical single-PR thaw", row: lifecycle.historicalSinglePRThawActivity},
		{label: "shared-head thaw", row: fixture.activity.sharedHeadThaw},
		{label: "planned unfreeze", row: fixture.activity.plannedUnfreeze},
		{label: "Schedule C creation", row: fixture.activity.scheduleCCreated},
		{label: "Schedule C edit", row: fixture.activity.scheduleCEdited},
		{label: "Schedule C Start Now", row: fixture.activity.scheduleCStarted},
		{label: "Schedule C cancellation", row: fixture.activity.scheduleCCancelled},
		{label: "role-boundary thaw", row: fixture.activity.roleBoundaryThaw},
	} {
		if retained.row == "" || !strings.Contains(activityPage, retained.row) {
			t.Fatalf("terminal activity did not retain exact %s evidence", retained.label)
		}
	}
	if strings.Index(activityPage, fixture.activity.roleBoundaryThaw) >= strings.Index(activityPage, repositoryAdded) {
		t.Fatal("terminal activity is not newest-first: role-boundary evidence did not precede repository setup evidence")
	}
	for _, forbidden := range []string{"repository.runtime_convergence_failed", "actor_kind", "actor_role", "repository_id", "Unrecognized activity", "Stored audit details could not be displayed safely."} {
		if strings.Contains(activityPage, forbidden) {
			t.Fatalf("terminal activity exposed internal or uncurated audit material category %q", forbidden)
		}
	}

	publicationsPage := requirePage(t, ctx, fixture.roleSessions[0].browser, "/publications")
	decisionsPage := requirePage(t, ctx, fixture.roleSessions[0].browser, "/decisions")
	statusResults := requirePageCount(t, decisionsPage, statusResultsPattern, "status results")
	publicationIntents := requirePageCount(t, publicationsPage, publicationIntentsPattern, "publication intents")
	publicationAttempts := requirePageCount(t, publicationsPage, publicationAttemptsPattern, "publication attempts")
	if statusResults != before.evidence.sideEffects.statusResults || publicationIntents != before.evidence.sideEffects.publicationIntents || publicationAttempts != before.evidence.sideEffects.publicationAttempts {
		t.Fatalf("terminal status diagnostics do not match persisted counters: results=%d/%d intents=%d/%d attempts=%d/%d", statusResults, before.evidence.sideEffects.statusResults, publicationIntents, before.evidence.sideEffects.publicationIntents, publicationAttempts, before.evidence.sideEffects.publicationAttempts)
	}
	if statusResults <= 0 || publicationIntents <= 0 || publicationAttempts <= 0 || statusResults >= statusDiagnosticLimit || publicationIntents >= statusDiagnosticLimit || publicationAttempts >= statusDiagnosticLimit {
		t.Fatalf("terminal status diagnostics reached a presentation boundary: results=%d intents=%d attempts=%d limit=%d", statusResults, publicationIntents, publicationAttempts, statusDiagnosticLimit)
	}
	for label, row := range map[string]string{
		"historical Eligible decision":    lifecycle.historicalEligibleDecisionRow,
		"role-boundary Eligible decision": fixture.allowedDecision,
	} {
		if row == "" || !strings.Contains(decisionsPage, row) {
			t.Fatalf("terminal decisions did not retain exact %s", label)
		}
	}

	tokenAttempts := requireDiagnosticRowsForHead(t, publicationsPage, `aria-label="Recent publication attempts"`, lifecycle.historicalThawedHeadSHA)
	tokenFailureIndex := diagnosticRowIndex(tokenAttempts,
		`>failure · forgejo_status</code>`,
		`>failed</span>`,
		frozenDescription,
		"post forgejo commit status",
		"forge returned 401",
	)
	tokenRecoveryIndex := diagnosticRowIndex(tokenAttempts,
		`>failure · forgejo_status</code>`,
		`>posted</span>`,
		frozenDescription,
	)
	tokenCurrentIndex := diagnosticRowIndex(tokenAttempts,
		`>success · forgejo_status</code>`,
		`>posted</span>`,
		explicitThawDescription,
	)
	if tokenFailureIndex < 0 || tokenRecoveryIndex < 0 || tokenCurrentIndex < 0 || tokenRecoveryIndex >= tokenFailureIndex || tokenCurrentIndex >= tokenFailureIndex {
		t.Fatalf("token-loss attempt history is incomplete or out of append-only order: failure=%d recovery=%d current=%d rows=%d", tokenFailureIndex, tokenRecoveryIndex, tokenCurrentIndex, len(tokenAttempts))
	}
	tokenIntent := requirePublicationIntentRowForHead(t, publicationsPage, lifecycle.historicalThawedHeadSHA)
	requireDiagnosticRowContains(t, tokenIntent, "token-loss current desired status",
		fixtureOwner+"/"+fixtureRepository,
		`PR #`+strconv.Itoa(lifecycle.primaryPullRequestIndex)+` · main`,
		`title="`+lifecycle.historicalThawedHeadSHA+`"`,
		`>`+requiredContext+`</code>`,
		`>success</span>`,
		`>forgejo_status</code>`,
		explicitThawDescription,
	)

	releaseAttempts := requireDiagnosticRowsForHead(t, publicationsPage, `aria-label="Recent publication attempts"`, lifecycle.releaseHeadSHA)
	if len(releaseAttempts) != 3 {
		t.Fatalf("release head has %d retained publication attempts, want eligible/frozen/eligible", len(releaseAttempts))
	}
	requireStatusAttemptEvidence(t, releaseAttempts[2], lifecycle.releasePullRequestIndex, fixtureReleaseBranch, lifecycle.releaseHeadSHA, "success", "posted", noFreezeDescription)
	requireStatusAttemptEvidence(t, releaseAttempts[1], lifecycle.releasePullRequestIndex, fixtureReleaseBranch, lifecycle.releaseHeadSHA, "failure", "posted", frozenDescription)
	requireStatusAttemptEvidence(t, releaseAttempts[0], lifecycle.releasePullRequestIndex, fixtureReleaseBranch, lifecycle.releaseHeadSHA, "success", "posted", noFreezeDescription)
	releaseIntent := requirePublicationIntentRowForHead(t, publicationsPage, lifecycle.releaseHeadSHA)
	requireCurrentStatusIntentEvidence(t, releaseIntent, lifecycle.releasePullRequestIndex, fixtureReleaseBranch, lifecycle.releaseHeadSHA, "success", noFreezeDescription)
	requireCommitStatusProgression(t, before.evidence.statusHistories[2], []string{"success", "failure", "success"}, []string{noFreezeDescription, frozenDescription, noFreezeDescription}, "release")

	if !strings.Contains(decisionsPage, `>`+requiredContext+`</code>`) {
		t.Fatal("terminal decisions page does not state the required status context")
	}
	roleDecisions := requireDiagnosticRowsForHead(t, decisionsPage, `aria-label="Freeze decisions"`, fixture.uniqueHeadSHA)
	if len(roleDecisions) != 2 {
		t.Fatalf("role-boundary unique head has %d decision rows, want frozen then Eligible", len(roleDecisions))
	}
	roleEligibleIndex := diagnosticRowIndex(roleDecisions, `>Eligible</span>`, explicitThawDescription)
	roleBlockedIndex := diagnosticRowIndex(roleDecisions, `>Blocked</span>`, frozenDescription)
	if roleEligibleIndex < 0 || roleBlockedIndex < 0 || roleEligibleIndex >= roleBlockedIndex {
		t.Fatalf("role-boundary decision chronology is incomplete: Eligible=%d Blocked=%d", roleEligibleIndex, roleBlockedIndex)
	}
	for label, row := range map[string]string{"Eligible decision": roleDecisions[roleEligibleIndex], "Blocked decision": roleDecisions[roleBlockedIndex]} {
		requireDiagnosticRowContains(t, row, "role-boundary "+label,
			`>#`+strconv.Itoa(lifecycle.primaryPullRequestIndex)+`</code>`,
			fixtureOwner+`/`+fixtureRepository,
			`>main</code>`,
			`title="`+fixture.uniqueHeadSHA+`"`,
		)
	}
	roleAttempts := requireDiagnosticRowsForHead(t, publicationsPage, `aria-label="Recent publication attempts"`, fixture.uniqueHeadSHA)
	if len(roleAttempts) != 2 {
		t.Fatalf("role-boundary unique head has %d publication attempts, want failure then success", len(roleAttempts))
	}
	requireStatusAttemptEvidence(t, roleAttempts[1], lifecycle.primaryPullRequestIndex, "main", fixture.uniqueHeadSHA, "failure", "posted", frozenDescription)
	requireStatusAttemptEvidence(t, roleAttempts[0], lifecycle.primaryPullRequestIndex, "main", fixture.uniqueHeadSHA, "success", "posted", explicitThawDescription)
	roleIntent := requirePublicationIntentRowForHead(t, publicationsPage, fixture.uniqueHeadSHA)
	requireCurrentStatusIntentEvidence(t, roleIntent, lifecycle.primaryPullRequestIndex, "main", fixture.uniqueHeadSHA, "success", explicitThawDescription)
	requireCommitStatusProgression(t, before.evidence.statusHistories[0], []string{"failure", "success"}, []string{frozenDescription, explicitThawDescription}, "role-boundary")

	unfilteredWebhookPage := before.evidence.sideEffects.webhookPage
	unfilteredSummary := requireWebhookPageSummary(t, unfilteredWebhookPage)
	if unfilteredSummary.showing != before.evidence.sideEffects.webhookRows || unfilteredSummary.total != unfilteredSummary.showing || unfilteredSummary.showing <= 0 || unfilteredSummary.showing >= 20 {
		t.Fatalf("unfiltered webhook summary is not complete on one page: showing=%d total=%d expected=%d", unfilteredSummary.showing, unfilteredSummary.total, before.evidence.sideEffects.webhookRows)
	}
	for _, action := range []string{"opened", "synchronized", "closed"} {
		if countPullRequestDeliveryActions(unfilteredWebhookPage, action) <= 0 {
			t.Fatalf("unfiltered webhook diagnostics did not retain a processed %s delivery", action)
		}
	}
	requireProcessedWebhookRowEvidence(t, fixture.terminalReleaseDelivery, "closed")
	requireProcessedWebhookRowEvidence(t, fixture.roleBoundaryDelivery, "synchronized")
	if !strings.Contains(unfilteredWebhookPage, fixture.terminalReleaseDelivery) || !strings.Contains(unfilteredWebhookPage, fixture.roleBoundaryDelivery) {
		t.Fatal("unfiltered webhook diagnostics did not retain exact terminal closed and role-boundary synchronized rows")
	}
	duplicateRow := requireProcessedVerifiedDelivery(t, unfilteredWebhookPage, duplicateDeliveryID)
	if countWebhookDesktopRowsContaining(t, unfilteredWebhookPage, html.EscapeString(duplicateDeliveryID)) != 1 {
		t.Fatal("fixed duplicate delivery is not represented by exactly one persisted webhook row")
	}
	if strings.Contains(unfilteredWebhookPage, invalidDeliveryID) {
		t.Fatal("invalid-signature delivery unexpectedly appears in terminal webhook diagnostics")
	}

	processedPath := "/webhooks?" + url.Values{
		"repo":       {strconv.FormatInt(repositoryID, 10)},
		"processing": {"processed"},
		"sort":       {"received"},
		"dir":        {"asc"},
	}.Encode()
	processedPage := requirePage(t, ctx, fixture.roleSessions[0].browser, processedPath)
	requireWebhookFilterControls(t, processedPage, repositoryID, "processed", "received", "asc")
	processedSummary := requireWebhookPageSummary(t, processedPage)
	if processedSummary.showing != processedSummary.total || processedSummary.total != unfilteredSummary.total-1 {
		t.Fatalf("processed webhook filter has untruthful counts: showing=%d total=%d unfiltered=%d", processedSummary.showing, processedSummary.total, unfilteredSummary.total)
	}
	for _, action := range []string{"opened", "synchronized", "closed"} {
		if countPullRequestDeliveryActions(processedPage, action) <= 0 {
			t.Fatalf("processed webhook filter did not retain %s evidence", action)
		}
	}
	if !strings.Contains(processedPage, duplicateRow) || !strings.Contains(processedPage, fixture.terminalReleaseDelivery) || !strings.Contains(processedPage, fixture.roleBoundaryDelivery) || strings.Contains(processedPage, ">Retryable failure</span>") {
		t.Fatal("processed webhook filter did not separate retained processed rows from retryable failure evidence")
	}

	retryPath := "/webhooks?" + url.Values{
		"repo":       {strconv.FormatInt(repositoryID, 10)},
		"processing": {"retryable_failure"},
		"sort":       {"received"},
		"dir":        {"asc"},
	}.Encode()
	retryablePage := requirePage(t, ctx, fixture.roleSessions[0].browser, retryPath)
	requireWebhookFilterControls(t, retryablePage, repositoryID, "retryable_failure", "received", "asc")
	retryableSummary := requireWebhookPageSummary(t, retryablePage)
	if retryableSummary.showing != 1 || retryableSummary.total != 1 || processedSummary.total+retryableSummary.total != unfilteredSummary.total {
		t.Fatalf("retryable-failure webhook filter has unexpected counts: showing=%d total=%d processed=%d unfiltered=%d", retryableSummary.showing, retryableSummary.total, processedSummary.total, unfilteredSummary.total)
	}
	retryableRow := requireLatestWebhookDeliveryRow(t, retryablePage)
	for _, want := range []string{
		`>pull_request · synchronized</span>`,
		`>Verified</span>`,
		`>Retryable failure</span>`,
		`>webhook processing failed</span>`,
	} {
		if !strings.Contains(retryableRow, want) {
			t.Fatalf("retryable-failure webhook evidence is missing %q", want)
		}
	}
	if strings.Contains(retryablePage, duplicateRow) || strings.Contains(retryablePage, fixture.terminalReleaseDelivery) || strings.Contains(retryablePage, fixture.roleBoundaryDelivery) || strings.Contains(retryablePage, `>Processed</span>`) {
		t.Fatal("retryable-failure webhook filter retained processed-only delivery evidence")
	}

	processedDescendingPath := "/webhooks?" + url.Values{
		"repo":       {strconv.FormatInt(repositoryID, 10)},
		"processing": {"processed"},
		"sort":       {"received"},
		"dir":        {"desc"},
	}.Encode()
	processedDescendingPage := requirePage(t, ctx, fixture.roleSessions[0].browser, processedDescendingPath)
	requireWebhookFilterControls(t, processedDescendingPage, repositoryID, "processed", "received", "desc")
	ascendingDuplicate := strings.Index(processedPage, duplicateRow)
	ascendingClosed := strings.Index(processedPage, fixture.terminalReleaseDelivery)
	descendingDuplicate := strings.Index(processedDescendingPage, duplicateRow)
	descendingClosed := strings.Index(processedDescendingPage, fixture.terminalReleaseDelivery)
	if ascendingDuplicate < 0 || ascendingClosed < 0 || descendingDuplicate < 0 || descendingClosed < 0 || ascendingDuplicate >= ascendingClosed || descendingClosed >= descendingDuplicate {
		t.Fatalf("received-time sorting did not reverse fixed duplicate and terminal closed deliveries: asc duplicate=%d closed=%d desc duplicate=%d closed=%d", ascendingDuplicate, ascendingClosed, descendingDuplicate, descendingClosed)
	}

	payload := syntheticPullRequestWebhookPayload(t, cfg, lifecycle.primaryPullRequestIndex, lifecycle.historicalThawedHeadSHA)
	signature := syntheticWebhookSignature(payload, cfg.webhookSecret)
	requireNoRawDiagnosticMaterial(t, cfg, payload, signature, []struct {
		label string
		page  string
	}{
		{label: "activity", page: activityPage},
		{label: "status diagnostics", page: publicationsPage},
		{label: "decisions", page: decisionsPage},
		{label: "unfiltered webhooks", page: unfilteredWebhookPage},
		{label: "processed webhooks", page: processedPage},
		{label: "processed descending webhooks", page: processedDescendingPage},
		{label: "retryable webhooks", page: retryablePage},
	})

	after := collectTerminalReadOnlySnapshot(t, ctx, forgejo, repositoryID, lifecycle, fixture)
	requireUnchangedTerminalReadOnlySnapshot(t, before, after)
	t.Logf("terminal audit/diagnostics slice passed in %s: activity=%d, status results=%d, desired intents=%d, attempts=%d, webhooks=%d total/%d processed/%d retryable", time.Since(sliceStartedAt).Round(time.Millisecond), activityCount, statusResults, publicationIntents, publicationAttempts, unfilteredSummary.showing, processedSummary.showing, retryableSummary.showing)
}

func collectTerminalReadOnlySnapshot(t *testing.T, ctx context.Context, forgejo *forgejoAPI, repositoryID int64, lifecycle scheduledFreezeLifecycleFixture, fixture terminalDiagnosticsFixture) terminalReadOnlySnapshot {
	t.Helper()
	snapshot := terminalReadOnlySnapshot{
		evidence: collectRoleBoundaryEvidence(
			t,
			ctx,
			forgejo,
			fixture.roleSessions[0].browser,
			repositoryID,
			fixture.uniqueHeadSHA,
			fixture.scheduleReasons,
			[]string{fixture.uniqueHeadSHA, lifecycle.sharedHeadSHA, lifecycle.releaseHeadSHA, lifecycle.historicalThawedHeadSHA},
		),
		pullRequests: []pullRequest{
			requireOpenForgejoPullRequest(t, ctx, forgejo, lifecycle.primaryPullRequestIndex, "main", fixturePrimaryPRTitle, fixture.uniqueHeadSHA),
			requireOpenForgejoPullRequest(t, ctx, forgejo, lifecycle.sharedHeadPullRequestIndex, "main", fixtureSharedHeadPRTitle, lifecycle.sharedHeadSHA),
			requireMergedForgejoPullRequest(t, ctx, forgejo, lifecycle.releasePullRequestIndex, fixtureReleaseBranch, fixtureScheduledPRTitle, lifecycle.releaseHeadSHA),
		},
	}
	for _, session := range fixture.roleSessions {
		snapshot.roleSessions = append(snapshot.roleSessions, currentRoleBoundarySession(t, ctx, session.browser, session.email, session.displayName, session.roleLabel))
	}
	snapshot.diagnosticPages = [4]string{
		requireAllActivityPages(t, ctx, fixture.roleSessions[0].browser),
		requirePage(t, ctx, fixture.roleSessions[0].browser, "/decisions"),
		requirePage(t, ctx, fixture.roleSessions[0].browser, "/publications"),
		snapshot.evidence.sideEffects.webhookPage,
	}
	return snapshot
}

func requireUnchangedTerminalReadOnlySnapshot(t *testing.T, before, after terminalReadOnlySnapshot) {
	t.Helper()
	requireUnchangedRoleBoundaryEvidence(t, before.evidence, after.evidence, "terminal diagnostic reads and filter queries")
	if !slices.Equal(before.roleSessions, after.roleSessions) {
		t.Fatal("terminal diagnostic reads changed a user session or role identity")
	}
	if !slices.Equal(before.pullRequests, after.pullRequests) {
		t.Fatalf("terminal diagnostic reads changed final Forgejo PR states: before=%+v after=%+v", before.pullRequests, after.pullRequests)
	}
	if before.diagnosticPages != after.diagnosticPages {
		t.Fatal("terminal diagnostic reads rewrote rendered activity, decision, publication, or webhook evidence")
	}
}

func requireActivityRowEvidence(t *testing.T, page, actor, action, target, outcome string, details ...string) string {
	t.Helper()
	wants := []string{
		`>` + html.EscapeString(actor) + `</td>`,
		`<span class="font-medium text-text">` + html.EscapeString(action) + `</span>`,
		`>` + html.EscapeString(target) + `</td>`,
		`>` + html.EscapeString(outcome) + `</span>`,
	}
	for _, detail := range details {
		wants = append(wants, html.EscapeString(detail))
	}
	// A concatenated multi-page fetch repeats the recent-activity section once
	// per page, so scan every desktop table body rather than only the first.
	sections := 0
	for rest := page; ; {
		sectionStart := strings.Index(rest, `aria-label="Recent activity"`)
		if sectionStart < 0 {
			break
		}
		rest = rest[sectionStart:]
		tbodyOffset := strings.Index(rest, "<tbody>")
		if tbodyOffset < 0 {
			t.Fatal("recent activity is missing its desktop table body")
		}
		tbodyEndOffset := strings.Index(rest[tbodyOffset:], "</tbody>")
		if tbodyEndOffset < 0 {
			t.Fatal("recent activity has an incomplete desktop table body")
		}
		tbody := rest[tbodyOffset : tbodyOffset+tbodyEndOffset]
		sections++
		for remainder := tbody; ; {
			rowStart := strings.Index(remainder, "<tr ")
			if rowStart < 0 {
				break
			}
			rowEndOffset := strings.Index(remainder[rowStart:], "</tr>")
			if rowEndOffset < 0 {
				t.Fatal("recent activity contains an incomplete desktop row")
			}
			rowEnd := rowStart + rowEndOffset + len("</tr>")
			row := remainder[rowStart:rowEnd]
			matches := true
			for _, want := range wants {
				if !strings.Contains(row, want) {
					matches = false
					break
				}
			}
			if matches {
				return row
			}
			remainder = remainder[rowEnd:]
		}
		rest = rest[tbodyOffset+tbodyEndOffset:]
	}
	if sections == 0 {
		t.Fatal("activity page is missing recent activity")
	}
	t.Fatalf("activity is missing curated %s/%s evidence by %s", action, outcome, actor)
	return ""
}

func requireDiagnosticRowsForHead(t *testing.T, page, sectionMarker, headSHA string) []string {
	t.Helper()
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatalf("diagnostic page is missing section %q", sectionMarker)
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatalf("diagnostic section %q is missing its table body", sectionMarker)
	}
	tbodyStart := sectionStart + tbodyOffset
	tbodyEndOffset := strings.Index(page[tbodyStart:], "</tbody>")
	if tbodyEndOffset < 0 {
		t.Fatalf("diagnostic section %q has an incomplete table body", sectionMarker)
	}
	tbody := page[tbodyStart : tbodyStart+tbodyEndOffset]
	marker := `title="` + html.EscapeString(headSHA) + `"`
	var rows []string
	for remainder := tbody; ; {
		rowStart := strings.Index(remainder, "<tr ")
		if rowStart < 0 {
			break
		}
		rowEndOffset := strings.Index(remainder[rowStart:], "</tr>")
		if rowEndOffset < 0 {
			t.Fatalf("diagnostic section %q contains an incomplete row", sectionMarker)
		}
		rowEnd := rowStart + rowEndOffset + len("</tr>")
		row := remainder[rowStart:rowEnd]
		if strings.Contains(row, marker) {
			rows = append(rows, row)
		}
		remainder = remainder[rowEnd:]
	}
	if len(rows) == 0 {
		t.Fatalf("diagnostic section %q has no rows for head %q", sectionMarker, headSHA)
	}
	return rows
}

func diagnosticRowIndex(rows []string, wants ...string) int {
	for index, row := range rows {
		matches := true
		for _, want := range wants {
			if !strings.Contains(row, want) {
				matches = false
				break
			}
		}
		if matches {
			return index
		}
	}
	return -1
}

func requireDiagnosticRowContains(t *testing.T, row, label string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(row, want) {
			t.Fatalf("%s is missing %q", label, want)
		}
	}
}

func requireStatusAttemptEvidence(t *testing.T, row string, pullRequestIndex int, branch, headSHA, state, result, description string) {
	t.Helper()
	requireDiagnosticRowContains(t, row, "status publication attempt",
		fixtureOwner+"/"+fixtureRepository,
		`PR #`+strconv.Itoa(pullRequestIndex)+` · `+html.EscapeString(branch),
		`title="`+html.EscapeString(headSHA)+`"`,
		`>`+requiredContext+`</code>`,
		`>`+result+`</span>`,
		`>`+state+` · forgejo_status</code>`,
		html.EscapeString(description),
	)
}

func requireCurrentStatusIntentEvidence(t *testing.T, row string, pullRequestIndex int, branch, headSHA, state, description string) {
	t.Helper()
	requireDiagnosticRowContains(t, row, "current desired status",
		fixtureOwner+"/"+fixtureRepository,
		`PR #`+strconv.Itoa(pullRequestIndex)+` · `+html.EscapeString(branch),
		`title="`+html.EscapeString(headSHA)+`"`,
		`>`+requiredContext+`</code>`,
		`>`+state+`</span>`,
		`>forgejo_status</code>`,
		html.EscapeString(description),
	)
}

func requireCommitStatusProgression(t *testing.T, statuses []commitStatus, states, descriptions []string, label string) {
	t.Helper()
	if len(statuses) != len(states) || len(states) != len(descriptions) {
		t.Fatalf("%s Forgejo status history has %d entries, want %d", label, len(statuses), len(states))
	}
	for index, status := range statuses {
		if status.ID <= 0 || status.Context != requiredContext || status.Status != states[index] || status.Description != descriptions[index] {
			t.Fatalf("%s Forgejo status %d has unexpected correlated evidence: %+v", label, index, status)
		}
		if index > 0 && status.ID <= statuses[index-1].ID {
			t.Fatalf("%s Forgejo status IDs are not append-only: %d then %d", label, statuses[index-1].ID, status.ID)
		}
	}
}

func requireWebhookPageSummary(t *testing.T, page string) webhookPageSummary {
	t.Helper()
	match := deliveryCountPattern.FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatal("webhook diagnostics are missing the delivery-count badge")
	}
	total, err := strconv.Atoi(match[1])
	if err != nil {
		t.Fatalf("parse webhook delivery count: %v", err)
	}
	return webhookPageSummary{
		showing: countWebhookDesktopRowsContaining(t, page, "<tr "),
		total:   total,
	}
}

func requireProcessedWebhookRowEvidence(t *testing.T, row, action string) {
	t.Helper()
	for _, want := range []string{
		`>` + fixtureOwner + `/` + fixtureRepository + `</span>`,
		`>pull_request · ` + action + `</span>`,
		`>Verified</span>`,
		`>Processed</span>`,
		`>No processing error</span>`,
	} {
		if !strings.Contains(row, want) {
			t.Fatalf("processed %s webhook row is missing %q", action, want)
		}
	}
}

func countWebhookDesktopRowsContaining(t *testing.T, page, marker string) int {
	t.Helper()
	sectionStart := strings.Index(page, `aria-label="Signed webhook deliveries"`)
	if sectionStart < 0 {
		t.Fatal("webhook diagnostics are missing signed deliveries")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("signed webhook deliveries are missing their desktop table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	tbodyEndOffset := strings.Index(page[tbodyStart:], "</tbody>")
	if tbodyEndOffset < 0 {
		t.Fatal("signed webhook deliveries have an incomplete desktop table body")
	}
	return strings.Count(page[tbodyStart:tbodyStart+tbodyEndOffset], marker)
}

func requireWebhookFilterControls(t *testing.T, page string, repositoryID int64, processing, sortField, direction string) {
	t.Helper()
	ariaSort := "descending"
	if direction == "asc" {
		ariaSort = "ascending"
	}
	chipLabels := map[string]string{
		"received":             "Received",
		"processing":           "Processing",
		"processed":            "Processed",
		"processed_with_error": "Processed with error",
		"retryable_failure":    "Retryable failure",
	}
	chipLabel, known := chipLabels[processing]
	if !known {
		t.Fatalf("unknown webhook processing filter %q", processing)
	}
	wants := []string{
		`<option value="` + strconv.FormatInt(repositoryID, 10) + `" selected>` + fixtureOwner + `/` + fixtureRepository + `</option>`,
		`<input type="hidden" name="processing" value="` + processing + `">`,
		`aria-current="true">` + chipLabel + `</a>`,
		`aria-sort="` + ariaSort + `"`,
	}
	if sortField == "processed" {
		wants = append(wants, `<input type="hidden" name="sort" value="processed">`)
	}
	if direction == "asc" {
		wants = append(wants, `<input type="hidden" name="dir" value="asc">`)
	}
	for _, want := range wants {
		if !strings.Contains(page, want) {
			t.Fatalf("webhook filter controls are missing selected evidence %q", want)
		}
	}
}

func requireNoRawDiagnosticMaterial(t *testing.T, cfg e2eConfig, payload []byte, signature string, pages []struct {
	label string
	page  string
}) {
	t.Helper()
	for _, surface := range pages {
		for _, secret := range cfg.sensitiveValues() {
			if secret != "" && strings.Contains(surface.page, secret) {
				t.Fatalf("%s diagnostics exposed a generated sensitive value", surface.label)
			}
		}
		for category, forbidden := range map[string]string{
			"raw payload":                  string(payload),
			"HTML-escaped raw payload":     html.EscapeString(string(payload)),
			"computed webhook signature":   signature,
			"Forgejo signature header":     "X-Forgejo-Signature",
			"Hub signature header":         "X-Hub-Signature",
			"invalid-signature secret":     invalidSignatureSecret,
			"raw payload clone URL marker": "clone_url",
		} {
			if forbidden != "" && strings.Contains(surface.page, forbidden) {
				t.Fatalf("%s diagnostics exposed %s", surface.label, category)
			}
		}
	}
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
		(sourceRef == fixtureFeatureBranch && branch == fixtureSharedHeadBranch) ||
		(sourceRef == fixtureReleaseBranch && branch == fixtureScheduledBranch)
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

func createScheduledTransitionCommit(t *testing.T, ctx context.Context, forgejo *forgejoAPI, releaseBaseSHA string) string {
	t.Helper()
	releaseBaseSHA = strings.ToLower(strings.TrimSpace(releaseBaseSHA))
	if releaseBaseSHA == "" {
		t.Fatal("scheduled-transition commit requires the exact release base SHA")
	}
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("contents", fixtureScheduledFilename), map[string]any{
		"branch":  fixtureScheduledBranch,
		"message": "Add fictional scheduled transition fixture",
		"content": base64.StdEncoding.EncodeToString([]byte("fictional scheduled release transition\n")),
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo scheduled-transition fixture commit")
	var created struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	decodeJSON(t, response.body, &created, "decode Forgejo scheduled-transition fixture commit")
	headSHA := strings.ToLower(strings.TrimSpace(created.Commit.SHA))
	if headSHA == "" || headSHA == releaseBaseSHA {
		t.Fatalf("Forgejo scheduled-transition fixture did not advance release base %q", releaseBaseSHA)
	}
	return headSHA
}

func requireForgejoBranchProtection(t *testing.T, ctx context.Context, forgejo *forgejoAPI, branch string) {
	t.Helper()
	if branch != fixtureReleaseBranch {
		t.Fatalf("branch protection verification for %q is not allowlisted", branch)
	}
	response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("branch_protections", url.PathEscape(branch)), nil)
	requireAPIStatus(t, response, err, http.StatusOK, "read Forgejo branch protection for "+branch)
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

func createForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI, head, base, title string) pullRequest {
	t.Helper()
	allowed := (head == fixtureFeatureBranch && base == "main" && title == fixturePrimaryPRTitle) ||
		(head == fixtureSharedHeadBranch && base == "main" && title == fixtureSharedHeadPRTitle) ||
		(head == fixtureScheduledBranch && base == fixtureReleaseBranch && title == fixtureScheduledPRTitle)
	if !allowed {
		t.Fatalf("Forgejo pull request head %q, base %q, and title %q are not allowlisted", head, base, title)
	}
	response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("pulls"), map[string]any{
		"head":  head,
		"base":  base,
		"title": title,
	})
	requireAPIStatus(t, response, err, http.StatusCreated, "create Forgejo pull request")
	var pr pullRequest
	decodeJSON(t, response.body, &pr, "decode Forgejo pull request")
	normalizePullRequest(&pr)
	if pr.Number <= 0 || pr.Title != title || pr.State != "open" || pr.Base.Ref != base || pr.Head.SHA == "" || pr.HTMLURL == "" {
		t.Fatalf("Forgejo returned incomplete pull request evidence: number=%d title=%q state=%q base=%q head=%q", pr.Number, pr.Title, pr.State, pr.Base.Ref, pr.Head.SHA)
	}
	return pr
}

func requireOpenForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI, index int, base, title, headSHA string) pullRequest {
	t.Helper()
	response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("pulls", strconv.Itoa(index)), nil)
	requireAPIStatus(t, response, err, http.StatusOK, "read Forgejo pull request")
	var pr pullRequest
	decodeJSON(t, response.body, &pr, "decode Forgejo pull request")
	normalizePullRequest(&pr)
	if pr.Number != index || pr.Title != title || pr.State != "open" || pr.Base.Ref != base || pr.Head.SHA != headSHA || pr.HTMLURL == "" {
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
	if freezeBefore.id <= 0 || freezeBefore.branch != "main" || freezeBefore.reason != "Fictional release verification" || freezeBefore.status != "Frozen" {
		t.Fatalf("active freeze has unexpected pre-restart evidence: id=%d branch=%q reason=%q status=%q", freezeBefore.id, freezeBefore.branch, freezeBefore.reason, freezeBefore.status)
	}
	activityBefore := requireAllActivityPages(t, ctx, browser)
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
			strings.Contains(repositoriesPage, ">enforcement active</span>") &&
			!strings.Contains(repositoriesPage, "Enforcement is unhealthy") &&
			!strings.Contains(repositoriesPage, "Automatic recovery is pending") &&
			strings.Contains(activityPage, ">Reconciliation runner</td>") &&
			strings.Contains(activityPage, `<span class="font-medium text-text">Enforcement recovery</span>`) &&
			strings.Contains(activityPage, "1 open PRs evaluated; 1 statuses posted and 0 failed."), nil
	})

	repositoriesAfter := requirePage(t, ctx, browser, "/repositories")
	if csrfAfter := requireHiddenInput(t, repositoriesAfter, "csrf_token"); csrfAfter != csrfBefore {
		t.Fatal("authenticated session CSRF token changed after restarted recovery")
	}
	for _, want := range []string{
		`<strong class="text-sm text-text">Webhook secret</strong>`,
		"Stored encrypted. Hidden until you intentionally rotate it.",
		`<strong class="text-sm text-text">Status token</strong>`,
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

	activityAfter := requireAllActivityPages(t, ctx, browser)
	recoveryRow := requireLatestActivityRow(t, activityAfter, "Enforcement recovery")
	for _, want := range []string{
		">Reconciliation runner</td>",
		">Succeeded</span>",
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
	for _, want := range []string{pr.Head.SHA, requiredContext, ">failure · forgejo_status</code>", ">posted</span>", "Branch is frozen; merge is blocked by Thawguard"} {
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
	if fixtureFilename != "token-loss.txt" && fixtureFilename != "stale-head-thaw.txt" && fixtureFilename != fixtureRoleThawFilename {
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
		"repo":       {strconv.FormatInt(repositoryID, 10)},
		"processing": {"retryable_failure"},
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
			strings.Contains(webhookPage, ">Verified</span>") &&
			strings.Contains(webhookPage, ">Retryable failure</span>") &&
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
			strings.Contains(activityPage, `<span class="font-medium text-text">Runtime convergence</span>`) &&
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
			strings.Contains(activityPage, `<span class="font-medium text-text">Status token configuration</span>`) &&
			strings.Contains(activityPage, "Status token rotated; the value remains hidden.") &&
			strings.Contains(activityPage, `<span class="font-medium text-text">Enforcement recovery</span>`) &&
			strings.Contains(activityPage, ">Succeeded</span>") &&
			strings.Contains(activityPage, "1 open PRs evaluated; 1 statuses posted and 0 failed.") &&
			strings.Contains(activityPage, "status publication failed; state unhealthy. Automatic recovery remains pending.") &&
			strings.Contains(publicationsPage, headSHA) &&
			strings.Contains(publicationsPage, ">failed</span>") &&
			strings.Contains(publicationsPage, "post forgejo commit status") &&
			strings.Contains(publicationsPage, ">posted</span>"), nil
	})
}

func createRoleBoundaryUser(t *testing.T, ctx context.Context, browser *thawguardBrowser, email, displayName, role, password string, expectedUsersBefore int) int64 {
	t.Helper()
	page := requirePage(t, ctx, browser, "/users")
	if count := requirePageCount(t, page, userCountPattern, "users"); count != expectedUsersBefore {
		t.Fatalf("user creation baseline has %d users, want %d", count, expectedUsersBefore)
	}
	if strings.Contains(page, html.EscapeString(email)) || strings.Contains(page, html.EscapeString(displayName)) {
		t.Fatalf("fictional user %q already exists before creation", email)
	}
	response, err := browser.postFormNoRedirect(ctx, "/users", url.Values{
		"csrf_token":   {requireHiddenInput(t, page, "csrf_token")},
		"email":        {email},
		"display_name": {displayName},
		"password":     {password},
		"roles":        {role},
	})
	if err != nil {
		t.Fatalf("create fictional role-boundary user %q: %v", email, err)
	}
	if response.statusCode != http.StatusSeeOther || response.location != "/users" {
		t.Fatalf("create fictional role-boundary user %q returned HTTP %d with Location %q, want 303 to /users", email, response.statusCode, response.location)
	}
	page = requirePage(t, ctx, browser, "/users")
	if count := requirePageCount(t, page, userCountPattern, "users"); count != expectedUsersBefore+1 {
		t.Fatalf("user creation changed configured users from %d to %d, want %d", expectedUsersBefore, count, expectedUsersBefore+1)
	}
	row := requireRoleBoundaryUserRow(t, page, email)
	for _, want := range []string{html.EscapeString(displayName), ">" + html.EscapeString(email) + "</code>", ">Enabled</span>"} {
		if !strings.Contains(row, want) {
			t.Fatalf("created user %q row is missing %q", email, want)
		}
	}
	for _, candidate := range []string{"admin", "freezer", "thaw_approver", "viewer"} {
		checkboxIndex := strings.Index(row, `value="`+candidate+`"`)
		if checkboxIndex < 0 {
			t.Fatalf("created user %q row is missing the %q role checkbox", email, candidate)
		}
		tagEnd := strings.Index(row[checkboxIndex:], ">")
		if tagEnd < 0 {
			t.Fatalf("created user %q row has an unterminated %q role checkbox", email, candidate)
		}
		selected := strings.Contains(row[checkboxIndex:checkboxIndex+tagEnd], " checked")
		if selected != (candidate == role) {
			t.Fatalf("created user %q role %q selected=%v, want %v", email, candidate, selected, candidate == role)
		}
	}
	userID, err := strconv.ParseInt(requireHiddenInput(t, row, "user_id"), 10, 64)
	if err != nil || userID <= 0 {
		t.Fatalf("created user %q has an invalid rendered user ID", email)
	}
	return userID
}

func requireRoleBoundaryUserRow(t *testing.T, page, email string) string {
	t.Helper()
	marker := ">" + html.EscapeString(email) + "</code>"
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("users page is missing fictional user %q", email)
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("fictional user %q is missing its desktop row", email)
	}
	return page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func loginRoleBoundaryUser(t *testing.T, ctx context.Context, cfg e2eConfig, email, displayName, roleLabel string) roleBoundarySession {
	t.Helper()
	browser := newThawguardBrowser(t, cfg.thawguardURL, cfg.sensitiveValues())
	loginPage, err := browser.getResponseNoRedirect(ctx, "/login")
	if err != nil {
		t.Fatalf("GET /login for %s: %v", roleLabel, err)
	}
	if loginPage.statusCode != http.StatusOK || loginPage.location != "" {
		t.Fatalf("GET /login for %s returned HTTP %d with Location %q, want 200", roleLabel, loginPage.statusCode, loginPage.location)
	}
	loginCSRF := requireHiddenInput(t, string(loginPage.body), "csrf_token")
	if loginCSRF == "" {
		t.Fatalf("GET /login for %s rendered an empty signed CSRF token", roleLabel)
	}
	response, err := browser.postFormNoRedirect(ctx, "/login", url.Values{
		"csrf_token": {loginCSRF},
		"email":      {email},
		"password":   {cfg.thawguardPassword},
	})
	if err != nil {
		t.Fatalf("POST /login for %s: %v", roleLabel, err)
	}
	if response.statusCode != http.StatusSeeOther || response.location != "/" {
		t.Fatalf("POST /login for %s returned HTTP %d with Location %q, want 303 to /", roleLabel, response.statusCode, response.location)
	}
	session := currentRoleBoundarySession(t, ctx, browser, email, displayName, roleLabel)
	if session.csrfToken == loginCSRF {
		t.Fatalf("%s login reused its pre-auth CSRF token as the authenticated session token", roleLabel)
	}
	return session
}

func currentRoleBoundarySession(t *testing.T, ctx context.Context, browser *thawguardBrowser, email, displayName, roleLabel string) roleBoundarySession {
	t.Helper()
	response, err := browser.getResponseNoRedirect(ctx, "/")
	if err != nil {
		t.Fatalf("GET dashboard for %s: %v", roleLabel, err)
	}
	if response.statusCode != http.StatusOK || response.location != "" {
		t.Fatalf("GET dashboard for %s returned HTTP %d with Location %q, want 200", roleLabel, response.statusCode, response.location)
	}
	page := string(response.body)
	for _, want := range []string{
		">" + html.EscapeString(displayName) + "</p>",
		">" + html.EscapeString(email) + "</p>",
		">" + html.EscapeString(roleLabel) + "</span>",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("%s dashboard identity is missing %q", roleLabel, want)
		}
	}
	csrf := requireHiddenInput(t, page, "csrf_token")
	if csrf == "" {
		t.Fatalf("%s session has an empty CSRF token", roleLabel)
	}
	cookie := roleBoundarySessionCookie(t, browser)
	return roleBoundarySession{displayName: displayName, email: email, roleLabel: roleLabel, browser: browser, csrfToken: csrf, sessionCookie: cookie}
}

func roleBoundarySessionCookie(t *testing.T, browser *thawguardBrowser) string {
	t.Helper()
	baseURL, err := url.Parse(browser.baseURL)
	if err != nil {
		t.Fatal("parse Thawguard browser URL for session isolation")
	}
	for _, cookie := range browser.client.Jar.Cookies(baseURL) {
		if cookie.Name == thawguardSessionCookie && cookie.Value != "" {
			return cookie.Value
		}
	}
	t.Fatal("role-boundary browser cookie jar has no authenticated session")
	return ""
}

func requireRoleSessionsIsolated(t *testing.T, ctx context.Context, sessions []roleBoundarySession) {
	t.Helper()
	for i, session := range sessions {
		current := currentRoleBoundarySession(t, ctx, session.browser, session.email, session.displayName, session.roleLabel)
		if current.csrfToken != session.csrfToken || current.sessionCookie != session.sessionCookie {
			t.Fatalf("%s session identity changed while proving isolation", session.roleLabel)
		}
		page := requirePage(t, ctx, session.browser, "/")
		for j, other := range sessions {
			if i != j && strings.Contains(page, ">"+html.EscapeString(other.displayName)+"</p>") {
				t.Fatalf("%s dashboard rendered %s as the signed-in identity", session.roleLabel, other.roleLabel)
			}
		}
		for j := i + 1; j < len(sessions); j++ {
			other := sessions[j]
			if session.browser == other.browser || session.sessionCookie == other.sessionCookie || session.csrfToken == other.csrfToken {
				t.Fatalf("%s and %s did not retain isolated browser, session, and CSRF state", session.roleLabel, other.roleLabel)
			}
		}
	}
}

func requireRoleBoundaryReadAccess(t *testing.T, ctx context.Context, session roleBoundarySession, canAdmin bool) map[string]string {
	t.Helper()
	pages := make(map[string]string)
	for _, path := range []string{"/", "/repositories", "/freezes", "/scheduled-freezes", "/decisions", "/activity", "/publications", "/webhooks"} {
		response, err := session.browser.getResponseNoRedirect(ctx, path)
		if err != nil {
			t.Fatalf("%s GET %s: %v", session.roleLabel, path, err)
		}
		if response.statusCode != http.StatusOK || response.location != "" {
			t.Fatalf("%s GET %s returned HTTP %d with Location %q, want 200", session.roleLabel, path, response.statusCode, response.location)
		}
		page := string(response.body)
		if !strings.Contains(page, ">"+html.EscapeString(session.displayName)+"</p>") || requireHiddenInput(t, page, "csrf_token") != session.csrfToken {
			t.Fatalf("%s GET %s did not retain its identity and CSRF evidence", session.roleLabel, path)
		}
		pages[path] = page
	}
	response, err := session.browser.getResponseNoRedirect(ctx, "/users")
	if err != nil {
		t.Fatalf("%s GET /users: %v", session.roleLabel, err)
	}
	if canAdmin {
		if response.statusCode != http.StatusOK || response.location != "" {
			t.Fatalf("%s GET /users returned HTTP %d with Location %q, want 200", session.roleLabel, response.statusCode, response.location)
		}
		pages["/users"] = string(response.body)
		return pages
	}
	if response.statusCode != http.StatusForbidden || response.location != "" || string(response.body) != "forbidden\n" {
		t.Fatalf("%s GET /users returned HTTP %d with Location %q, want exact 403", session.roleLabel, response.statusCode, response.location)
	}
	return pages
}

func requireRoleBoundaryControls(t *testing.T, pages map[string]string, canAdmin, canFreeze, canThaw bool) {
	t.Helper()
	for path, page := range pages {
		hasUsersNav := strings.Contains(page, `href="/users"`)
		if hasUsersNav != canAdmin {
			t.Fatalf("%s Users & Roles nav visibility=%v, want %v", path, hasUsersNav, canAdmin)
		}
	}
	repositoryPage := pages["/repositories"]
	hasRepositoryMutation := strings.Contains(repositoryPage, `<form method="post" action="/repositories`)
	if hasRepositoryMutation != canAdmin {
		t.Fatalf("repository setup controls visibility=%v, want %v", hasRepositoryMutation, canAdmin)
	}
	if canAdmin {
		for _, want := range []string{`action="/repositories"`, `action="/repositories/setup-check"`, `action="/repositories/reconcile"`} {
			if !strings.Contains(repositoryPage, want) {
				t.Fatalf("Admin-only repository page is missing %q", want)
			}
		}
		if !strings.Contains(pages["/users"], `<form method="post" action="/users"`) {
			t.Fatal("Admin-only users page is missing the create-user form")
		}
	}

	freezesPage := pages["/freezes"]
	for _, marker := range []string{`<form method="post" action="/freezes"`, `action="/freezes/end"`, `action="/freezes/cancel"`} {
		if got := strings.Contains(freezesPage, marker); got != canFreeze {
			t.Fatalf("freeze control %q visibility=%v, want %v", marker, got, canFreeze)
		}
	}
	if got := strings.Contains(pages["/scheduled-freezes"], `<form method="post" action="/scheduled-freezes"`); got != canFreeze {
		t.Fatalf("scheduled-freeze create visibility=%v, want %v", got, canFreeze)
	}
	if got := strings.Contains(pages["/decisions"], `<form method="post" action="/decisions"`); got != canThaw {
		t.Fatalf("thaw approval form visibility=%v, want %v", got, canThaw)
	}
	if got := strings.Contains(pages["/"], "Start freeze</a>"); got != canFreeze {
		t.Fatalf("dashboard Start freeze action visibility=%v, want %v", got, canFreeze)
	}
	if got := strings.Contains(pages["/"], "Review thaws</a>"); got != canThaw {
		t.Fatalf("dashboard Review thaws action visibility=%v, want %v", got, canThaw)
	}
	if !canFreeze && (!strings.Contains(freezesPage, "Read-only freeze access") || !strings.Contains(pages["/scheduled-freezes"], "Read-only schedule access")) {
		t.Fatal("non-Freezer pages are missing their read-only freeze/schedule evidence")
	}
	if !canThaw && !strings.Contains(pages["/decisions"], "Read-only thaw access") {
		t.Fatal("non-Thaw-approver page is missing read-only thaw evidence")
	}
}

func roleBoundarySlug(roleLabel string) string {
	return strings.NewReplacer(" ", "-", "_", "-").Replace(strings.ToLower(roleLabel))
}

func requireForbiddenRoleMutation(t *testing.T, ctx context.Context, session roleBoundarySession, path string, values url.Values, operation string) {
	t.Helper()
	switch path {
	case "/repositories",
		"/repositories/branches",
		"/repositories/branches/remove",
		"/repositories/webhook-secret",
		"/repositories/status-token",
		"/repositories/setup-check",
		"/repositories/status-verification",
		"/repositories/activate",
		"/repositories/deactivate",
		"/repositories/reconcile",
		"/repositories/recover",
		"/users",
		"/users/roles",
		"/users/disable",
		"/users/enable",
		"/users/reset-password",
		"/freezes",
		"/freezes/end",
		"/freezes/cancel",
		"/scheduled-freezes",
		"/scheduled-freezes/edit",
		"/scheduled-freezes/start-now",
		"/scheduled-freezes/cancel",
		"/decisions":
	default:
		t.Fatalf("wrong-role mutation path %q is not allowlisted", path)
	}
	form := make(url.Values, len(values)+1)
	for key, entries := range values {
		form[key] = slices.Clone(entries)
	}
	form.Set("csrf_token", session.csrfToken)
	response, err := session.browser.postFormNoRedirect(ctx, path, form)
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
	if response.statusCode != http.StatusForbidden || response.location != "" || string(response.body) != "forbidden\n" {
		t.Fatalf("%s returned HTTP %d with Location %q, want exact 403", operation, response.statusCode, response.location)
	}
}

func collectRoleBoundaryEvidence(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, repositoryID int64, evidenceHeadSHA string, scheduleReasons, trackedHeads []string) roleBoundaryEvidence {
	t.Helper()
	usersPage := requirePage(t, ctx, browser, "/users")
	dashboardPage := requirePage(t, ctx, browser, "/")
	freezesPage := requirePage(t, ctx, browser, "/freezes")
	schedulesPage := requirePage(t, ctx, browser, "/scheduled-freezes")
	repositoriesPage := requirePage(t, ctx, browser, "/repositories")
	requireHealthyActiveRepository(t, repositoriesPage)
	mainFreeze, _ := requireActiveFreezeEvidenceForBranch(t, freezesPage, "main")
	evidence := roleBoundaryEvidence{
		userCount:        requirePageCount(t, usersPage, userCountPattern, "users"),
		repositoryCount:  requirePageCount(t, dashboardPage, repositoryCountPattern, "repositories"),
		activeFreezes:    requirePageCount(t, freezesPage, activeFreezeCountPattern, "active freezes"),
		scheduledCount:   requirePageCount(t, schedulesPage, scheduledFreezeCountPattern, "scheduled freezes"),
		usersPage:        usersPage,
		repositoriesPage: repositoriesPage,
		mainFreeze:       mainFreeze,
		sideEffects:      collectWebhookSideEffectEvidence(t, ctx, forgejo, browser, repositoryID, evidenceHeadSHA),
	}
	for _, reason := range scheduleReasons {
		evidence.schedules = append(evidence.schedules, requireScheduledFreezeRow(t, schedulesPage, 0, reason))
	}
	for _, headSHA := range trackedHeads {
		statuses, err := listForgejoFreezeStatuses(ctx, forgejo, headSHA)
		if err != nil {
			t.Fatal(err)
		}
		evidence.statusHistories = append(evidence.statusHistories, statuses)
	}
	return evidence
}

func requireUnchangedRoleBoundaryEvidence(t *testing.T, before, after roleBoundaryEvidence, operation string) {
	t.Helper()
	if before.userCount != after.userCount || before.repositoryCount != after.repositoryCount || before.activeFreezes != after.activeFreezes || before.scheduledCount != after.scheduledCount || before.mainFreeze != after.mainFreeze {
		t.Fatalf("%s changed user/repository/freeze/schedule state: users %d→%d repositories %d→%d active %d→%d schedules %d→%d main %+v→%+v",
			operation,
			before.userCount, after.userCount,
			before.repositoryCount, after.repositoryCount,
			before.activeFreezes, after.activeFreezes,
			before.scheduledCount, after.scheduledCount,
			before.mainFreeze, after.mainFreeze)
	}
	if before.usersPage != after.usersPage {
		t.Fatalf("%s changed the full admin Users & Roles state snapshot", operation)
	}
	if before.repositoriesPage != after.repositoriesPage {
		t.Fatalf("%s changed the full admin repository setup/readiness/lifecycle snapshot", operation)
	}
	if len(before.schedules) != len(after.schedules) {
		t.Fatalf("%s changed compared schedule rows from %d to %d", operation, len(before.schedules), len(after.schedules))
	}
	for index := range before.schedules {
		requireSameScheduleEvidence(t, before.schedules[index], after.schedules[index], operation+" changed schedule evidence")
	}
	requireIdenticalWebhookEvidence(t, before.sideEffects, after.sideEffects, operation)
	requireRoleStatusHistoriesUnchanged(t, before.statusHistories, after.statusHistories, operation)
}

func requireRoleStatusHistoriesUnchanged(t *testing.T, before, after [][]commitStatus, operation string) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("%s changed tracked status-history count from %d to %d", operation, len(before), len(after))
	}
	for index := range before {
		if !slices.Equal(before[index], after[index]) {
			t.Fatalf("%s changed tracked Forgejo status history %d: before=%+v after=%+v", operation, index, before[index], after[index])
		}
	}
}

func requireSameScheduleEvidence(t *testing.T, before, after scheduledFreezeRowEvidence, operation string) {
	t.Helper()
	if before.id != after.id || before.branch != after.branch || before.reason != after.reason || before.startsAt != after.startsAt || before.plannedEndsAt != after.plannedEndsAt || before.status != after.status || before.endedAt != after.endedAt {
		t.Fatalf("%s: before=%+v after=%+v", operation, before, after)
	}
}

func requireRoleBoundaryActivity(t *testing.T, row, actor, action, target, outcome string, details ...string) {
	t.Helper()
	wants := []string{
		">" + html.EscapeString(actor) + "</td>",
		`<span class="font-medium text-text">` + html.EscapeString(action) + `</span>`,
		">" + html.EscapeString(target) + "</td>",
		">" + html.EscapeString(outcome) + "</span>",
	}
	for _, detail := range details {
		wants = append(wants, html.EscapeString(detail))
	}
	for _, want := range wants {
		if !strings.Contains(row, want) {
			t.Fatalf("%s activity by %s is missing %q", action, actor, want)
		}
	}
}

func requireScheduleRoleControls(t *testing.T, ctx context.Context, session roleBoundarySession, reason string, canCreate, canEdit, canStart, canCancel bool) {
	t.Helper()
	page := requirePage(t, ctx, session.browser, "/scheduled-freezes")
	row := requireScheduledFreezeRow(t, page, 0, reason).row
	if got := strings.Contains(page, `<form method="post" action="/scheduled-freezes"`); got != canCreate {
		t.Fatalf("%s schedule create-form visibility=%v, want %v", session.roleLabel, got, canCreate)
	}
	for marker, want := range map[string]bool{
		`action="/scheduled-freezes/edit"`: canEdit,
		`aria-controls="start-scheduled-`:  canStart,
		`aria-controls="cancel-scheduled-`: canCancel,
	} {
		if got := strings.Contains(row, marker); got != want {
			t.Fatalf("%s schedule control %q visibility=%v, want %v", session.roleLabel, marker, got, want)
		}
	}
}

func scanRenderedTokenSurfaces(t *testing.T, ctx context.Context, browser *thawguardBrowser) {
	t.Helper()
	for _, path := range []string{
		"/",
		"/repositories",
		"/freezes",
		"/scheduled-freezes",
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

	response, err := postSyntheticWebhook(ctx, cfg, payload, invalidDeliveryID, invalidSignatureSecret)
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
		"repo": {strconv.FormatInt(repositoryID, 10)},
	}.Encode()
	webhookPage := requirePage(t, ctx, browser, webhookPath)
	decisionsPage := requirePage(t, ctx, browser, "/decisions")
	publicationsPage := requirePage(t, ctx, browser, "/publications")
	// The header count badge is a total, so the first page is enough here and
	// keeps the polling loops that call this helper cheap.
	activityPage := requirePage(t, ctx, browser, "/activity")
	statuses, err := listForgejoFreezeStatuses(ctx, forgejo, headSHA)
	if err != nil {
		t.Fatal(err)
	}
	return webhookSideEffectEvidence{
		webhookPage:         webhookPage,
		webhookRows:         requirePageCount(t, webhookPage, deliveryCountPattern, "webhook deliveries"),
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

func requireProcessedVerifiedDelivery(t *testing.T, page, deliveryID string) string {
	t.Helper()
	marker := `title="` + html.EscapeString(deliveryID) + `"`
	if count := strings.Count(page, marker); count != 2 {
		t.Fatalf("delivery ID %q rendered %d times, want one desktop row and one mobile card", deliveryID, count)
	}
	markerIndex := strings.Index(page, marker)
	rowStart := strings.LastIndex(page[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("delivery ID %q is missing its desktop row", deliveryID)
	}
	row := page[rowStart : markerIndex+rowEndOffset]
	if !strings.Contains(row, ">Verified</span>") || !strings.Contains(row, ">Processed</span>") {
		t.Fatalf("delivery ID %q is not rendered as verified and processed", deliveryID)
	}
	return row
}

func waitForOneNewProcessedPullRequestDelivery(t *testing.T, ctx context.Context, browser *thawguardBrowser, repositoryID int64, beforeRows int, action string) {
	t.Helper()
	if action != "opened" && action != "synchronized" && action != "closed" {
		t.Fatalf("pull request delivery action %q is not allowlisted", action)
	}
	webhookPath := "/webhooks?" + url.Values{
		"repo": {strconv.FormatInt(repositoryID, 10)},
	}.Encode()
	expectedRows := beforeRows + 1
	waitFor(t, 30*time.Second, "one new verified and processed "+action+" delivery", func() (bool, error) {
		page, err := browser.get(ctx, webhookPath)
		if err != nil {
			return false, err
		}
		rows := requirePageCount(t, page, deliveryCountPattern, "webhook deliveries")
		if rows > expectedRows {
			t.Fatalf("%s pull request delivery changed webhook deliveries from %d to %d, want exactly %d", action, beforeRows, rows, expectedRows)
		}
		if rows != expectedRows {
			return false, nil
		}
		latestRow := requireLatestWebhookDeliveryRow(t, page)
		for _, want := range []string{
			">" + fixtureOwner + "/" + fixtureRepository + "</span>",
			">pull_request · " + action + "</span>",
			`>Verified</span>`,
			`>Processed</span>`,
			`>No processing error</span>`,
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
	sectionMarker := `aria-label="Signed webhook deliveries"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("webhook page is missing signed deliveries")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("signed webhook deliveries are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr ")
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
	return countActivityEvents(page, "Open pull request sync")
}

func countPullRequestDeliveryActions(page, action string) int {
	return strings.Count(page, ">pull_request · "+html.EscapeString(action)+"</span>")
}

func countActivityEvents(page, action string) int {
	return strings.Count(page, `<span class="font-medium text-text">`+html.EscapeString(action)+`</span>`)
}

func countSharedHeadThawEvents(page string) int {
	return countActivityEvents(page, "Shared-head thaw")
}

func countEligibleDecisionRows(page string) int {
	// The state badge renders in both the desktop row and the mobile card, so
	// count only inside the desktop table body.
	sectionStart := strings.Index(page, `aria-label="Freeze decisions"`)
	if sectionStart < 0 {
		return 0
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		return 0
	}
	tbody := page[sectionStart+tbodyOffset:]
	if end := strings.Index(tbody, "</tbody>"); end >= 0 {
		tbody = tbody[:end]
	}
	return strings.Count(tbody, ">Eligible</span>")
}

// getAllActivityPages walks the paginated /activity table and returns every
// page concatenated newest-first, so event counts and retained-row checks do
// not saturate on the first page once history exceeds one page.
func getAllActivityPages(ctx context.Context, browser *thawguardBrowser) (string, error) {
	var pages strings.Builder
	for page := 1; ; page++ {
		path := "/activity"
		if page > 1 {
			path = "/activity?page=" + strconv.Itoa(page)
		}
		pageHTML, err := browser.get(ctx, path)
		if err != nil {
			return "", err
		}
		pages.WriteString(pageHTML)
		// The pager links to the next page only when one exists; the server
		// clamps overflowing page numbers back to the last page, so fetching
		// past the advertised end would double-count its rows.
		if !strings.Contains(pageHTML, "page="+strconv.Itoa(page+1)) {
			return pages.String(), nil
		}
		if page >= 100 {
			return "", fmt.Errorf("/activity pagination did not terminate within 100 pages")
		}
	}
}

func requireAllActivityPages(t *testing.T, ctx context.Context, browser *thawguardBrowser) string {
	t.Helper()
	pages, err := getAllActivityPages(ctx, browser)
	if err != nil {
		t.Fatal(err)
	}
	return pages
}

func waitForOneNewOpenPullRequestSync(t *testing.T, ctx context.Context, browser *thawguardBrowser, before int) string {
	t.Helper()
	expected := before + 1
	var activityPage string
	waitFor(t, 30*time.Second, "one new open pull request sync activity event", func() (bool, error) {
		page, err := getAllActivityPages(ctx, browser)
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

func requireScheduleOnlyActivityDelta(t *testing.T, before, after webhookSideEffectEvidence, activityDelta int, operation string) {
	t.Helper()
	if before.webhookRows != after.webhookRows ||
		before.statusResults != after.statusResults ||
		before.publicationIntents != after.publicationIntents ||
		before.publicationAttempts != after.publicationAttempts ||
		after.activityEvents != before.activityEvents+activityDelta ||
		!slices.Equal(before.freezeStatuses, after.freezeStatuses) {
		t.Fatalf("%s changed non-activity evidence or added the wrong activity delta: webhooks %d→%d, status results %d→%d, intents %d→%d, attempts %d→%d, activity %d→%d, Forgejo statuses %d→%d",
			operation,
			before.webhookRows, after.webhookRows,
			before.statusResults, after.statusResults,
			before.publicationIntents, after.publicationIntents,
			before.publicationAttempts, after.publicationAttempts,
			before.activityEvents, after.activityEvents,
			len(before.freezeStatuses), len(after.freezeStatuses))
	}
}

func requireMainSharedStateUnchanged(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, expectedFreeze activeFreezeEvidence, sharedHeadSHA string, expectedStatuses []commitStatus, operation string) {
	t.Helper()
	currentFreeze, _ := requireActiveFreezeEvidenceForBranch(t, requirePage(t, ctx, browser, "/freezes"), "main")
	if currentFreeze != expectedFreeze {
		t.Fatalf("%s changed the active main freeze: before=%+v after=%+v", operation, expectedFreeze, currentFreeze)
	}
	currentStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, sharedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(currentStatuses, expectedStatuses) {
		t.Fatalf("%s changed the shared main-head status history: before=%+v after=%+v", operation, expectedStatuses, currentStatuses)
	}
}

func requireRetainedPlannedUnfreezeFixtureState(t *testing.T, ctx context.Context, forgejo *forgejoAPI, browser *thawguardBrowser, fixture scheduledFreezeLifecycleFixture, operation string) {
	t.Helper()
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.primaryPullRequestIndex, "main", fixturePrimaryPRTitle, fixture.sharedHeadSHA)
	requireOpenForgejoPullRequest(t, ctx, forgejo, fixture.sharedHeadPullRequestIndex, "main", fixtureSharedHeadPRTitle, fixture.sharedHeadSHA)
	requireMainSharedStateUnchanged(t, ctx, forgejo, browser, fixture.activeMainFreeze, fixture.sharedHeadSHA, fixture.mainSharedHeadStatuses, operation)

	historicalStatuses, err := listForgejoFreezeStatuses(ctx, forgejo, fixture.historicalThawedHeadSHA)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(historicalStatuses, fixture.historicalThawedHeadStatuses) {
		t.Fatalf("%s changed historical thawed-head status evidence: before=%+v after=%+v", operation, fixture.historicalThawedHeadStatuses, historicalStatuses)
	}
	decisionsPage := requirePage(t, ctx, browser, "/decisions")
	if !strings.Contains(decisionsPage, fixture.historicalEligibleDecisionRow) {
		t.Fatalf("%s changed the historical Eligible decision evidence", operation)
	}
	activityPage := requireAllActivityPages(t, ctx, browser)
	if !strings.Contains(activityPage, fixture.historicalSinglePRThawActivity) {
		t.Fatalf("%s changed the historical Single-PR thaw activity evidence", operation)
	}
}

func requireHealthyActiveRepository(t *testing.T, page string) {
	t.Helper()
	for _, want := range []string{
		fixtureOwner + `/` + fixtureRepository,
		`>enforcement active</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("healthy active repository evidence is missing %q", want)
		}
	}
	for _, absent := range []string{
		"Enforcement is unhealthy",
		"Automatic recovery is pending",
		"Recovery in progress",
		`action="/repositories/recover"`,
	} {
		if strings.Contains(page, absent) {
			t.Fatalf("healthy active repository unexpectedly renders %q", absent)
		}
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
	if !strings.Contains(releaseRow, `>failed</span>`) {
		t.Fatal("unprotected release branch is missing its failed readiness badge")
	}
	requireReadinessCheck(t, releaseRow, "Branch protection readable", "passed")
	if want := `Branch protection readable</strong> <span class="text-text-muted">The forge confirmed that this exact managed branch has no branch protection configuration.`; !strings.Contains(releaseRow, want) {
		t.Fatalf("unprotected release readiness row is missing %q", want)
	}
	requireReadinessCheck(t, releaseRow, "Branch protection enabled", "failed")
	requireReadinessCheck(t, releaseRow, "Required status checks enabled", "failed")
	requireReadinessCheck(t, releaseRow, "Required thawguard/freeze context configured", "failed")
	for _, absent := range []string{
		`action="/repositories/status-verification"`,
		`action="/repositories/activate"`,
	} {
		if strings.Contains(page, absent) {
			t.Fatalf("failed readiness unexpectedly offered form %s", absent)
		}
	}
	for _, want := range []string{
		`>setup incomplete</span>`,
		`disabled>Verify status posting</button>`,
		`Fix the failing readiness checks and rerun them. Verification is offered once every mandatory read-only check passes.`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("failed readiness page is missing %q", want)
		}
	}

	activityRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Readiness check")
	if want := "8 passed, 1 warnings, 3 failed across 2 managed branches; webhook evidence fresh."; !strings.Contains(activityRow, want) {
		t.Fatalf("failed readiness activity is missing %q", want)
	}
}

func requireRepairedReleaseReadiness(t *testing.T, ctx context.Context, browser *thawguardBrowser) {
	t.Helper()
	page := requirePage(t, ctx, browser, "/repositories")
	releaseRow := requireManagedBranchRow(t, page, fixtureReleaseBranch)
	if !strings.Contains(releaseRow, `>passed</span>`) {
		t.Fatal("repaired release branch is missing its passed readiness badge")
	}
	requireReadinessCheck(t, releaseRow, "Branch protection readable", "passed")
	requireReadinessCheck(t, releaseRow, "Branch protection enabled", "passed")
	requireReadinessCheck(t, releaseRow, "Required status checks enabled", "passed")
	requireReadinessCheck(t, releaseRow, "Required thawguard/freeze context configured", "passed")
	if !strings.Contains(page, `>enforcement active</span>`) {
		t.Fatal("repaired repository did not reach enforcement-active state")
	}

	activityRow := requireLatestActivityRow(t, requireAllActivityPages(t, ctx, browser), "Readiness check")
	if want := "11 passed, 1 warnings, 0 failed across 2 managed branches; webhook evidence fresh."; !strings.Contains(activityRow, want) {
		t.Fatalf("successful readiness activity is missing %q", want)
	}
}

func requireManagedBranchRow(t *testing.T, page, branch string) string {
	t.Helper()
	marker := `<code class="text-sm font-semibold">` + html.EscapeString(branch) + `</code>`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("managed branch %q is missing from repositories page", branch)
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<li ")
	rowEndOffset := strings.Index(page[markerIndex:], "</li>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("managed branch %q is missing its branch row", branch)
	}
	return page[rowStart : markerIndex+rowEndOffset+len("</li>")]
}

// requireReadinessCheck asserts one named readiness check inside a readiness
// evidence scope renders the expected status badge.
func requireReadinessCheck(t *testing.T, scope, name, status string) {
	t.Helper()
	marker := `<strong class="text-text">` + html.EscapeString(name) + `</strong>`
	markerIndex := strings.Index(scope, marker)
	if markerIndex < 0 {
		t.Fatalf("readiness check %q is missing", name)
	}
	checkStart := strings.LastIndex(scope[:markerIndex], `<div class="flex items-start gap-2.5 text-sm">`)
	if checkStart < 0 {
		t.Fatalf("readiness check %q is missing its evidence row", name)
	}
	if !strings.Contains(scope[checkStart:markerIndex], ">"+status+"</span>") {
		t.Fatalf("readiness check %q is not rendered as %s", name, status)
	}
}

func requireLatestActivityRow(t *testing.T, page, action string) string {
	t.Helper()
	marker := `<span class="font-medium text-text">` + html.EscapeString(action) + `</span>`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("activity is missing a %q event", action)
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("latest %q event is missing its activity row", action)
	}
	return page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func requireScheduledFreezeRow(t *testing.T, page string, expectedPendingID int64, reason string) scheduledFreezeRowEvidence {
	t.Helper()
	reason = strings.TrimSpace(reason)
	if reason == "" {
		t.Fatal("scheduled freeze row lookup requires a unique reason")
	}
	marker := ">" + html.EscapeString(reason) + "</td>"
	if count := strings.Count(page, marker); count != 1 {
		t.Fatalf("scheduled freeze reason %q rendered %d desktop rows, want exactly one", reason, count)
	}
	markerIndex := strings.Index(page, marker)
	rowStart := strings.LastIndex(page[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("scheduled freeze reason %q is missing its desktop row", reason)
	}
	row := page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
	// The Starts and Planned unfreeze cells are the only two time cells in the
	// row: a <time> element when set, an em dash otherwise.
	timeCells := scheduleTimeCellPattern.FindAllStringSubmatch(row, -1)
	if len(timeCells) < 2 {
		t.Fatalf("scheduled freeze reason %q rendered %d time cells, want 2", reason, len(timeCells))
	}
	startsAt, plannedEndsAt := timeCells[0][1], timeCells[1][1]
	if startsAt == "" {
		startsAt = "—"
	}
	if plannedEndsAt == "" {
		plannedEndsAt = "—"
	}
	endedAt := "—"
	if subLine := scheduleSubLinePattern.FindStringSubmatch(row); subLine != nil {
		endedAt = subLine[1]
	}
	evidence := scheduledFreezeRowEvidence{
		branch:        requirePatternText(t, row, branchCodePattern, "scheduled freeze branch"),
		reason:        reason,
		startsAt:      startsAt,
		plannedEndsAt: plannedEndsAt,
		status:        requirePatternText(t, row, scheduledFreezeStatusPattern, "scheduled freeze status"),
		endedAt:       endedAt,
		row:           row,
	}
	if strings.Contains(row, `name="freeze_id"`) {
		id, err := strconv.ParseInt(requireHiddenInput(t, row, "freeze_id"), 10, 64)
		if err != nil || id <= 0 {
			t.Fatalf("parse scheduled freeze ID for reason %q: %v", reason, err)
		}
		evidence.id = id
	}
	if expectedPendingID > 0 && evidence.id == 0 {
		t.Fatalf("pending scheduled freeze reason %q did not render ID %d", reason, expectedPendingID)
	}
	if expectedPendingID > 0 && evidence.id != expectedPendingID {
		t.Fatalf("pending scheduled freeze reason %q rendered ID %d, want %d", reason, evidence.id, expectedPendingID)
	}
	return evidence
}

func requirePendingScheduleActions(t *testing.T, page string, schedule scheduledFreezeRowEvidence, startsAt, plannedEndsAt time.Time) {
	t.Helper()
	if schedule.id <= 0 {
		t.Fatalf("pending schedule %q has no exact ID", schedule.reason)
	}
	id := strconv.FormatInt(schedule.id, 10)
	for _, want := range []string{
		`action="/scheduled-freezes/edit"`,
		`aria-controls="start-scheduled-` + id + `"`,
		`aria-controls="cancel-scheduled-` + id + `"`,
		`name="freeze_id" value="` + id + `"`,
		`data-utc-datetime="` + startsAt.UTC().Format(time.RFC3339) + `"`,
		`data-utc-datetime="` + plannedEndsAt.UTC().Format(time.RFC3339) + `"`,
	} {
		if !strings.Contains(schedule.row, want) {
			t.Fatalf("pending schedule %d (%s) is missing %q", schedule.id, schedule.reason, want)
		}
	}
	// The Start Now and Cancel confirmation dialogs render outside the table.
	requireDialogEvidence(t, page, "start-scheduled-"+id,
		`action="/scheduled-freezes/start-now"`,
		`name="freeze_id" value="`+id+`"`,
		`Start Now</button>`,
	)
	requireDialogEvidence(t, page, "cancel-scheduled-"+id,
		`action="/scheduled-freezes/cancel"`,
		`name="freeze_id" value="`+id+`"`,
		`Cancel schedule</button>`,
	)
}

func requireDialogEvidence(t *testing.T, page, dialogID string, wants ...string) {
	t.Helper()
	marker := `<dialog id="` + dialogID + `"`
	start := strings.Index(page, marker)
	if start < 0 {
		t.Fatalf("dialog %q is missing", dialogID)
	}
	endOffset := strings.Index(page[start:], "</dialog>")
	if endOffset < 0 {
		t.Fatalf("dialog %q is incomplete", dialogID)
	}
	dialog := page[start : start+endOffset]
	for _, want := range wants {
		if !strings.Contains(dialog, want) {
			t.Fatalf("dialog %q is missing %q", dialogID, want)
		}
	}
}

func requireNoPendingScheduleActions(t *testing.T, schedule scheduledFreezeRowEvidence) {
	t.Helper()
	for _, absent := range []string{
		`action="/scheduled-freezes/edit"`,
		`aria-controls="start-scheduled-`,
		`aria-controls="cancel-scheduled-`,
		`name="freeze_id"`,
	} {
		if strings.Contains(schedule.row, absent) {
			t.Fatalf("non-pending schedule %q still renders pending action evidence %q", schedule.reason, absent)
		}
	}
}

func requireUnchangedPendingSchedule(t *testing.T, before, after scheduledFreezeRowEvidence, operation string) {
	t.Helper()
	if before.id != after.id || before.branch != after.branch || before.reason != after.reason || before.startsAt != after.startsAt || before.plannedEndsAt != after.plannedEndsAt || before.status != after.status || before.endedAt != after.endedAt {
		t.Fatalf("%s changed Schedule A: before=%+v after=%+v", operation, before, after)
	}
	for _, action := range []string{
		`action="/scheduled-freezes/edit"`,
		`aria-controls="start-scheduled-`,
		`aria-controls="cancel-scheduled-`,
	} {
		if !strings.Contains(after.row, action) {
			t.Fatalf("%s removed pending Schedule A action %q", operation, action)
		}
	}
}

func requireScheduleActivityEvidence(t *testing.T, row, action, outcome, reason string) {
	t.Helper()
	for _, want := range []string{
		`>E2E Admin</td>`,
		`<span class="font-medium text-text">` + html.EscapeString(action) + `</span>`,
		`>` + fixtureOwner + `/` + fixtureRepository + ` → ` + fixtureReleaseBranch + `</td>`,
		`>` + outcome + `</span>`,
		html.EscapeString(reason),
	} {
		if !strings.Contains(row, want) {
			t.Fatalf("%s activity is missing %q", action, want)
		}
	}
}

func scheduleTime(value time.Time) string {
	return value.UTC().Format("2006-01-02 15:04 UTC")
}

func requireActiveFreezeEvidence(t *testing.T, page string) activeFreezeEvidence {
	t.Helper()
	// The lift/cancel forms live in dialogs outside the table; the desktop row
	// carries the aria-controls buttons that open them.
	marker := `aria-controls="lift-freeze-`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatal("active freeze is missing its lift action")
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatal("active freeze is missing its desktop table row")
	}
	row := page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
	evidence := activeFreezeEvidence{
		id:     parseLiftFreezeID(t, row),
		branch: requirePatternText(t, row, branchCodePattern, "active freeze branch"),
		reason: requirePatternText(t, row, activeFreezeReasonPattern, "active freeze reason"),
		status: requirePatternText(t, row, activeFreezeStatusPattern, "active freeze status"),
	}
	requireActiveFreezeDialogs(t, page, evidence.id)
	return evidence
}

func requireActiveFreezeDialogs(t *testing.T, page string, freezeID int64) {
	t.Helper()
	id := strconv.FormatInt(freezeID, 10)
	requireDialogEvidence(t, page, "lift-freeze-"+id,
		`action="/freezes/end"`,
		`name="freeze_id" value="`+id+`"`,
		`Lift freeze</button>`,
	)
	requireDialogEvidence(t, page, "cancel-freeze-"+id,
		`action="/freezes/cancel"`,
		`name="freeze_id" value="`+id+`"`,
		`Cancel freeze</button>`,
	)
}

func parseLiftFreezeID(t *testing.T, row string) int64 {
	t.Helper()
	marker := `aria-controls="lift-freeze-`
	start := strings.Index(row, marker)
	if start < 0 {
		t.Fatal("active freeze row is missing its lift action")
	}
	digits := row[start+len(marker):]
	end := strings.Index(digits, `"`)
	if end < 0 {
		t.Fatal("active freeze row has an unterminated lift action")
	}
	id, err := strconv.ParseInt(digits[:end], 10, 64)
	if err != nil || id <= 0 {
		t.Fatalf("parse active freeze ID: %v", err)
	}
	return id
}

func requireActiveFreezeEvidenceForBranch(t *testing.T, page, branch string) (activeFreezeEvidence, string) {
	t.Helper()
	// The branch code renders in both the desktop row and the mobile card, so
	// scope the uniqueness check to the desktop table body.
	sectionStart := strings.Index(page, `aria-label="Active freezes"`)
	if sectionStart < 0 {
		t.Fatal("freezes page is missing the active freezes section")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("active freezes section is missing its table body")
	}
	tbody := page[sectionStart+tbodyOffset:]
	if end := strings.Index(tbody, "</tbody>"); end >= 0 {
		tbody = tbody[:end]
	}
	marker := `<code class="font-mono text-xs text-text-muted">` + html.EscapeString(branch) + `</code>`
	if count := strings.Count(tbody, marker); count != 1 {
		t.Fatalf("active freeze branch %q rendered %d desktop rows, want exactly one", branch, count)
	}
	markerIndex := strings.Index(tbody, marker)
	rowStart := strings.LastIndex(tbody[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(tbody[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("active freeze branch %q is missing its desktop row", branch)
	}
	row := tbody[rowStart : markerIndex+rowEndOffset+len("</tr>")]
	if !strings.Contains(row, `aria-controls="lift-freeze-`) {
		t.Fatalf("active freeze branch %q is missing its active action", branch)
	}
	evidence := activeFreezeEvidence{
		id:     parseLiftFreezeID(t, row),
		branch: requirePatternText(t, row, branchCodePattern, "active freeze branch"),
		reason: requirePatternText(t, row, activeFreezeReasonPattern, "active freeze reason"),
		status: requirePatternText(t, row, activeFreezeStatusPattern, "active freeze status"),
	}
	if evidence.branch != branch {
		t.Fatalf("active freeze lookup for %q returned branch %q", branch, evidence.branch)
	}
	requireActiveFreezeDialogs(t, page, evidence.id)
	return evidence, row
}

func requireActiveFreezeCount(t *testing.T, page string, expected int) {
	t.Helper()
	want := ">" + strconv.Itoa(expected) + " active</span>"
	if !strings.Contains(page, want) {
		t.Fatalf("freezes page is missing exact active count %q", want)
	}
}

func requireNoActiveFreezeForBranch(t *testing.T, page string, freeze activeFreezeEvidence) {
	t.Helper()
	marker := `<code class="font-mono text-xs text-text-muted">` + html.EscapeString(freeze.branch) + `</code>`
	for _, absent := range []string{
		marker,
		`name="freeze_id" value="` + strconv.FormatInt(freeze.id, 10) + `"`,
		html.EscapeString(freeze.reason),
	} {
		if strings.Contains(page, absent) {
			t.Fatalf("inactive branch %q freeze %d still renders active evidence %q", freeze.branch, freeze.id, absent)
		}
	}
}

func requireNoActiveFreezeEvidence(t *testing.T, page string, freeze activeFreezeEvidence) {
	t.Helper()
	for _, want := range []string{">0 active</span>", "No active freezes"} {
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

func requireBranchFreezeActivityEvidence(t *testing.T, row string, freeze activeFreezeEvidence, outcome string) {
	t.Helper()
	for _, want := range []string{
		`>E2E Admin</td>`,
		`<span class="font-medium text-text">Branch freeze</span>`,
		`>` + fixtureOwner + `/` + fixtureRepository + ` → ` + html.EscapeString(freeze.branch) + `</td>`,
		`>` + outcome + `</span>`,
		`>Reason: ` + html.EscapeString(freeze.reason),
	} {
		if !strings.Contains(row, want) {
			t.Fatalf("branch-freeze activity for freeze %d is missing %q", freeze.id, want)
		}
	}
}

func requireLatestPublicationIntentRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := `aria-label="Latest desired statuses"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("publications page is missing latest desired statuses")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("latest desired statuses are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr ")
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

func requirePublicationIntentRowForHead(t *testing.T, page, headSHA string) string {
	t.Helper()
	sectionMarker := `aria-label="Latest desired statuses"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("publications page is missing latest desired statuses")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("latest desired statuses are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	tbodyEndOffset := strings.Index(page[tbodyStart:], "</tbody>")
	if tbodyEndOffset < 0 {
		t.Fatal("latest desired statuses have an incomplete table body")
	}
	tbody := page[tbodyStart : tbodyStart+tbodyEndOffset]
	// The short SHA code element carries the full head SHA in its title.
	marker := `title="` + html.EscapeString(headSHA) + `"`
	if count := strings.Count(tbody, marker); count != 1 {
		t.Fatalf("latest desired statuses render head %q in %d desktop rows, want exactly one", headSHA, count)
	}
	markerIndex := strings.Index(tbody, marker)
	rowStart := strings.LastIndex(tbody[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(tbody[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("latest desired status for head %q is incomplete", headSHA)
	}
	return tbody[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func requireLatestPublicationAttemptRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := `aria-label="Recent publication attempts"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("publications page is missing recent publication attempts")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("recent publication attempts are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr ")
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

func requirePublicationAttemptRowForHead(t *testing.T, page, headSHA string) string {
	t.Helper()
	sectionMarker := `aria-label="Recent publication attempts"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("publications page is missing recent publication attempts")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("recent publication attempts are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	tbodyEndOffset := strings.Index(page[tbodyStart:], "</tbody>")
	if tbodyEndOffset < 0 {
		t.Fatal("recent publication attempts have an incomplete table body")
	}
	tbody := page[tbodyStart : tbodyStart+tbodyEndOffset]
	marker := `title="` + html.EscapeString(headSHA) + `"`
	markerIndex := strings.Index(tbody, marker)
	if markerIndex < 0 {
		t.Fatalf("recent publication attempts are missing head %q", headSHA)
	}
	rowStart := strings.LastIndex(tbody[:markerIndex], "<tr ")
	rowEndOffset := strings.Index(tbody[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("recent publication attempt for head %q is incomplete", headSHA)
	}
	return tbody[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func requireLatestDecisionResultRow(t *testing.T, page string) string {
	t.Helper()
	sectionMarker := `aria-label="Freeze decisions"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("decisions page is missing the freeze decisions table")
	}
	tbodyOffset := strings.Index(page[sectionStart:], "<tbody>")
	if tbodyOffset < 0 {
		t.Fatal("freeze decisions are missing their table body")
	}
	tbodyStart := sectionStart + tbodyOffset
	rowStartOffset := strings.Index(page[tbodyStart:], "<tr ")
	if rowStartOffset < 0 {
		t.Fatal("freeze decisions are missing their latest row")
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
	sectionMarker := `aria-label="Freeze decisions"`
	sectionStart := strings.Index(page, sectionMarker)
	if sectionStart < 0 {
		t.Fatal("decisions page is missing the freeze decisions table")
	}
	marker := `title="` + html.EscapeString(headSHA) + `"`
	markerOffset := strings.Index(page[sectionStart:], marker)
	if markerOffset < 0 {
		t.Fatalf("freeze decisions are missing head %q", headSHA)
	}
	markerIndex := sectionStart + markerOffset
	rowStart := strings.LastIndex(page[sectionStart:markerIndex], "<tr ")
	rowEndOffset := strings.Index(page[markerIndex:], "</tr>")
	if rowStart < 0 || rowEndOffset < 0 {
		t.Fatalf("freeze decision for head %q is incomplete", headSHA)
	}
	rowStart += sectionStart
	return page[rowStart : markerIndex+rowEndOffset+len("</tr>")]
}

func waitForLatestPostedPublicationAttempt(t *testing.T, ctx context.Context, browser *thawguardBrowser, headSHA, state, description string) {
	t.Helper()
	wants := []string{
		`title="` + headSHA + `"`,
		">" + requiredContext + "</code>",
		">" + state + " · forgejo_status</code>",
		">posted</span>",
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

func requireRawScheduledFreezeMutation(t *testing.T, ctx context.Context, browser *thawguardBrowser, path string, values url.Values, operation string) {
	t.Helper()
	notices := map[string]string{
		"/scheduled-freezes":           "schedule-created",
		"/scheduled-freezes/edit":      "schedule-updated",
		"/scheduled-freezes/start-now": "schedule-started",
		"/scheduled-freezes/cancel":    "schedule-cancelled",
	}
	notice, allowlisted := notices[path]
	if !allowlisted {
		t.Fatalf("scheduled freeze mutation path %q is not allowlisted", path)
	}
	page := requirePage(t, ctx, browser, "/scheduled-freezes")
	values.Set("csrf_token", requireHiddenInput(t, page, "csrf_token"))
	response, err := browser.postFormNoRedirect(ctx, path, values)
	if err != nil {
		t.Fatalf("%s: %v", operation, err)
	}
	wantLocation := "/scheduled-freezes?notice=" + notice
	if response.statusCode != http.StatusSeeOther || response.location != wantLocation {
		t.Fatalf("%s returned HTTP %d with Location %q, want raw 303 to %s", operation, response.statusCode, response.location, wantLocation)
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
	if created.branch != "main" || created.reason != reason || created.status != "Frozen" {
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

func mergeForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI, index int) {
	t.Helper()
	waitFor(t, 30*time.Second, "ordinary Forgejo release mergeability convergence", func() (bool, error) {
		response, err := forgejo.do(ctx, http.MethodPost, forgejo.repositoryPath("pulls", strconv.Itoa(index), "merge"), map[string]string{"Do": "merge"})
		if err != nil {
			return false, err
		}
		if response.statusCode >= 200 && response.statusCode < 300 {
			return true, nil
		}
		if response.statusCode == http.StatusMethodNotAllowed && requiredStatusChecksPending(response) {
			return false, nil
		}
		t.Fatalf("ordinary Forgejo release merge returned an unexpected response: %v", apiStatusError(response, "merge release pull request"))
		return false, nil
	})
}

func requireMergedForgejoPullRequest(t *testing.T, ctx context.Context, forgejo *forgejoAPI, index int, base, title, headSHA string) pullRequest {
	t.Helper()
	var merged pullRequest
	waitFor(t, 30*time.Second, "Forgejo release pull request to become closed and merged", func() (bool, error) {
		response, err := forgejo.do(ctx, http.MethodGet, forgejo.repositoryPath("pulls", strconv.Itoa(index)), nil)
		if err != nil {
			return false, err
		}
		if response.statusCode != http.StatusOK {
			return false, apiStatusError(response, "read merged Forgejo pull request")
		}
		var pr pullRequest
		if err := json.Unmarshal(response.body, &pr); err != nil {
			return false, fmt.Errorf("decode merged Forgejo pull request: %w", err)
		}
		normalizePullRequest(&pr)
		if pr.Number != index || pr.Title != title || pr.Base.Ref != base || pr.Head.SHA != headSHA || pr.HTMLURL == "" {
			t.Fatalf("unexpected merged Forgejo PR #%d evidence: number=%d title=%q state=%q merged=%t base=%q head=%q", index, pr.Number, pr.Title, pr.State, pr.Merged, pr.Base.Ref, pr.Head.SHA)
		}
		if pr.State == "open" {
			return false, nil
		}
		if pr.State != "closed" {
			t.Fatalf("merged Forgejo PR #%d has unexpected state %q", index, pr.State)
		}
		if pr.Merged {
			merged = pr
		}
		return pr.Merged, nil
	})
	return merged
}

func requiredStatusChecksPending(response apiResponse) bool {
	var payload struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(response.body, &payload) != nil {
		return false
	}
	message := strings.ToLower(strings.TrimSpace(payload.Message))
	return strings.Contains(message, "required status checks") &&
		(strings.Contains(message, "not all") || strings.Contains(message, "not successful") || strings.Contains(message, "unsuccessful"))
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

		return requiredStatusChecksPending(response), nil
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

func (b *thawguardBrowser) getResponseNoRedirect(ctx context.Context, path string) (apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+path, nil)
	if err != nil {
		return apiResponse{}, err
	}
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
	marker := `<code class="font-mono text-xs font-bold text-text">#` + strconv.Itoa(pullRequestIndex) + `</code>`
	markerIndex := strings.Index(page, marker)
	if markerIndex < 0 {
		t.Fatalf("shared-head confirmation is missing PR #%d", pullRequestIndex)
	}
	rowStart := strings.LastIndex(page[:markerIndex], "<tr ")
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

// The count patterns match the visible section-header badge text ("3 users",
// "1 delivery", "0 active", …) rather than any styling classes so they survive
// restyles. Row-field patterns anchor on visible text or the small stable
// markers the templates emit (branch <code> elements, <time> cells, badges).
var (
	userCountPattern             = regexp.MustCompile(`>([0-9]+) users?</span>`)
	repositoryCountPattern       = regexp.MustCompile(`(?s)>Enforcing</p>\s*<p[^>]*>[0-9]+ of ([0-9]+)</p>`)
	activeFreezeCountPattern     = regexp.MustCompile(`>([0-9]+) active</span>`)
	scheduledFreezeCountPattern  = regexp.MustCompile(`>([0-9]+) windows?</span>`)
	deliveryCountPattern         = regexp.MustCompile(`>([0-9]+) deliver(?:y|ies)</span>`)
	nonzeroDeliveryCountPattern  = regexp.MustCompile(`>[1-9][0-9]* deliver(?:y|ies)</span>`)
	statusResultsPattern         = regexp.MustCompile(`>([0-9]+) decisions?</span>`)
	publicationIntentsPattern    = regexp.MustCompile(`>([0-9]+) status(?:es)?</span>`)
	publicationAttemptsPattern   = regexp.MustCompile(`>([0-9]+) attempts?</span>`)
	activityEventsPattern        = regexp.MustCompile(`>([0-9]+) events?</span>`)
	branchCodePattern            = regexp.MustCompile(`<code class="font-mono text-xs text-text-muted">([^<]+)</code>`)
	activeFreezeReasonPattern    = regexp.MustCompile(`(?s)<td class="px-4 py-3 text-text">\s*([^<]+?)\s*<`)
	activeFreezeStatusPattern    = regexp.MustCompile(`>(Frozen)</span>`)
	scheduledFreezeStatusPattern = regexp.MustCompile(`>(Upcoming|Active|Completed|Cancelled)</span>`)
	scheduleTimeCellPattern      = regexp.MustCompile(`<td class="px-4 py-3 text-text">(?:<time datetime="[^"]*">([^<]+)</time>|<span class="text-text-muted">—</span>)</td>`)
	scheduleSubLinePattern       = regexp.MustCompile(`(?:Ended|Cancelled) <time datetime="[^"]*">([^<]+)</time>`)
	formInputNamePattern         = regexp.MustCompile(`(?i)<input\b[^>]*\bname="([^"]+)"[^>]*>`)
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

func waitUntilContext(t *testing.T, ctx context.Context, deadline time.Time, description string) {
	t.Helper()
	delay := time.Until(deadline)
	if delay <= 0 {
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatalf("context ended while waiting for %s: %v", description, ctx.Err())
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
