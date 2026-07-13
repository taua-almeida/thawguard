package setupcheck

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/webhook"
)

const webhookFreshness = 24 * time.Hour

type TokenProvider interface {
	StatusToken(ctx context.Context, repositoryID int64) (string, bool, error)
}

type WebhookEvidenceStore interface {
	LatestVerifiedPullRequestByRepository(ctx context.Context, repositoryID int64) (webhook.Delivery, bool, error)
}

type InspectorFactory func(repo domain.Repository, token string) (Inspector, error)

type Service struct {
	db           *sql.DB
	tokens       TokenProvider
	deliveries   WebhookEvidenceStore
	newInspector InspectorFactory
	now          func() time.Time
}

type branchRun struct {
	branch     domain.RepositoryBranch
	inspection BranchInspection
	valid      bool
}

func NewReadinessService(db *sql.DB, tokens TokenProvider, deliveries WebhookEvidenceStore, factory InspectorFactory) *Service {
	return &Service{
		db:           db,
		tokens:       tokens,
		deliveries:   deliveries,
		newInspector: factory,
		now:          func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) Run(ctx context.Context, repo domain.Repository) ([]Result, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("readiness service has no database")
	}
	if s.deliveries == nil {
		return nil, errors.New("readiness service has no webhook evidence store")
	}
	now := s.now().UTC()
	branches, err := repository.NewStore(s.db).ListBranches(ctx, repo.ID)
	if err != nil {
		return nil, fmt.Errorf("list managed branches for readiness: %w", err)
	}
	if len(branches) == 0 {
		return nil, errors.New("repository has no managed branches")
	}

	webhookResult, webhookFresh, err := s.webhookResult(ctx, repo.ID, now)
	if err != nil {
		return nil, err
	}
	repositoryResults := []Result{statusTokenResult(repo.HasStatusToken)}
	branchRuns := make([]branchRun, 0, len(branches))

	token, found, err := s.loadToken(ctx, repo)
	if err != nil {
		return nil, err
	}
	repositoryResults[0] = statusTokenResult(found)
	if !found {
		repositoryResults = append(repositoryResults, tokenRequiredPullRequestResult(), webhookResult, statusPostingUntestedResult())
		for _, branch := range branches {
			branchRuns = append(branchRuns, branchRun{branch: branch, inspection: tokenRequiredBranchInspection(branch.Name)})
		}
	} else {
		if s.newInspector == nil {
			return nil, errors.New("readiness service has no forge inspector factory")
		}
		inspector, err := s.newInspector(repo, token)
		if err != nil {
			return nil, sanitizedTokenError("create forge readiness inspector", err, token)
		}
		if inspector == nil {
			return nil, errors.New("forge readiness inspector is nil")
		}
		pullRequestResult, err := inspector.InspectPullRequestRead(ctx, repo, branches[0].Name)
		if err != nil {
			return nil, sanitizedTokenError("inspect pull request read access", err, token)
		}
		repositoryResults = append(repositoryResults, pullRequestResult, webhookResult, statusPostingUntestedResult())
		for _, branch := range branches {
			inspection, err := inspector.InspectBranch(ctx, repo, branch.Name)
			if err != nil {
				return nil, sanitizedTokenError("inspect managed branch", err, token)
			}
			if err := validateBranchInspection(inspection); err != nil {
				return nil, err
			}
			branchRuns = append(branchRuns, branchRun{branch: branch, inspection: inspection, valid: true})
		}
	}

	if err := s.persistRun(ctx, repo, repositoryResults, branchRuns, webhookFresh, now); err != nil {
		return nil, err
	}
	results := append([]Result(nil), repositoryResults...)
	for _, run := range branchRuns {
		results = append(results, run.inspection.Results...)
	}
	return results, nil
}

func (s *Service) loadToken(ctx context.Context, repo domain.Repository) (string, bool, error) {
	if !repo.HasStatusToken {
		return "", false, nil
	}
	if s.tokens == nil {
		return "", false, errors.New("readiness service has no token provider")
	}
	token, found, err := s.tokens.StatusToken(ctx, repo.ID)
	if err != nil {
		return "", false, fmt.Errorf("load repository status token: %w", err)
	}
	if !found {
		return "", false, nil
	}
	if strings.TrimSpace(token) == "" {
		return "", false, errors.New("decrypted repository status token is empty")
	}
	return token, true, nil
}

func (s *Service) webhookResult(ctx context.Context, repositoryID int64, now time.Time) (Result, bool, error) {
	delivery, found, err := s.deliveries.LatestVerifiedPullRequestByRepository(ctx, repositoryID)
	if err != nil {
		return Result{}, false, fmt.Errorf("load verified pull request webhook evidence: %w", err)
	}
	if !found {
		return Result{
			Name:        CheckRecentVerifiedPullRequestWebhook,
			Status:      StatusFailed,
			Description: "No verified pull_request webhook delivery has been recorded for this repository.",
			Remediation: "Send a signed pull_request webhook to /webhooks/forgejo with the configured repository secret.",
		}, false, nil
	}
	if delivery.ReceivedAt.Before(now.Add(-webhookFreshness)) {
		return Result{
			Name:        CheckRecentVerifiedPullRequestWebhook,
			Status:      StatusWarning,
			Description: "The latest verified pull_request webhook delivery is stale (older than 24 hours).",
			Remediation: "Confirm the forge webhook is enabled and deliver a current signed pull_request event.",
		}, false, nil
	}
	return Result{
		Name:        CheckRecentVerifiedPullRequestWebhook,
		Status:      StatusOK,
		Description: "A verified pull_request webhook delivery was received within the last 24 hours.",
	}, true, nil
}

func (s *Service) persistRun(ctx context.Context, repo domain.Repository, repositoryResults []Result, branches []branchRun, webhookFresh bool, checkedAt time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin readiness persistence: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	checkedAt, err = nextRunTimestamp(ctx, tx, repo.ID, checkedAt)
	if err != nil {
		return err
	}

	store := NewStore(s.db)
	if err := store.recordNoTx(ctx, tx, repo.ID, "", repositoryResults, checkedAt); err != nil {
		return err
	}
	repositoryStore := repository.NewStoreTx(tx)
	drifted := make([]string, 0)
	allResults := append([]Result(nil), repositoryResults...)
	for _, run := range branches {
		if err := store.recordNoTx(ctx, tx, repo.ID, run.branch.Name, run.inspection.Results, checkedAt); err != nil {
			return err
		}
		allResults = append(allResults, run.inspection.Results...)
		if !run.valid {
			continue
		}
		setupStatus := "unknown"
		if allOK(run.inspection.Results) {
			setupStatus = "ok"
		}
		if run.branch.SetupStatus == "ok" && setupStatus != "ok" {
			drifted = append(drifted, run.branch.Name)
		}
		if err := repositoryStore.UpdateBranchReadiness(ctx, repo.ID, run.branch.Name, run.inspection.Protected, setupStatus, checkedAt); err != nil {
			return err
		}
	}
	okCount, warningCount, failedCount := resultCounts(allResults)
	if repo.EnforcementState == domain.EnforcementActive && failedCount > 0 {
		if _, err := repositoryStore.SetEnforcementState(ctx, repo.ID, domain.EnforcementUnhealthy); err != nil {
			return err
		}
		// The stored failure keeps the repository page truthful about why
		// enforcement became unhealthy; only the explicit recovery action
		// clears it.
		if _, err := repositoryStore.SetEnforcementFailure(ctx, repo.ID, domain.EnforcementFailureReadinessChecks, checkedAt); err != nil {
			return err
		}
	}

	auditStore := audit.NewStoreTx(tx)
	if err := auditStore.Record(ctx, setupCheckRunEvent(repo.ID, len(branches), okCount, warningCount, failedCount, webhookFresh)); err != nil {
		return fmt.Errorf("record repository.setup_check_run audit event: %w", err)
	}
	if len(drifted) > 0 {
		if err := auditStore.Record(ctx, setupDriftEvent(repo.ID, drifted)); err != nil {
			return fmt.Errorf("record repository.setup_drift_detected audit event: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit readiness persistence: %w", err)
	}
	committed = true
	return nil
}

func nextRunTimestamp(ctx context.Context, tx *sql.Tx, repositoryID int64, proposed time.Time) (time.Time, error) {
	var latestText sql.NullString
	if err := tx.QueryRowContext(ctx, `
SELECT checked_at
FROM setup_checks
WHERE repository_id = ?
ORDER BY checked_at DESC, id DESC
LIMIT 1`, repositoryID).Scan(&latestText); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("load latest readiness timestamp: %w", err)
	}
	proposed = proposed.UTC()
	if !latestText.Valid {
		return proposed, nil
	}
	latest, err := time.Parse(setupCheckTimeFormat, latestText.String)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse latest readiness timestamp: %w", err)
	}
	if !proposed.After(latest) {
		return latest.Add(time.Nanosecond), nil
	}
	return proposed, nil
}

func statusTokenResult(configured bool) Result {
	result := Result{
		Name:        CheckStatusTokenConfigured,
		Status:      StatusFromBool(configured),
		Description: "An encrypted per-repository status token must be stored before forge readiness can be checked.",
		Remediation: "Store the repository status token using the encrypted credential form.",
	}
	if configured {
		result.Description = "Encrypted status token material is configured for this repository."
		result.Remediation = ""
	}
	return result
}

func tokenRequiredPullRequestResult() Result {
	return Result{Name: CheckPullRequestReadAccess, Status: StatusFailed, Description: "Pull request read access was not checked because no encrypted status token is configured.", Remediation: "Store a repository status token with pull request read access."}
}

func tokenRequiredBranchInspection(branch string) BranchInspection {
	description := "Forge branch readiness was not checked because no encrypted status token is configured."
	remediation := "Store a repository status token, then rerun readiness checks for " + branch + "."
	return BranchInspection{Results: []Result{
		{Name: CheckBranchProtectionReadable, Status: StatusFailed, Description: description, Remediation: remediation},
		{Name: CheckBranchProtectionEnabled, Status: StatusFailed, Description: description, Remediation: remediation},
		{Name: CheckRequiredStatusChecksEnabled, Status: StatusFailed, Description: description, Remediation: remediation},
		{Name: CheckRequiredThawguardFreezeContextConfigured, Status: StatusFailed, Description: description, Remediation: remediation},
	}}
}

func statusPostingUntestedResult() Result {
	return Result{
		Name:        CheckStatusPostingUntested,
		Status:      StatusWarning,
		Description: "This read-only readiness run did not post a commit status, so status-post permission remains unverified.",
		Remediation: "Activation requires a later controlled status-post test before enforcement can become ready or active.",
	}
}

func validateBranchInspection(inspection BranchInspection) error {
	if len(inspection.Results) != 4 {
		return errors.New("branch readiness inspection did not return all required checks")
	}
	if err := validateRecordParams(1, inspection.Results); err != nil {
		return fmt.Errorf("invalid branch readiness result: %w", err)
	}
	return nil
}

func allOK(results []Result) bool {
	if len(results) == 0 {
		return false
	}
	for _, result := range results {
		if result.Status != StatusOK {
			return false
		}
	}
	return true
}

func resultCounts(results []Result) (ok, warning, failed int) {
	for _, result := range results {
		switch result.Status {
		case StatusOK:
			ok++
		case StatusWarning:
			warning++
		case StatusFailed:
			failed++
		}
	}
	return ok, warning, failed
}

func setupCheckRunEvent(repositoryID int64, branchCount, okCount, warningCount, failedCount int, webhookFresh bool) audit.Event {
	details, _ := json.Marshal(map[string]any{
		"repository_id":          repositoryID,
		"managed_branch_count":   branchCount,
		"ok_count":               okCount,
		"warning_count":          warningCount,
		"failed_count":           failedCount,
		"webhook_evidence_fresh": webhookFresh,
	})
	return audit.Event{Action: audit.ActionRepositorySetupCheckRun, SubjectType: audit.SubjectTypeRepository, SubjectID: strconv.FormatInt(repositoryID, 10), DetailsJSON: string(details)}
}

func setupDriftEvent(repositoryID int64, branches []string) audit.Event {
	details, _ := json.Marshal(map[string]any{
		"repository_id":    repositoryID,
		"branches":         branches,
		"drifted_branches": len(branches),
	})
	return audit.Event{Action: audit.ActionRepositorySetupDriftDetected, SubjectType: audit.SubjectTypeRepository, SubjectID: strconv.FormatInt(repositoryID, 10), DetailsJSON: string(details)}
}

func sanitizedTokenError(operation string, err error, token string) error {
	message := err.Error()
	if token = strings.TrimSpace(token); token != "" {
		message = strings.ReplaceAll(message, token, "[redacted]")
	}
	return fmt.Errorf("%s: %s", operation, message)
}
