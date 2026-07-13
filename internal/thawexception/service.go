package thawexception

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/jobs"
)

type Service struct {
	db *sql.DB
}

type ApproveSharedHeadParams struct {
	RepositoryID               int64
	SelectedPullRequestIndex   int
	HeadSHA                    string
	Reason                     string
	AffectedPullRequestIndexes []int
	Exceptions                 []ApproveParams
}

func NewService(db *sql.DB) *Service {
	return &Service{db: db}
}

func (s *Service) Approve(ctx context.Context, params ApproveParams, actor domain.Actor) (domain.ThawException, error) {
	if s == nil || s.db == nil {
		return domain.ThawException{}, errors.New("thaw exception service has no database")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.ThawException{}, fmt.Errorf("begin thaw exception approval: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	approved, err := NewStoreTx(tx).Approve(ctx, params, actor)
	if err != nil {
		return domain.ThawException{}, err
	}
	if err := audit.NewStoreTx(tx).Record(ctx, thawExceptionApprovedEvent(approved, actor)); err != nil {
		return domain.ThawException{}, fmt.Errorf("record thaw_exception.approved audit event: %w", err)
	}
	if _, err := jobs.NewStoreTx(tx).EnqueueReconciliation(ctx, approved.RepositoryID); err != nil {
		return domain.ThawException{}, err
	}
	if err := tx.Commit(); err != nil {
		return domain.ThawException{}, fmt.Errorf("commit thaw exception approval: %w", err)
	}
	committed = true
	return approved, nil
}

func (s *Service) ApproveSharedHead(ctx context.Context, params ApproveSharedHeadParams, actor domain.Actor) ([]domain.ThawException, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("thaw exception service has no database")
	}
	params = normalizeApproveSharedHeadParams(params)
	if err := validateApproveSharedHeadParams(params); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin shared-head thaw approval: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	store := NewStoreTx(tx)
	approved := make([]domain.ThawException, 0, len(params.Exceptions))
	created := make([]domain.ThawException, 0, len(params.Exceptions))
	alreadyCovered := make([]domain.ThawException, 0, len(params.Exceptions))
	for _, exceptionParams := range params.Exceptions {
		existing, err := store.ActiveForPullRequest(ctx, domain.PullRequest{RepositoryID: exceptionParams.RepositoryID, Index: exceptionParams.PullRequestIndex, TargetBranch: exceptionParams.TargetBranch, HeadSHA: exceptionParams.HeadSHA})
		if err != nil {
			return nil, err
		}
		if existing != nil {
			approved = append(approved, *existing)
			alreadyCovered = append(alreadyCovered, *existing)
			continue
		}
		exception, err := store.Approve(ctx, exceptionParams, actor)
		if err != nil {
			return nil, err
		}
		approved = append(approved, exception)
		created = append(created, exception)
	}
	if err := audit.NewStoreTx(tx).Record(ctx, thawExceptionSharedHeadApprovedEvent(params, created, alreadyCovered, actor)); err != nil {
		return nil, fmt.Errorf("record thaw_exception.shared_head_approved audit event: %w", err)
	}
	if _, err := jobs.NewStoreTx(tx).EnqueueReconciliation(ctx, params.RepositoryID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit shared-head thaw approval: %w", err)
	}
	committed = true
	return approved, nil
}

func (s *Service) ActiveForPullRequest(ctx context.Context, pr domain.PullRequest) (*domain.ThawException, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("thaw exception service has no database")
	}
	return NewStore(s.db).ActiveForPullRequest(ctx, pr)
}

func thawExceptionApprovedEvent(thaw domain.ThawException, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":         actor.Kind,
		"actor_role":         actor.Role,
		"repository_id":      strconv.FormatInt(thaw.RepositoryID, 10),
		"pull_request_index": strconv.Itoa(thaw.PullRequestIndex),
		"target_branch":      thaw.TargetBranch,
		"head_sha":           thaw.HeadSHA,
		"reason":             thaw.Reason,
		"status":             thaw.Status,
	}
	if thaw.PullRequestURL != "" {
		details["pull_request_url"] = thaw.PullRequestURL
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionThawExceptionApproved,
		SubjectType: audit.SubjectTypeThawException,
		SubjectID:   strconv.FormatInt(thaw.ID, 10),
		DetailsJSON: string(detailsJSON),
	}
}

// thawExceptionSharedHeadApprovedEvent separates the exceptions this approval
// newly created (with the confirmation reason) from exceptions that were
// already active and merely cover the shared head, so the audit trail never
// claims an existing exception was re-approved with the new reason.
func thawExceptionSharedHeadApprovedEvent(params ApproveSharedHeadParams, created []domain.ThawException, alreadyCovered []domain.ThawException, actor domain.Actor) audit.Event {
	details := map[string]string{
		"actor_kind":                           actor.Kind,
		"actor_role":                           actor.Role,
		"repository_id":                        strconv.FormatInt(params.RepositoryID, 10),
		"selected_pull_request_index":          strconv.Itoa(params.SelectedPullRequestIndex),
		"affected_pull_request_indexes":        joinPullRequestIndexes(params.AffectedPullRequestIndexes),
		"created_pull_request_indexes":         joinExceptionPullRequestIndexes(created),
		"already_covered_pull_request_indexes": joinExceptionPullRequestIndexes(alreadyCovered),
		"affected_pull_request_count":          strconv.Itoa(len(params.AffectedPullRequestIndexes)),
		"created_pull_request_count":           strconv.Itoa(len(created)),
		"already_covered_pull_request_count":   strconv.Itoa(len(alreadyCovered)),
		"head_sha":                             params.HeadSHA,
		"reason":                               params.Reason,
		"approval_scope":                       "shared_head",
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte(`{}`)
	}
	return audit.Event{
		ActorUserID: actor.UserID,
		Action:      audit.ActionThawExceptionSharedHeadApproved,
		SubjectType: audit.SubjectTypeThawException,
		SubjectID:   strconv.FormatInt(params.RepositoryID, 10) + ":" + params.HeadSHA,
		DetailsJSON: string(detailsJSON),
	}
}

func normalizeApproveSharedHeadParams(params ApproveSharedHeadParams) ApproveSharedHeadParams {
	params.HeadSHA = strings.ToLower(strings.TrimSpace(params.HeadSHA))
	params.Reason = strings.TrimSpace(params.Reason)
	params.AffectedPullRequestIndexes = append([]int(nil), params.AffectedPullRequestIndexes...)
	sort.Ints(params.AffectedPullRequestIndexes)
	return params
}

func validateApproveSharedHeadParams(params ApproveSharedHeadParams) error {
	if params.RepositoryID <= 0 || params.SelectedPullRequestIndex <= 0 || params.HeadSHA == "" || params.Reason == "" || len(params.AffectedPullRequestIndexes) < 2 {
		return ValidationError{Message: "missing required shared-head thaw approval fields"}
	}
	if len(params.HeadSHA) < 6 || len(params.HeadSHA) > 64 || containsControl(params.HeadSHA) || !isHex(params.HeadSHA) {
		return ValidationError{Message: "head SHA is invalid"}
	}
	if len(params.Reason) > 500 || containsControl(params.Reason) {
		return ValidationError{Message: "reason is invalid"}
	}
	selectedFound := false
	previous := 0
	for _, index := range params.AffectedPullRequestIndexes {
		if index <= 0 || index > 1_000_000 || index == previous {
			return ValidationError{Message: "affected pull request set is invalid"}
		}
		if index == params.SelectedPullRequestIndex {
			selectedFound = true
		}
		previous = index
	}
	if !selectedFound {
		return ValidationError{Message: "selected pull request is not in the affected set"}
	}
	for _, exception := range params.Exceptions {
		normalized := normalizeApproveParams(exception)
		if err := validateApproveParams(normalized); err != nil {
			return err
		}
		if normalized.RepositoryID != params.RepositoryID || normalized.HeadSHA != params.HeadSHA || normalized.Reason != params.Reason || !containsPullRequestIndex(params.AffectedPullRequestIndexes, normalized.PullRequestIndex) {
			return ValidationError{Message: "shared-head thaw exception does not match the confirmed set"}
		}
	}
	return nil
}

func containsPullRequestIndex(indexes []int, target int) bool {
	position := sort.SearchInts(indexes, target)
	return position < len(indexes) && indexes[position] == target
}

func joinExceptionPullRequestIndexes(exceptions []domain.ThawException) string {
	indexes := make([]int, 0, len(exceptions))
	for _, exception := range exceptions {
		indexes = append(indexes, exception.PullRequestIndex)
	}
	sort.Ints(indexes)
	return joinPullRequestIndexes(indexes)
}

func joinPullRequestIndexes(indexes []int) string {
	values := make([]string, 0, len(indexes))
	for _, index := range indexes {
		values = append(values, strconv.Itoa(index))
	}
	return strings.Join(values, ",")
}
