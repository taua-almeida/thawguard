package webhook

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

type PullRequestEvent struct {
	Action         string
	Forge          string
	BaseURL        string
	Owner          string
	RepositoryName string
	PullRequest    domain.PullRequest
}

type PullRequestProcessResult struct {
	Event         PullRequestEvent
	Repository    domain.Repository
	PullRequest   domain.PullRequest
	StatusResults []statusresult.Result
	Publications  []statuspublication.Publication
	Recomputed    bool
}

type RepositoryFinder interface {
	FindActiveByRemote(ctx context.Context, params repository.RemoteParams) (domain.Repository, bool, error)
}

type PullRequestCache interface {
	Get(ctx context.Context, repositoryID int64, index int) (domain.PullRequest, error)
	Upsert(ctx context.Context, pr domain.PullRequest) (domain.PullRequest, error)
	ListOpenByHead(ctx context.Context, repositoryID int64, headSHA string) ([]domain.PullRequest, error)
}

type StatusRunner interface {
	RunForSharedHead(ctx context.Context, prs []domain.PullRequest, preferredIndex int) (statusresult.Result, error)
}

type StatusPublisher interface {
	Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error)
}

type PullRequestProcessor struct {
	repositories RepositoryFinder
	cache        PullRequestCache
	statuses     StatusRunner
	publisher    StatusPublisher
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

func NewPullRequestProcessor(repositories RepositoryFinder, cache PullRequestCache, statuses StatusRunner, publisher StatusPublisher) *PullRequestProcessor {
	return &PullRequestProcessor{repositories: repositories, cache: cache, statuses: statuses, publisher: publisher}
}

func (p *PullRequestProcessor) Process(ctx context.Context, body []byte) (PullRequestProcessResult, error) {
	if p == nil || p.repositories == nil || p.cache == nil || p.statuses == nil || p.publisher == nil {
		return PullRequestProcessResult{}, errors.New("pull request processor is not configured")
	}
	event, err := ParsePullRequestEvent(body)
	if err != nil {
		return PullRequestProcessResult{}, err
	}
	repo, found, err := p.repositories.FindActiveByRemote(ctx, repository.RemoteParams{Forge: event.Forge, BaseURL: event.BaseURL, Owner: event.Owner, Name: event.RepositoryName})
	if err != nil {
		return PullRequestProcessResult{}, fmt.Errorf("find webhook repository: %w", err)
	}
	if !found {
		return PullRequestProcessResult{}, ValidationError{Message: "repository is not configured for this webhook"}
	}

	pr := event.PullRequest
	pr.RepositoryID = repo.ID
	// Before enforcement activation a verified webhook still refreshes the PR
	// cache as setup evidence, but no status is recomputed or published and no
	// publication attempt is recorded.
	if !repo.EnforcementActive() {
		cached, err := p.cache.Upsert(ctx, pr)
		if err != nil {
			return PullRequestProcessResult{}, err
		}
		return PullRequestProcessResult{Event: event, Repository: repo, PullRequest: cached}, nil
	}
	previous, previousFound, err := p.previousPullRequest(ctx, repo.ID, pr.Index)
	if err != nil {
		return PullRequestProcessResult{}, err
	}
	plans, err := p.recomputePlans(ctx, repo.ID, pr, previous, previousFound)
	if err != nil {
		return PullRequestProcessResult{}, err
	}
	results, publications, err := p.recomputeAndPublish(ctx, plans)
	if err != nil {
		return PullRequestProcessResult{}, err
	}
	cached, err := p.cache.Upsert(ctx, pr)
	if err != nil {
		return PullRequestProcessResult{}, err
	}
	if len(results) == 0 {
		return PullRequestProcessResult{Event: event, Repository: repo, PullRequest: cached}, nil
	}

	return PullRequestProcessResult{Event: event, Repository: repo, PullRequest: cached, StatusResults: results, Publications: publications, Recomputed: true}, nil
}

func (p *PullRequestProcessor) previousPullRequest(ctx context.Context, repositoryID int64, index int) (domain.PullRequest, bool, error) {
	previous, err := p.cache.Get(ctx, repositoryID, index)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.PullRequest{}, false, nil
		}
		return domain.PullRequest{}, false, err
	}
	return previous, true, nil
}

type recomputePlan struct {
	PullRequests   []domain.PullRequest
	PreferredIndex int
}

func (p *PullRequestProcessor) recomputePlans(ctx context.Context, repositoryID int64, current domain.PullRequest, previous domain.PullRequest, previousFound bool) ([]recomputePlan, error) {
	plans := make([]recomputePlan, 0, 2)
	if prs, err := p.openPullRequestsForHead(ctx, repositoryID, current.HeadSHA, current); err != nil {
		return nil, err
	} else if len(prs) > 0 {
		plans = append(plans, recomputePlan{PullRequests: prs, PreferredIndex: current.Index})
	}
	if previousFound && previous.IsOpen() && previous.HeadSHA != current.HeadSHA {
		if prs, err := p.openPullRequestsForHead(ctx, repositoryID, previous.HeadSHA, current); err != nil {
			return nil, err
		} else if len(prs) > 0 {
			plans = append(plans, recomputePlan{PullRequests: prs, PreferredIndex: previous.Index})
		}
	}
	return plans, nil
}

func (p *PullRequestProcessor) openPullRequestsForHead(ctx context.Context, repositoryID int64, headSHA string, current domain.PullRequest) ([]domain.PullRequest, error) {
	openPRs, err := p.cache.ListOpenByHead(ctx, repositoryID, headSHA)
	if err != nil {
		return nil, err
	}
	filtered := make([]domain.PullRequest, 0, len(openPRs)+1)
	for _, pr := range openPRs {
		if pr.Index == current.Index {
			continue
		}
		filtered = append(filtered, pr)
	}
	if current.IsOpen() && current.HeadSHA == headSHA {
		filtered = append(filtered, current)
	}
	return filtered, nil
}

func (p *PullRequestProcessor) recomputeAndPublish(ctx context.Context, plans []recomputePlan) ([]statusresult.Result, []statuspublication.Publication, error) {
	results := make([]statusresult.Result, 0, len(plans))
	publications := make([]statuspublication.Publication, 0, len(plans))
	for _, plan := range plans {
		status, err := p.statuses.RunForSharedHead(ctx, plan.PullRequests, plan.PreferredIndex)
		if err != nil {
			return nil, nil, err
		}
		publication, err := p.publisher.Publish(ctx, status)
		if err != nil {
			return nil, nil, err
		}
		results = append(results, status)
		publications = append(publications, publication)
	}
	return results, publications, nil
}

func ParsePullRequestEvent(body []byte) (PullRequestEvent, error) {
	var payload pullRequestPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return PullRequestEvent{}, fmt.Errorf("parse pull request webhook: %w", err)
	}

	owner := strings.TrimSpace(payload.Repository.Owner.Login)
	if owner == "" {
		owner = ownerFromFullName(payload.Repository.FullName)
	}
	baseURL := remoteBaseURL(payload.Repository.CloneURL)
	if baseURL == "" {
		baseURL = remoteBaseURL(payload.PullRequest.HTMLURL)
	}
	event := PullRequestEvent{
		Action:         strings.TrimSpace(payload.Action),
		Forge:          "forgejo",
		BaseURL:        baseURL,
		Owner:          owner,
		RepositoryName: strings.TrimSpace(payload.Repository.Name),
		PullRequest: domain.PullRequest{
			Index:        payload.PullRequest.Number,
			Title:        strings.TrimSpace(payload.PullRequest.Title),
			State:        strings.ToLower(strings.TrimSpace(payload.PullRequest.State)),
			TargetBranch: strings.TrimSpace(payload.PullRequest.Base.Ref),
			HeadSHA:      strings.ToLower(strings.TrimSpace(payload.PullRequest.Head.SHA)),
			URL:          strings.TrimSpace(payload.PullRequest.HTMLURL),
		},
	}
	if err := validatePullRequestEvent(event); err != nil {
		return PullRequestEvent{}, err
	}
	return event, nil
}

type pullRequestPayload struct {
	Action     string `json:"action"`
	Repository struct {
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
	PullRequest struct {
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
	} `json:"pull_request"`
}

func validatePullRequestEvent(event PullRequestEvent) error {
	var missing []string
	if event.Action == "" {
		missing = append(missing, "action")
	}
	if event.BaseURL == "" {
		missing = append(missing, "repository base URL")
	}
	if event.Owner == "" {
		missing = append(missing, "repository owner")
	}
	if event.RepositoryName == "" {
		missing = append(missing, "repository name")
	}
	if event.PullRequest.Index <= 0 {
		missing = append(missing, "pull request")
	}
	if event.PullRequest.TargetBranch == "" {
		missing = append(missing, "target branch")
	}
	if event.PullRequest.HeadSHA == "" {
		missing = append(missing, "head SHA")
	}
	if len(missing) > 0 {
		return ValidationError{Message: fmt.Sprintf("missing required pull request webhook fields: %s", strings.Join(missing, ", "))}
	}
	return nil
}

func ownerFromFullName(fullName string) string {
	parts := strings.SplitN(strings.TrimSpace(fullName), "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func remoteBaseURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}
