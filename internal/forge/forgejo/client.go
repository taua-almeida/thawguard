package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
)

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{BaseURL: baseURL, Token: token}
}

func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, index int) (domain.PullRequest, error) {
	if err := validateGetPullRequest(owner, repo, index); err != nil {
		return domain.PullRequest{}, err
	}
	endpoint, err := c.pullRequestEndpoint(owner, repo, index)
	if err != nil {
		return domain.PullRequest{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.PullRequest{}, fmt.Errorf("create get pull request request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "token "+strings.TrimSpace(c.Token))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return domain.PullRequest{}, fmt.Errorf("get pull request: %w", err)
	}
	return decodePullRequest(resp, c.Token)
}

func (c *Client) ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error) {
	if err := validateListOpenPullRequests(owner, repo, targetBranch); err != nil {
		return nil, err
	}
	const limit = 50
	prs := make([]domain.PullRequest, 0)
	for page := 1; ; page++ {
		endpoint, err := c.pullRequestsEndpoint(owner, repo, targetBranch, page, limit)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("create list pull requests request: %w", err)
		}
		req.Header.Set("Accept", "application/json")
		if strings.TrimSpace(c.Token) != "" {
			req.Header.Set("Authorization", "token "+strings.TrimSpace(c.Token))
		}
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return nil, fmt.Errorf("list open pull requests: %w", err)
		}
		pagePRs, payloadCount, err := decodePullRequestsPage(resp, strings.TrimSpace(targetBranch), c.Token)
		if err != nil {
			return nil, err
		}
		prs = append(prs, pagePRs...)
		if payloadCount < limit {
			break
		}
	}
	return prs, nil
}

func (c *Client) PostCommitStatus(ctx context.Context, owner, repo string, status forge.CommitStatus) error {
	if err := validatePostCommitStatus(owner, repo, status); err != nil {
		return err
	}
	endpoint, err := c.statusEndpoint(owner, repo, status.SHA)
	if err != nil {
		return err
	}
	body, err := json.Marshal(commitStatusRequest{
		State:       string(status.State),
		TargetURL:   status.TargetURL,
		Description: clipDescription(status.Description),
		Context:     status.Context,
	})
	if err != nil {
		return fmt.Errorf("encode commit status request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create commit status request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "token "+strings.TrimSpace(c.Token))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("post commit status: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return responseError("post commit status", resp, c.Token)
	}
	return nil
}

func (c *Client) GetBranchHead(ctx context.Context, owner, repo, branch string) (forge.BranchHead, error) {
	if err := validateBranchHead(owner, repo, branch); err != nil {
		return forge.BranchHead{}, err
	}
	endpoint, err := c.branchEndpoint(owner, repo, branch)
	if err != nil {
		return forge.BranchHead{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return forge.BranchHead{}, fmt.Errorf("create branch head request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "token "+strings.TrimSpace(c.Token))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return forge.BranchHead{}, fmt.Errorf("get branch head: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return forge.BranchHead{}, responseError("get branch head", resp, c.Token)
	}
	var payload branchResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return forge.BranchHead{}, fmt.Errorf("decode branch head response: %w", err)
	}
	payload.Name = strings.TrimSpace(payload.Name)
	if payload.Name == "" || payload.Name != strings.TrimSpace(branch) {
		return forge.BranchHead{}, errors.New("branch head response has an unexpected branch name")
	}
	sha := strings.ToLower(strings.TrimSpace(payload.Commit.ID))
	if sha == "" {
		return forge.BranchHead{}, errors.New("branch head response is missing the commit SHA")
	}
	return forge.BranchHead{Branch: payload.Name, SHA: sha}, nil
}

func (c *Client) ReadBranchProtection(ctx context.Context, owner, repo, branch string) (forge.BranchProtection, error) {
	if err := validateBranchProtection(owner, repo, branch); err != nil {
		return forge.BranchProtection{}, err
	}
	endpoint, err := c.branchProtectionEndpoint(owner, repo, branch)
	if err != nil {
		return forge.BranchProtection{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return forge.BranchProtection{}, fmt.Errorf("create branch protection request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(c.Token) != "" {
		req.Header.Set("Authorization", "token "+strings.TrimSpace(c.Token))
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return forge.BranchProtection{}, fmt.Errorf("read branch protection: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return forge.BranchProtection{Branch: strings.TrimSpace(branch)}, forge.ErrBranchProtectionNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return forge.BranchProtection{}, responseError("read branch protection", resp, c.Token)
	}
	var payload branchProtectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return forge.BranchProtection{}, fmt.Errorf("decode branch protection response: %w", err)
	}
	payload.BranchName = strings.TrimSpace(payload.BranchName)
	if payload.BranchName == "" || payload.BranchName != strings.TrimSpace(branch) {
		return forge.BranchProtection{}, errors.New("branch protection response has an unexpected branch name")
	}
	return forge.BranchProtection{
		Branch:              payload.BranchName,
		Protected:           true,
		RequiresStatusCheck: payload.EnableStatusCheck,
		RequiredContexts:    append([]string(nil), payload.StatusCheckContexts...),
	}, nil
}

var _ forge.Client = (*Client)(nil)

type commitStatusRequest struct {
	State       string `json:"state"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	Context     string `json:"context"`
}

// commitStatusDescriptionMaxRunes is Forgejo's commit status description
// limit. Callers already build descriptions within it, but this client is the
// last boundary before the API, so it clips defensively rather than trusting
// every caller forever.
const commitStatusDescriptionMaxRunes = 255

func clipDescription(description string) string {
	runes := []rune(description)
	if len(runes) <= commitStatusDescriptionMaxRunes {
		return description
	}
	return string(runes[:commitStatusDescriptionMaxRunes-1]) + "…"
}

type pullRequestResponse struct {
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

type branchProtectionResponse struct {
	BranchName          string   `json:"branch_name"`
	EnableStatusCheck   bool     `json:"enable_status_check"`
	StatusCheckContexts []string `json:"status_check_contexts"`
}

type branchResponse struct {
	Name   string `json:"name"`
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
}

func validatePostCommitStatus(owner string, repo string, status forge.CommitStatus) error {
	var missing []string
	if strings.TrimSpace(owner) == "" {
		missing = append(missing, "owner")
	}
	if strings.TrimSpace(repo) == "" {
		missing = append(missing, "repository")
	}
	if strings.TrimSpace(status.SHA) == "" {
		missing = append(missing, "head SHA")
	}
	if strings.TrimSpace(status.Context) == "" {
		missing = append(missing, "context")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required commit status fields: %s", strings.Join(missing, ", "))
	}
	if !validCommitStatusState(status.State) {
		return fmt.Errorf("commit status state is invalid")
	}
	return nil
}

func validateGetPullRequest(owner string, repo string, index int) error {
	var missing []string
	if strings.TrimSpace(owner) == "" {
		missing = append(missing, "owner")
	}
	if strings.TrimSpace(repo) == "" {
		missing = append(missing, "repository")
	}
	if index <= 0 {
		missing = append(missing, "pull request")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required pull request fields: %s", strings.Join(missing, ", "))
	}
	if index > 1_000_000 {
		return fmt.Errorf("pull request number is too large")
	}
	return nil
}

func validateListOpenPullRequests(owner string, repo string, targetBranch string) error {
	var missing []string
	if strings.TrimSpace(owner) == "" {
		missing = append(missing, "owner")
	}
	if strings.TrimSpace(repo) == "" {
		missing = append(missing, "repository")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required pull request list fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

func validateBranchProtection(owner, repo, branch string) error {
	return validateOwnerRepoBranch("branch protection", owner, repo, branch)
}

func validateBranchHead(owner, repo, branch string) error {
	return validateOwnerRepoBranch("branch head", owner, repo, branch)
}

func validateOwnerRepoBranch(kind, owner, repo, branch string) error {
	var missing []string
	if strings.TrimSpace(owner) == "" {
		missing = append(missing, "owner")
	}
	if strings.TrimSpace(repo) == "" {
		missing = append(missing, "repository")
	}
	if strings.TrimSpace(branch) == "" {
		missing = append(missing, "branch")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required %s fields: %s", kind, strings.Join(missing, ", "))
	}
	return nil
}

func validCommitStatusState(state domain.CommitStatusState) bool {
	switch state {
	case domain.CommitStatusSuccess, domain.CommitStatusFailure, domain.CommitStatusPending, domain.CommitStatusError:
		return true
	default:
		return false
	}
}

func (c *Client) statusEndpoint(owner string, repo string, sha string) (string, error) {
	if c == nil {
		return "", errors.New("forgejo client is nil")
	}
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("forgejo base URL is invalid")
	}
	return base.JoinPath("api", "v1", "repos", owner, repo, "statuses", strings.ToLower(strings.TrimSpace(sha))).String(), nil
}

func (c *Client) pullRequestsEndpoint(owner string, repo string, targetBranch string, page int, limit int) (string, error) {
	if c == nil {
		return "", errors.New("forgejo client is nil")
	}
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("forgejo base URL is invalid")
	}
	endpoint := base.JoinPath("api", "v1", "repos", owner, repo, "pulls")
	query := endpoint.Query()
	query.Set("state", "open")
	if targetBranch = strings.TrimSpace(targetBranch); targetBranch != "" {
		query.Set("base", targetBranch)
	}
	query.Set("page", strconv.Itoa(page))
	query.Set("limit", strconv.Itoa(limit))
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

func (c *Client) pullRequestEndpoint(owner string, repo string, index int) (string, error) {
	if c == nil {
		return "", errors.New("forgejo client is nil")
	}
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("forgejo base URL is invalid")
	}
	return base.JoinPath("api", "v1", "repos", owner, repo, "pulls", strconv.Itoa(index)).String(), nil
}

func (c *Client) branchProtectionEndpoint(owner, repo, branch string) (string, error) {
	return c.escapedEndpoint("api", "v1", "repos", owner, repo, "branch_protections", branch)
}

func (c *Client) branchEndpoint(owner, repo, branch string) (string, error) {
	return c.escapedEndpoint("api", "v1", "repos", owner, repo, "branches", branch)
}

// escapedEndpoint escapes every path segment individually so exact owner,
// repository, and branch names (including slashes) cannot change the path.
func (c *Client) escapedEndpoint(segments ...string) (string, error) {
	if c == nil {
		return "", errors.New("forgejo client is nil")
	}
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", errors.New("forgejo base URL is invalid")
	}
	path := strings.TrimRight(base.Path, "/")
	rawPath := strings.TrimRight(base.EscapedPath(), "/")
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		path += "/" + segment
		rawPath += "/" + url.PathEscape(segment)
	}
	base.Path = path
	base.RawPath = rawPath
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func decodePullRequest(resp *http.Response, token string) (domain.PullRequest, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return domain.PullRequest{}, responseError("get pull request", resp, token)
	}
	var payload pullRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return domain.PullRequest{}, fmt.Errorf("decode pull request response: %w", err)
	}
	pr := pullRequestFromResponse(payload)
	if pr.Index <= 0 || pr.TargetBranch == "" || pr.HeadSHA == "" {
		return domain.PullRequest{}, fmt.Errorf("pull request response is missing required fields")
	}
	return pr, nil
}

func decodePullRequestsPage(resp *http.Response, targetBranch, token string) ([]domain.PullRequest, int, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, responseError("list open pull requests", resp, token)
	}
	var payload []pullRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, 0, fmt.Errorf("decode pull requests response: %w", err)
	}
	prs := make([]domain.PullRequest, 0, len(payload))
	for _, item := range payload {
		if targetBranch != "" && strings.TrimSpace(item.Base.Ref) != targetBranch {
			continue
		}
		pr := pullRequestFromResponse(item)
		if pr.Index <= 0 || pr.TargetBranch == "" || pr.HeadSHA == "" {
			return nil, 0, fmt.Errorf("pull request response is missing required fields")
		}
		prs = append(prs, pr)
	}
	return prs, len(payload), nil
}

func pullRequestFromResponse(item pullRequestResponse) domain.PullRequest {
	pr := domain.PullRequest{Index: item.Number, Title: strings.TrimSpace(item.Title), State: strings.ToLower(strings.TrimSpace(item.State)), TargetBranch: strings.TrimSpace(item.Base.Ref), HeadSHA: strings.ToLower(strings.TrimSpace(item.Head.SHA)), URL: strings.TrimSpace(item.HTMLURL)}
	if pr.State == "" {
		pr.State = "open"
	}
	return pr
}

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func responseError(operation string, resp *http.Response, token string) error {
	return &forge.ResponseError{Operation: operation, StatusCode: resp.StatusCode, Status: resp.Status, Snippet: responseSnippet(resp.Body, token)}
}

func responseSnippet(reader io.Reader, token string) string {
	const maxResponseBytes = 512
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes))
	if err != nil {
		return "read response body failed"
	}
	message := strings.TrimSpace(string(data))
	if message == "" {
		return "empty response body"
	}
	if token = strings.TrimSpace(token); token != "" {
		message = strings.ReplaceAll(message, token, "[redacted]")
	}
	return message
}
