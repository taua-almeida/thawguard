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
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
)

var ErrNotImplemented = errors.New("forgejo client not implemented in scaffold")

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
}

func New(baseURL, token string) *Client {
	return &Client{BaseURL: baseURL, Token: token}
}

func (c *Client) GetPullRequest(ctx context.Context, owner, repo string, index int) (domain.PullRequest, error) {
	return domain.PullRequest{}, ErrNotImplemented
}

func (c *Client) ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error) {
	return nil, ErrNotImplemented
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
		Description: status.Description,
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
		return fmt.Errorf("post commit status: forge returned %s: %s", resp.Status, responseSnippet(resp.Body))
	}
	return nil
}

func (c *Client) ReadBranchProtection(ctx context.Context, owner, repo, branch string) (forge.BranchProtection, error) {
	return forge.BranchProtection{}, ErrNotImplemented
}

func (c *Client) UpsertRequiredStatusContext(ctx context.Context, owner, repo, branch, contextName string) error {
	return ErrNotImplemented
}

func (c *Client) VerifyCapabilities(ctx context.Context, owner, repo string) (forge.CapabilityReport, error) {
	return forge.CapabilityReport{}, ErrNotImplemented
}

var _ forge.Client = (*Client)(nil)

type commitStatusRequest struct {
	State       string `json:"state"`
	TargetURL   string `json:"target_url,omitempty"`
	Description string `json:"description,omitempty"`
	Context     string `json:"context"`
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

func (c *Client) httpClient() *http.Client {
	if c != nil && c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func responseSnippet(reader io.Reader) string {
	const maxResponseBytes = 512
	data, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes))
	if err != nil {
		return "read response body failed"
	}
	message := strings.TrimSpace(string(data))
	if message == "" {
		return "empty response body"
	}
	return message
}
