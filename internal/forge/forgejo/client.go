package forgejo

import (
	"context"
	"errors"

	"github.com/calitaz/thawguard/internal/domain"
	"github.com/calitaz/thawguard/internal/forge"
)

var ErrNotImplemented = errors.New("forgejo client not implemented in scaffold")

type Client struct {
	BaseURL string
	Token   string
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
	return ErrNotImplemented
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
