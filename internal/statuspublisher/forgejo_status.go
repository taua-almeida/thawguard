package statuspublisher

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

type ForgejoStatusIntentPublisher interface {
	PublishForgejoStatus(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error)
}

type ForgejoStatusAttemptRecorder interface {
	RecordForgejoStatusAttempt(ctx context.Context, publication statuspublication.Publication, result string, errorMessage string) (statuspublication.Attempt, error)
}

type RepositoryGetter interface {
	Get(ctx context.Context, id int64) (domain.Repository, error)
}

type RepositoryStatusTokenGetter interface {
	StatusToken(ctx context.Context, repositoryID int64) (string, bool, error)
}

type ForgeStatusClient interface {
	PostCommitStatus(ctx context.Context, owner, repo string, status forge.CommitStatus) error
}

type ForgeStatusClientFactory func(repository domain.Repository, token string) (ForgeStatusClient, error)

type ForgejoStatusPublisher struct {
	intents      ForgejoStatusIntentPublisher
	attempts     ForgejoStatusAttemptRecorder
	repositories RepositoryGetter
	tokens       RepositoryStatusTokenGetter
	clientFor    ForgeStatusClientFactory
}

var ErrRepositoryStatusTokenMissing = errors.New("repository status token is not configured")

func NewForgejoStatusPublisher(intents ForgejoStatusIntentPublisher, attempts ForgejoStatusAttemptRecorder, repositories RepositoryGetter, tokens RepositoryStatusTokenGetter, clientFor ForgeStatusClientFactory) *ForgejoStatusPublisher {
	return &ForgejoStatusPublisher{intents: intents, attempts: attempts, repositories: repositories, tokens: tokens, clientFor: clientFor}
}

func (p *ForgejoStatusPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	if p == nil || p.intents == nil || p.attempts == nil || p.repositories == nil || p.tokens == nil || p.clientFor == nil {
		return statuspublication.Publication{}, errors.New("forgejo status publisher is not configured")
	}
	publication, err := p.intents.PublishForgejoStatus(ctx, result)
	if err != nil {
		return statuspublication.Publication{}, err
	}
	repo, err := p.repositories.Get(ctx, result.RepositoryID)
	if err != nil {
		return publication, p.recordFailedAttempt(ctx, publication, fmt.Errorf("load repository for status publication: %w", err))
	}
	token, found, err := p.tokens.StatusToken(ctx, result.RepositoryID)
	if err != nil {
		return publication, p.recordFailedAttempt(ctx, publication, fmt.Errorf("load repository status token: %w", err))
	}
	token = strings.TrimSpace(token)
	if !found {
		return publication, p.recordFailedAttempt(ctx, publication, ErrRepositoryStatusTokenMissing)
	}
	if token == "" {
		return publication, p.recordFailedAttempt(ctx, publication, ErrRepositoryStatusTokenMissing)
	}
	client, err := p.clientFor(repo, token)
	if err != nil {
		return publication, p.recordFailedAttempt(ctx, publication, fmt.Errorf("create forgejo status client: %w", err), token)
	}
	if client == nil {
		return publication, p.recordFailedAttempt(ctx, publication, errors.New("create forgejo status client: nil client"))
	}
	status := forge.CommitStatus{SHA: result.HeadSHA, State: result.State, Context: result.Context, Description: result.Description, TargetURL: result.TargetURL}
	if err := client.PostCommitStatus(ctx, repo.Owner, repo.Name, status); err != nil {
		return publication, p.recordFailedAttempt(ctx, publication, fmt.Errorf("post forgejo commit status: %w", err), token)
	}
	if _, err := p.attempts.RecordForgejoStatusAttempt(ctx, publication, statuspublication.AttemptResultPosted, ""); err != nil {
		return publication, fmt.Errorf("record posted forgejo status attempt: %w", err)
	}
	return publication, nil
}

func (p *ForgejoStatusPublisher) recordFailedAttempt(ctx context.Context, publication statuspublication.Publication, cause error, sensitiveValues ...string) error {
	message := attemptErrorMessage(cause, sensitiveValues...)
	if _, err := p.attempts.RecordForgejoStatusAttempt(ctx, publication, statuspublication.AttemptResultFailed, message); err != nil {
		return errors.Join(safePublicationError(cause, sensitiveValues...), fmt.Errorf("record failed forgejo status attempt: %w", err))
	}
	return safePublicationError(cause, sensitiveValues...)
}

func safePublicationError(cause error, sensitiveValues ...string) error {
	if len(sensitiveValues) == 0 {
		return cause
	}
	return errors.New(attemptErrorMessage(cause, sensitiveValues...))
}

func attemptErrorMessage(err error, sensitiveValues ...string) string {
	message := strings.TrimSpace(err.Error())
	for _, sensitive := range sensitiveValues {
		sensitive = strings.TrimSpace(sensitive)
		if sensitive != "" {
			message = strings.ReplaceAll(message, sensitive, "[redacted]")
		}
	}
	if len(message) > 300 {
		message = message[:300]
	}
	if message == "" {
		return "forgejo status publication failed"
	}
	return message
}
