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

type ForgeStatusClient interface {
	PostCommitStatus(ctx context.Context, owner, repo string, status forge.CommitStatus) error
}

type ForgeStatusClientFactory func(repository domain.Repository) (ForgeStatusClient, error)

type ForgejoStatusPublisher struct {
	intents      ForgejoStatusIntentPublisher
	attempts     ForgejoStatusAttemptRecorder
	repositories RepositoryGetter
	clientFor    ForgeStatusClientFactory
}

func NewForgejoStatusPublisher(intents ForgejoStatusIntentPublisher, attempts ForgejoStatusAttemptRecorder, repositories RepositoryGetter, clientFor ForgeStatusClientFactory) *ForgejoStatusPublisher {
	return &ForgejoStatusPublisher{intents: intents, attempts: attempts, repositories: repositories, clientFor: clientFor}
}

func (p *ForgejoStatusPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	if p == nil || p.intents == nil || p.attempts == nil || p.repositories == nil || p.clientFor == nil {
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
	client, err := p.clientFor(repo)
	if err != nil {
		return publication, p.recordFailedAttempt(ctx, publication, fmt.Errorf("create forgejo status client: %w", err))
	}
	if client == nil {
		return publication, p.recordFailedAttempt(ctx, publication, errors.New("create forgejo status client: nil client"))
	}
	status := forge.CommitStatus{SHA: result.HeadSHA, State: result.State, Context: result.Context, Description: result.Description, TargetURL: result.TargetURL}
	if err := client.PostCommitStatus(ctx, repo.Owner, repo.Name, status); err != nil {
		return publication, p.recordFailedAttempt(ctx, publication, fmt.Errorf("post forgejo commit status: %w", err))
	}
	if _, err := p.attempts.RecordForgejoStatusAttempt(ctx, publication, statuspublication.AttemptResultPosted, ""); err != nil {
		return publication, fmt.Errorf("record posted forgejo status attempt: %w", err)
	}
	return publication, nil
}

func (p *ForgejoStatusPublisher) recordFailedAttempt(ctx context.Context, publication statuspublication.Publication, cause error) error {
	message := attemptErrorMessage(cause)
	if _, err := p.attempts.RecordForgejoStatusAttempt(ctx, publication, statuspublication.AttemptResultFailed, message); err != nil {
		return errors.Join(cause, fmt.Errorf("record failed forgejo status attempt: %w", err))
	}
	return cause
}

func attemptErrorMessage(err error) string {
	message := strings.TrimSpace(err.Error())
	if len(message) > 300 {
		message = message[:300]
	}
	if message == "" {
		return "forgejo status publication failed"
	}
	return message
}
