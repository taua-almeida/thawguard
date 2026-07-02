package statuspublisher

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

func TestForgejoStatusPublisherPostsAndRecordsAttempt(t *testing.T) {
	ctx := context.Background()
	result := forgejoPublisherResult()
	publication := forgejoPublisherPublication(result)
	intents := &fakeForgejoIntentPublisher{publication: publication}
	attempts := &fakeForgejoAttemptRecorder{}
	repositories := &fakeRepositoryGetter{repository: domain.Repository{ID: result.RepositoryID, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeRepositoryStatusTokenGetter{token: "live-status-token", found: true}
	client := &fakeForgeStatusClient{}
	publisher := NewForgejoStatusPublisher(intents, attempts, repositories, tokens, func(repository domain.Repository, token string) (ForgeStatusClient, error) {
		if token != "live-status-token" {
			t.Fatalf("expected decrypted status token, got %q", token)
		}
		return client, nil
	})

	got, err := publisher.Publish(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != publication.ID || got.DeliveryMode != statuspublication.DeliveryModeForgejoStatus {
		t.Fatalf("unexpected publication %+v", got)
	}
	if len(client.calls) != 1 {
		t.Fatalf("expected one forge status post, got %+v", client.calls)
	}
	call := client.calls[0]
	if call.owner != "taua-almeida" || call.repo != "thawguard" || call.status.SHA != result.HeadSHA || call.status.State != result.State || call.status.Context != result.Context {
		t.Fatalf("unexpected forge call %+v", call)
	}
	if len(attempts.attempts) != 1 || attempts.attempts[0].result != statuspublication.AttemptResultPosted || attempts.attempts[0].errorMessage != "" {
		t.Fatalf("expected posted attempt, got %+v", attempts.attempts)
	}
}

func TestForgejoStatusPublisherRecordsFailedAttempt(t *testing.T) {
	ctx := context.Background()
	result := forgejoPublisherResult()
	publication := forgejoPublisherPublication(result)
	postErr := errors.New("forge returned 500")
	intents := &fakeForgejoIntentPublisher{publication: publication}
	attempts := &fakeForgejoAttemptRecorder{}
	repositories := &fakeRepositoryGetter{repository: domain.Repository{ID: result.RepositoryID, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeRepositoryStatusTokenGetter{token: "live-status-token", found: true}
	client := &fakeForgeStatusClient{err: postErr}
	publisher := NewForgejoStatusPublisher(intents, attempts, repositories, tokens, func(repository domain.Repository, token string) (ForgeStatusClient, error) { return client, nil })

	got, err := publisher.Publish(ctx, result)
	if err == nil || !strings.Contains(err.Error(), postErr.Error()) {
		t.Fatalf("expected post error, got %v", err)
	}
	if got.ID != publication.ID {
		t.Fatalf("expected publication returned with error, got %+v", got)
	}
	if len(attempts.attempts) != 1 || attempts.attempts[0].result != statuspublication.AttemptResultFailed || attempts.attempts[0].errorMessage == "" {
		t.Fatalf("expected failed attempt, got %+v", attempts.attempts)
	}
}

func TestForgejoStatusPublisherRequiresConfiguration(t *testing.T) {
	if _, err := NewForgejoStatusPublisher(nil, nil, nil, nil, nil).Publish(context.Background(), statusresult.Result{}); err == nil {
		t.Fatal("expected configuration error")
	}
}

func TestForgejoStatusPublisherRecordsMissingStatusToken(t *testing.T) {
	ctx := context.Background()
	result := forgejoPublisherResult()
	publication := forgejoPublisherPublication(result)
	intents := &fakeForgejoIntentPublisher{publication: publication}
	attempts := &fakeForgejoAttemptRecorder{}
	repositories := &fakeRepositoryGetter{repository: domain.Repository{ID: result.RepositoryID, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeRepositoryStatusTokenGetter{found: false}
	client := &fakeForgeStatusClient{}
	publisher := NewForgejoStatusPublisher(intents, attempts, repositories, tokens, func(repository domain.Repository, token string) (ForgeStatusClient, error) { return client, nil })

	got, err := publisher.Publish(ctx, result)
	if !errors.Is(err, ErrRepositoryStatusTokenMissing) {
		t.Fatalf("expected missing status token error, got %v", err)
	}
	if got.ID != publication.ID {
		t.Fatalf("expected publication returned with error, got %+v", got)
	}
	if len(client.calls) != 0 {
		t.Fatalf("expected no forge status post without token, got %+v", client.calls)
	}
	if len(attempts.attempts) != 1 || attempts.attempts[0].result != statuspublication.AttemptResultFailed || attempts.attempts[0].errorMessage != ErrRepositoryStatusTokenMissing.Error() {
		t.Fatalf("expected failed missing-token attempt, got %+v", attempts.attempts)
	}
}

func TestForgejoStatusPublisherRecordsEmptyStatusTokenAsMissing(t *testing.T) {
	ctx := context.Background()
	result := forgejoPublisherResult()
	publication := forgejoPublisherPublication(result)
	intents := &fakeForgejoIntentPublisher{publication: publication}
	attempts := &fakeForgejoAttemptRecorder{}
	repositories := &fakeRepositoryGetter{repository: domain.Repository{ID: result.RepositoryID, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeRepositoryStatusTokenGetter{token: "   ", found: true}
	client := &fakeForgeStatusClient{}
	publisher := NewForgejoStatusPublisher(intents, attempts, repositories, tokens, func(repository domain.Repository, token string) (ForgeStatusClient, error) { return client, nil })

	if _, err := publisher.Publish(ctx, result); !errors.Is(err, ErrRepositoryStatusTokenMissing) {
		t.Fatalf("expected missing status token error, got %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("expected no forge status post with empty token, got %+v", client.calls)
	}
	if len(attempts.attempts) != 1 || attempts.attempts[0].result != statuspublication.AttemptResultFailed || attempts.attempts[0].errorMessage != ErrRepositoryStatusTokenMissing.Error() {
		t.Fatalf("expected failed empty-token attempt, got %+v", attempts.attempts)
	}
}

func TestForgejoStatusPublisherRedactsStatusTokenFromFailedAttempt(t *testing.T) {
	ctx := context.Background()
	result := forgejoPublisherResult()
	publication := forgejoPublisherPublication(result)
	intents := &fakeForgejoIntentPublisher{publication: publication}
	attempts := &fakeForgejoAttemptRecorder{}
	repositories := &fakeRepositoryGetter{repository: domain.Repository{ID: result.RepositoryID, Forge: "forgejo", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeRepositoryStatusTokenGetter{token: "live-status-token", found: true}
	client := &fakeForgeStatusClient{err: errors.New("forge response mentioned live-status-token")}
	publisher := NewForgejoStatusPublisher(intents, attempts, repositories, tokens, func(repository domain.Repository, token string) (ForgeStatusClient, error) { return client, nil })

	if _, err := publisher.Publish(ctx, result); err == nil {
		t.Fatal("expected post error")
	} else if strings.Contains(err.Error(), "live-status-token") {
		t.Fatalf("expected returned error not to contain token, got %v", err)
	}
	if len(attempts.attempts) != 1 {
		t.Fatalf("expected one failed attempt, got %+v", attempts.attempts)
	}
	if attempts.attempts[0].errorMessage == "" {
		t.Fatalf("expected sanitized failed attempt message, got %+v", attempts.attempts)
	}
	if strings.Contains(attempts.attempts[0].errorMessage, "live-status-token") {
		t.Fatalf("expected token to be redacted from attempt error, got %q", attempts.attempts[0].errorMessage)
	}
}

func forgejoPublisherResult() statusresult.Result {
	return statusresult.Result{ID: 7, RepositoryID: 1, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"}
}

func forgejoPublisherPublication(result statusresult.Result) statuspublication.Publication {
	return statuspublication.Publication{ID: 9, StatusResultID: result.ID, RepositoryID: result.RepositoryID, PullRequestIndex: result.PullRequestIndex, TargetBranch: result.TargetBranch, HeadSHA: result.HeadSHA, Context: result.Context, State: result.State, Description: result.Description, DeliveryMode: statuspublication.DeliveryModeForgejoStatus}
}

type fakeForgejoIntentPublisher struct {
	publication statuspublication.Publication
	results     []statusresult.Result
	err         error
}

func (p *fakeForgejoIntentPublisher) PublishForgejoStatus(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	p.results = append(p.results, result)
	if p.err != nil {
		return statuspublication.Publication{}, p.err
	}
	return p.publication, nil
}

type fakeForgejoAttemptRecorder struct {
	attempts []fakeForgejoAttempt
	err      error
}

type fakeForgejoAttempt struct {
	publication  statuspublication.Publication
	result       string
	errorMessage string
}

func (r *fakeForgejoAttemptRecorder) RecordForgejoStatusAttempt(ctx context.Context, publication statuspublication.Publication, result string, errorMessage string) (statuspublication.Attempt, error) {
	r.attempts = append(r.attempts, fakeForgejoAttempt{publication: publication, result: result, errorMessage: errorMessage})
	if r.err != nil {
		return statuspublication.Attempt{}, r.err
	}
	return statuspublication.Attempt{ID: int64(len(r.attempts)), PublicationID: publication.ID, Result: result, Error: errorMessage}, nil
}

type fakeRepositoryGetter struct {
	repository domain.Repository
	err        error
}

type fakeRepositoryStatusTokenGetter struct {
	token string
	found bool
	err   error
}

func (g *fakeRepositoryStatusTokenGetter) StatusToken(ctx context.Context, repositoryID int64) (string, bool, error) {
	if g.err != nil {
		return "", false, g.err
	}
	return g.token, g.found, nil
}

func (g *fakeRepositoryGetter) Get(ctx context.Context, id int64) (domain.Repository, error) {
	if g.err != nil {
		return domain.Repository{}, g.err
	}
	return g.repository, nil
}

type fakeForgeStatusClient struct {
	calls []fakeForgeStatusCall
	err   error
}

type fakeForgeStatusCall struct {
	owner  string
	repo   string
	status forge.CommitStatus
}

func (c *fakeForgeStatusClient) PostCommitStatus(ctx context.Context, owner, repo string, status forge.CommitStatus) error {
	c.calls = append(c.calls, fakeForgeStatusCall{owner: owner, repo: repo, status: status})
	return c.err
}
