package statuspublisher

import (
	"context"
	"errors"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

func TestDryRunPublisherRecordsIntentAndAttempt(t *testing.T) {
	ctx := context.Background()
	result := statusresult.Result{ID: 7, RepositoryID: 1, PullRequestIndex: 42, TargetBranch: "main", HeadSHA: "abc123", Context: domain.RequiredStatusContext, State: domain.CommitStatusFailure, Description: "Branch is frozen; merge is blocked by Thawguard"}
	publication := statuspublication.Publication{ID: 9, StatusResultID: result.ID, RepositoryID: result.RepositoryID, PullRequestIndex: result.PullRequestIndex, TargetBranch: result.TargetBranch, HeadSHA: result.HeadSHA, Context: result.Context, State: result.State, Description: result.Description, DeliveryMode: statuspublication.DeliveryModeLocalRecord}
	intents := &fakeIntentPublisher{publication: publication}
	attempts := &fakeAttemptRecorder{}
	publisher := NewDryRunPublisher(intents, attempts)

	got, err := publisher.Publish(ctx, result)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != publication.ID || len(intents.results) != 1 || intents.results[0].ID != result.ID {
		t.Fatalf("expected intent publication to be returned and recorded, got publication=%+v intents=%+v", got, intents.results)
	}
	if len(attempts.publications) != 1 || attempts.publications[0].ID != publication.ID {
		t.Fatalf("expected dry-run attempt for publication, got %+v", attempts.publications)
	}
}

func TestDryRunPublisherReturnsAttemptErrors(t *testing.T) {
	ctx := context.Background()
	intents := &fakeIntentPublisher{publication: statuspublication.Publication{ID: 1}}
	attempts := &fakeAttemptRecorder{err: errors.New("attempt failed")}
	publisher := NewDryRunPublisher(intents, attempts)

	if _, err := publisher.Publish(ctx, statusresult.Result{ID: 1}); err == nil || !errors.Is(err, attempts.err) {
		t.Fatalf("expected wrapped attempt error, got %v", err)
	}
}

func TestDryRunPublisherRequiresConfiguration(t *testing.T) {
	if _, err := NewDryRunPublisher(nil, nil).Publish(context.Background(), statusresult.Result{}); err == nil {
		t.Fatal("expected configuration error")
	}
}

type fakeIntentPublisher struct {
	publication statuspublication.Publication
	results     []statusresult.Result
	err         error
}

func (p *fakeIntentPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	p.results = append(p.results, result)
	if p.err != nil {
		return statuspublication.Publication{}, p.err
	}
	return p.publication, nil
}

type fakeAttemptRecorder struct {
	publications []statuspublication.Publication
	err          error
}

func (r *fakeAttemptRecorder) RecordDryRunAttempt(ctx context.Context, publication statuspublication.Publication) (statuspublication.Attempt, error) {
	r.publications = append(r.publications, publication)
	if r.err != nil {
		return statuspublication.Attempt{}, r.err
	}
	return statuspublication.Attempt{ID: int64(len(r.publications)), PublicationID: publication.ID}, nil
}
