package statuspublisher

import (
	"context"
	"errors"
	"fmt"

	"github.com/taua-almeida/thawguard/internal/statuspublication"
	"github.com/taua-almeida/thawguard/internal/statusresult"
)

type IntentPublisher interface {
	Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error)
}

type DryRunAttemptRecorder interface {
	RecordDryRunAttempt(ctx context.Context, publication statuspublication.Publication) (statuspublication.Attempt, error)
}

type DryRunPublisher struct {
	intents  IntentPublisher
	attempts DryRunAttemptRecorder
}

func NewDryRunPublisher(intents IntentPublisher, attempts DryRunAttemptRecorder) *DryRunPublisher {
	return &DryRunPublisher{intents: intents, attempts: attempts}
}

func (p *DryRunPublisher) Publish(ctx context.Context, result statusresult.Result) (statuspublication.Publication, error) {
	if p == nil || p.intents == nil || p.attempts == nil {
		return statuspublication.Publication{}, errors.New("dry-run status publisher is not configured")
	}
	publication, err := p.intents.Publish(ctx, result)
	if err != nil {
		return statuspublication.Publication{}, err
	}
	if _, err := p.attempts.RecordDryRunAttempt(ctx, publication); err != nil {
		return statuspublication.Publication{}, fmt.Errorf("record dry-run status publication attempt: %w", err)
	}
	return publication, nil
}
