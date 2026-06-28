package audit

import (
	"context"
	"time"
)

type Event struct {
	ID          int64
	ActorID     int64
	Action      string
	Subject     string
	DetailsJSON string
	CreatedAt   time.Time
}

type Recorder interface {
	Record(ctx context.Context, event Event) error
}
