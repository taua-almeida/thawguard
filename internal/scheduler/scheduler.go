package scheduler

import (
	"context"
	"time"
)

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type Runner interface {
	Start(ctx context.Context) error
}
