package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type applicationHTTPServer interface {
	ListenAndServe() error
	Shutdown(ctx context.Context) error
}

// runApplicationLifecycle owns cancellation of the one application child
// context created by App.Run and the join for the three database runners. Its
// boolean result is the only signal that both HTTP shutdown and every runner
// exit succeeded, making SQLite safe to close.
func runApplicationLifecycle(
	applicationCtx context.Context,
	cancelApplication context.CancelFunc,
	server applicationHTTPServer,
	freezeRunner func(context.Context),
	reconciliationRunner func(context.Context),
	shadowRunner func(context.Context),
	shutdownTimeout time.Duration,
) (bool, error) {
	defer cancelApplication()
	var runners sync.WaitGroup
	runners.Go(func() { freezeRunner(applicationCtx) })
	runners.Go(func() { reconciliationRunner(applicationCtx) })
	runners.Go(func() { shadowRunner(applicationCtx) })

	listenerDone := make(chan error, 1)
	go func() {
		listenerDone <- server.ListenAndServe()
	}()

	var listenerErr error
	select {
	case <-applicationCtx.Done():
	case listenerErr = <-listenerDone:
	}
	cancelApplication()

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancelShutdown()
	httpDone := make(chan error, 1)
	go func() {
		httpDone <- server.Shutdown(shutdownCtx)
	}()
	runnersDone := make(chan struct{})
	go func() {
		runners.Wait()
		close(runnersDone)
	}()

	var httpErr error
	httpFinished := false
	runnersFinished := false
	for !httpFinished || !runnersFinished {
		select {
		case httpErr = <-httpDone:
			httpFinished = true
			httpDone = nil
		case <-runnersDone:
			runnersFinished = true
			runnersDone = nil
		case <-shutdownCtx.Done():
			// Prefer completed signals that raced with the deadline.
			if !httpFinished {
				select {
				case httpErr = <-httpDone:
					httpFinished = true
				default:
				}
			}
			if !runnersFinished {
				select {
				case <-runnersDone:
					runnersFinished = true
				default:
				}
			}
			if httpFinished && runnersFinished {
				if httpErr != nil {
					return false, errors.Join(listenerErr, fmt.Errorf("shut down HTTP server: %w", httpErr))
				}
				return true, listenerErr
			}
			var shutdownErr error
			if !httpFinished {
				shutdownErr = errors.Join(shutdownErr, errors.New("HTTP shutdown exceeded the ten-second deadline"))
			} else if httpErr != nil {
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shut down HTTP server: %w", httpErr))
			}
			if !runnersFinished {
				shutdownErr = errors.Join(shutdownErr, errors.New("database runners exceeded the ten-second shutdown deadline"))
			}
			return false, errors.Join(listenerErr, shutdownErr)
		}
	}
	if httpErr != nil {
		return false, errors.Join(listenerErr, fmt.Errorf("shut down HTTP server: %w", httpErr))
	}
	return true, listenerErr
}
