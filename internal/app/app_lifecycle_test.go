package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecycleTestHTTPServer struct {
	listenRelease  <-chan struct{}
	listenErr      error
	shutdown       func(context.Context) error
	listenStarted  chan struct{}
	shutdownCalled chan struct{}
	listenOnce     sync.Once
	shutdownOnce   sync.Once
}

func (s *lifecycleTestHTTPServer) ListenAndServe() error {
	s.listenOnce.Do(func() {
		if s.listenStarted != nil {
			close(s.listenStarted)
		}
	})
	if s.listenRelease != nil {
		<-s.listenRelease
	}
	return s.listenErr
}

func (s *lifecycleTestHTTPServer) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		if s.shutdownCalled != nil {
			close(s.shutdownCalled)
		}
	})
	if s.shutdown != nil {
		return s.shutdown(ctx)
	}
	return nil
}

func TestApplicationLifecycleSignalCancellationShutsDownHTTPAndJoinsAllRunners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listenRelease := make(chan struct{})
	server := &lifecycleTestHTTPServer{
		listenRelease:  listenRelease,
		listenStarted:  make(chan struct{}),
		shutdownCalled: make(chan struct{}),
		shutdown: func(context.Context) error {
			close(listenRelease)
			return nil
		},
	}
	started := make(chan struct{}, 3)
	var exited atomic.Int32
	runner := func(ctx context.Context) {
		started <- struct{}{}
		<-ctx.Done()
		exited.Add(1)
	}
	result := make(chan struct {
		safe bool
		err  error
	}, 1)
	go func() {
		safe, err := runApplicationLifecycle(ctx, cancel, server, runner, runner, runner, time.Second)
		result <- struct {
			safe bool
			err  error
		}{safe: safe, err: err}
	}()

	<-server.listenStarted
	for range 3 {
		<-started
	}
	cancel()
	got := <-result
	if got.err != nil {
		t.Fatalf("runApplicationLifecycle() error = %v", got.err)
	}
	if !got.safe {
		t.Fatal("database close was not allowed after successful shutdown and runner join")
	}
	if exited.Load() != 3 {
		t.Fatalf("joined runners = %d", exited.Load())
	}
	select {
	case <-server.shutdownCalled:
	default:
		t.Fatal("HTTP shutdown was not called")
	}
}

func TestApplicationLifecycleListenerErrorCancelsAndJoinsAllRunners(t *testing.T) {
	listenerErr := errors.New("listener failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &lifecycleTestHTTPServer{
		listenErr: listenerErr,
		shutdown: func(context.Context) error {
			if ctx.Err() == nil {
				return errors.New("application context was live during HTTP shutdown")
			}
			return nil
		},
	}
	var exited atomic.Int32
	runner := func(ctx context.Context) {
		<-ctx.Done()
		exited.Add(1)
	}

	safe, err := runApplicationLifecycle(ctx, cancel, server, runner, runner, runner, time.Second)
	if !safe {
		t.Fatal("database close was not allowed after listener failure was fully drained")
	}
	if !errors.Is(err, listenerErr) {
		t.Fatalf("error = %v, want listener error", err)
	}
	if exited.Load() != 3 {
		t.Fatalf("joined runners = %d", exited.Load())
	}
}

func TestApplicationLifecycleHTTPTimeoutSkipsDatabaseClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listenRelease := make(chan struct{})
	server := &lifecycleTestHTTPServer{
		listenRelease: listenRelease,
		shutdown: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	}
	runner := func(ctx context.Context) { <-ctx.Done() }

	safe, err := runApplicationLifecycle(ctx, cancel, server, runner, runner, runner, 20*time.Millisecond)
	close(listenRelease)
	if safe {
		t.Fatal("database close was allowed while HTTP shutdown exceeded its deadline")
	}
	if err == nil || !strings.Contains(err.Error(), "HTTP") {
		t.Fatalf("error = %v, want HTTP shutdown failure", err)
	}
}

func TestApplicationLifecycleRunnerTimeoutSkipsDatabaseClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	listenRelease := make(chan struct{})
	runnerRelease := make(chan struct{})
	server := &lifecycleTestHTTPServer{
		listenRelease: listenRelease,
		shutdown: func(context.Context) error {
			close(listenRelease)
			return nil
		},
	}
	cooperative := func(ctx context.Context) { <-ctx.Done() }
	stuck := func(context.Context) { <-runnerRelease }

	safe, err := runApplicationLifecycle(ctx, cancel, server, cooperative, cooperative, stuck, 20*time.Millisecond)
	close(runnerRelease)
	if safe {
		t.Fatal("database close was allowed while a database runner remained live")
	}
	if err == nil || !strings.Contains(err.Error(), "database runners") {
		t.Fatalf("error = %v, want runner shutdown failure", err)
	}
}
