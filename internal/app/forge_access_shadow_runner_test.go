package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

type fakeForgeAccessShadowPeriodicService struct {
	mu     sync.Mutex
	calls  int
	err    error
	onCall func()
}

func (s *fakeForgeAccessShadowPeriodicService) RunPeriodicDue(context.Context) error {
	s.mu.Lock()
	s.calls++
	onCall := s.onCall
	err := s.err
	s.mu.Unlock()
	if onCall != nil {
		onCall()
	}
	return err
}

func (s *fakeForgeAccessShadowPeriodicService) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func TestForgeAccessShadowRunnerPerformsOneStartupScanAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &fakeForgeAccessShadowPeriodicService{onCall: cancel}
	runner := newForgeAccessShadowRunner(service, nil)

	runner.Start(ctx)
	if service.callCount() != 1 {
		t.Fatalf("startup scans = %d", service.callCount())
	}
}

func TestForgeAccessShadowRunnerCancelledContextSkipsStartupScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service := &fakeForgeAccessShadowPeriodicService{}

	newForgeAccessShadowRunner(service, nil).Start(ctx)
	if service.callCount() != 0 {
		t.Fatalf("cancelled startup scans = %d", service.callCount())
	}
}

func TestForgeAccessShadowRunnerScansAtItsFixedCadence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &fakeForgeAccessShadowPeriodicService{}
	service.onCall = func() {
		if service.callCount() == 2 {
			cancel()
		}
	}
	runner := newForgeAccessShadowRunner(service, nil)
	runner.interval = time.Millisecond

	runner.Start(ctx)
	if service.callCount() != 2 {
		t.Fatalf("runner scans = %d, want startup plus one tick", service.callCount())
	}
}

func TestForgeAccessShadowRunnerLogsOnlyFixedSanitizedUnexpectedMessage(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	service := &fakeForgeAccessShadowPeriodicService{
		err: errors.Join(
			forgeconnection.ErrAccessPeriodicReservationFailed,
			errors.New("https://forge-secret.example.test user@example.test repository-name raw-provider-body token-canary"),
		),
	}
	runner := newForgeAccessShadowRunner(service, logger)
	runner.runAndLog(context.Background())

	text := logs.String()
	if !strings.Contains(text, "periodic shadow refresh runner pass failed") {
		t.Fatalf("fixed log message missing: %q", text)
	}
	if !strings.Contains(text, "phase=reservation") {
		t.Fatalf("sanitized failure phase missing: %q", text)
	}
	for _, canary := range []string{
		"forge-secret", "user@example", "repository-name", "raw-provider-body", "token-canary", "err=",
	} {
		if strings.Contains(text, canary) {
			t.Fatalf("runner log leaked %q: %q", canary, text)
		}
	}
}

func TestForgeAccessShadowRunnerSuppressesCancellationLog(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	service := &fakeForgeAccessShadowPeriodicService{err: context.Canceled}
	runner := newForgeAccessShadowRunner(service, logger)
	runner.runAndLog(context.Background())
	if logs.Len() != 0 {
		t.Fatalf("cancellation was logged: %q", logs.String())
	}
}
