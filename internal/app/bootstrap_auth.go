package app

import (
	"context"
	"fmt"
	"net"
	"strings"
)

type userPresenceChecker interface {
	HasUsers(ctx context.Context) (bool, error)
}

func validateInitialSetupBind(ctx context.Context, addr string, checker userPresenceChecker) error {
	if checker == nil {
		return validateBootstrapLocalBind(addr)
	}
	hasUsers, err := checker.HasUsers(ctx)
	if err != nil {
		return fmt.Errorf("check local auth setup: %w", err)
	}
	if hasUsers {
		return nil
	}
	return validateBootstrapLocalBind(addr)
}

func validateBootstrapLocalBind(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("parse HTTP bind address %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("first-admin setup requires THAWGUARD_HTTP_ADDR to bind to localhost or a loopback IP until a user exists, got %q", addr)
	}
	return nil
}
