package app

import (
	"fmt"
	"net"
	"strings"
)

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
		return fmt.Errorf("bootstrap auth requires THAWGUARD_HTTP_ADDR to bind to localhost or a loopback IP, got %q", addr)
	}
	return nil
}
