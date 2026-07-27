package web

import (
	"net/http"
	"strings"
)

// Rejection classifications. Each one names why a request was already
// rejected; none of them takes part in the decision.
const (
	reasonOriginMissing  = "origin_missing"
	reasonOriginNull     = "origin_null"
	reasonOriginMultiple = "origin_multiple"
	reasonOriginMismatch = "origin_mismatch"
	reasonCSRFInvalid    = "csrf_invalid"
)

// logRequestRejected records only the matched ServeMux route and a fixed
// rejection reason. Raw paths and request values never reach the logger.
func (s *Server) logRequestRejected(r *http.Request, reason string) {
	route := strings.TrimPrefix(r.Pattern, r.Method+" ")
	s.cfg.Logger.InfoContext(r.Context(), "request rejected",
		"method", r.Method,
		"route", route,
		"status", http.StatusForbidden,
		"reason", reason,
	)
}

// originRejectionReason classifies an Origin header that has already failed an
// exact-Origin check. A literal "null" is called out separately because that is
// how a browser serializes an opaque origin, which distinguishes a referrer or
// sandbox misconfiguration from an ordinary cross-site post.
func originRejectionReason(r *http.Request) string {
	origins := r.Header.Values("Origin")
	switch {
	case len(origins) == 0:
		return reasonOriginMissing
	case len(origins) > 1:
		return reasonOriginMultiple
	case origins[0] == "null":
		return reasonOriginNull
	default:
		return reasonOriginMismatch
	}
}
