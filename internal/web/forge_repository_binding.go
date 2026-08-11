package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

const (
	forgeAccessConfirmBindValue   = "bind"
	forgeAccessConfirmUnbindValue = "unbind"

	forgeAccessBoundNotice           = "forge-repository-bound"
	forgeAccessBindStaleNotice       = "forge-bind-stale"
	forgeAccessBindUnavailableNotice = "forge-bind-unavailable"
	forgeAccessBindAuthorityNotice   = "forge-bind-authority"
	forgeAccessBindUnknownNotice     = "forge-bind-unknown"

	forgeAccessUnboundNotice           = "forge-repository-unbound"
	forgeAccessUnbindStaleNotice       = "forge-unbind-stale"
	forgeAccessUnbindUnavailableNotice = "forge-unbind-unavailable"
	forgeAccessUnbindAuthorityNotice   = "forge-unbind-authority"
	forgeAccessUnbindUnknownNotice     = "forge-unbind-unknown"
)

// forgeAccessBindingNotices maps one binding verb's service outcomes to
// redirect notices.
type forgeAccessBindingNotices struct {
	success     string
	stale       string
	unavailable string
	authority   string
	unknown     string
}

// forgeRepositoryBindingCommand runs one parsed binding mutation for the
// acting Administrator. It must not touch the service before it is invoked,
// so the shared handler can gate on an unconfigured service first.
type forgeRepositoryBindingCommand func(ctx context.Context, actorUserID int64) error

func (s *Server) handleForgeRepositoryBind(w http.ResponseWriter, r *http.Request) {
	notices := forgeAccessBindingNotices{
		success:     forgeAccessBoundNotice,
		stale:       forgeAccessBindStaleNotice,
		unavailable: forgeAccessBindUnavailableNotice,
		authority:   forgeAccessBindAuthorityNotice,
		unknown:     forgeAccessBindUnknownNotice,
	}
	s.handleForgeRepositoryBindingChange(w, r, notices,
		func(requestURL *url.URL, values url.Values) (forgeRepositoryBindingCommand, error) {
			input, err := parseForgeRepositoryBindForm(requestURL, values)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context, actorUserID int64) error {
				return s.cfg.ForgeConnectionService.BindRepository(ctx, actorUserID, input)
			}, nil
		})
}

func (s *Server) handleForgeRepositoryUnbind(w http.ResponseWriter, r *http.Request) {
	notices := forgeAccessBindingNotices{
		success:     forgeAccessUnboundNotice,
		stale:       forgeAccessUnbindStaleNotice,
		unavailable: forgeAccessUnbindUnavailableNotice,
		authority:   forgeAccessUnbindAuthorityNotice,
		unknown:     forgeAccessUnbindUnknownNotice,
	}
	s.handleForgeRepositoryBindingChange(w, r, notices,
		func(requestURL *url.URL, values url.Values) (forgeRepositoryBindingCommand, error) {
			input, err := parseForgeRepositoryUnbindForm(requestURL, values)
			if err != nil {
				return nil, err
			}
			return func(ctx context.Context, actorUserID int64) error {
				return s.cfg.ForgeConnectionService.UnbindRepository(ctx, actorUserID, input)
			}, nil
		})
}

func (s *Server) handleForgeRepositoryBindingChange(
	w http.ResponseWriter,
	r *http.Request,
	notices forgeAccessBindingNotices,
	parse func(*url.URL, url.Values) (forgeRepositoryBindingCommand, error),
) {
	r.Body = http.MaxBytesReader(w, r.Body, forgeAccessActionMaxBodyBytes)
	if !s.validExactPublicOrigin(r) {
		s.logRequestRejected(r, originRejectionReason(r))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	session, ok := s.requireAdminForm(w, r)
	if !ok || session.UserID == nil {
		return
	}
	command, err := parse(r.URL, r.PostForm)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.cfg.ForgeConnectionService == nil {
		redirectForgeAccessNotice(w, r, notices.unknown)
		return
	}
	if err := command(r.Context(), *session.UserID); err != nil {
		notice := notices.unknown
		switch {
		case errors.Is(err, forgeconnection.ErrConflict), errors.Is(err, forgeconnection.ErrNoConnection):
			notice = notices.stale
		case errors.Is(err, forgeconnection.ErrBindingUnavailable), forgeconnection.IsValidationError(err):
			notice = notices.unavailable
		case errors.Is(err, forgeconnection.ErrAuthorization):
			notice = notices.authority
		}
		redirectForgeAccessNotice(w, r, notice)
		return
	}
	redirectForgeAccessNotice(w, r, notices.success)
}

func parseForgeRepositoryBindForm(requestURL *url.URL, values url.Values) (forgeconnection.BindRepositoryInput, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_config_revision",
		"expected_check_generation",
		"expected_binding_revision",
		"repository_id",
		"repository_created_at",
		"confirm_bind",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeconnection.BindRepositoryInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeconnection.BindRepositoryInput{}, err
	}
	configRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_config_revision"))
	if err != nil {
		return forgeconnection.BindRepositoryInput{}, err
	}
	checkGeneration, err := canonicalPositiveForgeAccessValue(values.Get("expected_check_generation"))
	if err != nil {
		return forgeconnection.BindRepositoryInput{}, err
	}
	bindingRevision, err := canonicalExpectedRevision(values.Get("expected_binding_revision"))
	if err != nil {
		return forgeconnection.BindRepositoryInput{}, err
	}
	repositoryID, err := canonicalPositiveForgeAccessValue(values.Get("repository_id"))
	if err != nil {
		return forgeconnection.BindRepositoryInput{}, err
	}
	createdAt := values.Get("repository_created_at")
	if _, err := forgeconnection.ParseRepositoryCreatedAt(createdAt); err != nil {
		return forgeconnection.BindRepositoryInput{}, errors.New("repository creation timestamp is malformed")
	}
	if values.Get("confirm_bind") != forgeAccessConfirmBindValue {
		return forgeconnection.BindRepositoryInput{}, errors.New("bind confirmation is invalid")
	}
	return forgeconnection.BindRepositoryInput{
		ExpectedConnectionID:    connectionID,
		ExpectedConfigRevision:  configRevision,
		ExpectedCheckGeneration: checkGeneration,
		ExpectedBindingRevision: bindingRevision,
		RepositoryID:            repositoryID,
		RepositoryCreatedAt:     createdAt,
		ConfirmBind:             true,
	}, nil
}

func parseForgeRepositoryUnbindForm(requestURL *url.URL, values url.Values) (forgeconnection.UnbindRepositoryInput, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_config_revision",
		"expected_binding_revision",
		"repository_id",
		"confirm_unbind",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return forgeconnection.UnbindRepositoryInput{}, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return forgeconnection.UnbindRepositoryInput{}, err
	}
	configRevision, err := canonicalPositiveForgeAccessValue(values.Get("expected_config_revision"))
	if err != nil {
		return forgeconnection.UnbindRepositoryInput{}, err
	}
	bindingRevision, err := canonicalExpectedRevision(values.Get("expected_binding_revision"))
	if err != nil {
		return forgeconnection.UnbindRepositoryInput{}, err
	}
	repositoryID, err := canonicalPositiveForgeAccessValue(values.Get("repository_id"))
	if err != nil {
		return forgeconnection.UnbindRepositoryInput{}, err
	}
	if values.Get("confirm_unbind") != forgeAccessConfirmUnbindValue {
		return forgeconnection.UnbindRepositoryInput{}, errors.New("unbind confirmation is invalid")
	}
	return forgeconnection.UnbindRepositoryInput{
		ExpectedConnectionID:    connectionID,
		ExpectedConfigRevision:  configRevision,
		ExpectedBindingRevision: bindingRevision,
		RepositoryID:            repositoryID,
		ConfirmUnbind:           true,
	}, nil
}

func parseForgeAccessResetForm(requestURL *url.URL, values url.Values) (int64, int64, int64, int64, error) {
	fields := []string{
		csrfFormField,
		"expected_connection_id",
		"expected_revision",
		"expected_binding_revision",
		"expected_oauth_revision",
		"confirm_reset",
	}
	if err := exactForgeAccessForm(requestURL, values, fields); err != nil {
		return 0, 0, 0, 0, err
	}
	connectionID, err := canonicalPositiveForgeAccessValue(values.Get("expected_connection_id"))
	if err != nil {
		return 0, 0, 0, 0, err
	}
	revision, err := canonicalPositiveForgeAccessValue(values.Get("expected_revision"))
	if err != nil {
		return 0, 0, 0, 0, err
	}
	bindingRevision, err := canonicalExpectedRevision(values.Get("expected_binding_revision"))
	if err != nil {
		return 0, 0, 0, 0, err
	}
	oauthRevision, err := canonicalExpectedRevision(values.Get("expected_oauth_revision"))
	if err != nil {
		return 0, 0, 0, 0, err
	}
	if values.Get("confirm_reset") != forgeAccessConfirmResetValue {
		return 0, 0, 0, 0, errors.New("reset confirmation is invalid")
	}
	return connectionID, revision, bindingRevision, oauthRevision, nil
}

func exactForgeAccessForm(requestURL *url.URL, values url.Values, fields []string) error {
	if requestURL.RawQuery != "" || requestURL.ForceQuery || len(values) != len(fields) {
		return errors.New("form is malformed")
	}
	for _, field := range fields {
		if len(values[field]) != 1 {
			return errors.New("form is malformed")
		}
	}
	return nil
}

func canonicalPositiveForgeAccessValue(value string) (int64, error) {
	parsed, err := canonicalExpectedRevision(value)
	if err != nil || parsed == 0 {
		return 0, errors.New("positive canonical integer is required")
	}
	return parsed, nil
}

func forgeAccessConfirmationRepositoryID(values url.Values, field string) (int64, bool) {
	if len(values) != 1 || len(values[field]) != 1 {
		return 0, false
	}
	repositoryID, err := canonicalPositiveForgeAccessValue(values.Get(field))
	if err != nil {
		return 0, false
	}
	return repositoryID, true
}
