package forgejo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Low-level bounded reads for the Forgejo connection preview check. Every
// read is a plain GET, decodes strictly, caps its body at 1 MiB, and never
// retains raw response data in an error: failures surface only as a typed
// status, a malformed-response sentinel, or the wrapped transport cause.

// maxConnectionReadBodyBytes caps one response body for connection reads.
const maxConnectionReadBodyBytes = 1 << 20

// ErrResponseMalformed reports a response that was not bounded, valid
// UTF-8, correctly typed JSON with the required fields.
var ErrResponseMalformed = errors.New("forgejo response is malformed")

// ErrTotalCountInvalid reports a paginated response without exactly one
// valid canonical X-Total-Count header.
var ErrTotalCountInvalid = errors.New("forgejo X-Total-Count header is missing or invalid")

// StatusError reports a non-200 response status without any response data.
type StatusError struct {
	StatusCode int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("forgejo request returned status %d", e.StatusCode)
}

// ConnectionUser is the credential's own account as reported by /user.
type ConnectionUser struct {
	ID      int64
	Login   string
	IsAdmin bool
}

// ConnectionOrganization is one organization visible to the credential.
type ConnectionOrganization struct {
	ID       int64
	Name     string
	FullName string
}

// ConnectionRepository is one repository record from an organization
// listing or a direct read.
type ConnectionRepository struct {
	ID            int64
	Owner         string
	Name          string
	DefaultBranch string
	Private       bool
}

// Member rules for the strict object preflight: every critical field of a
// decoded payload, including the nested owner object. encoding/json keeps
// the last of duplicate members and matches field names case-insensitively,
// so without the preflight a crafted response could redefine a validated
// value after validation-relevant members were checked.
var (
	versionObjectRule      = &strictObjectRule{critical: map[string]*strictObjectRule{"version": nil}}
	userObjectRule         = &strictObjectRule{critical: map[string]*strictObjectRule{"id": nil, "login": nil, "is_admin": nil}}
	organizationObjectRule = &strictObjectRule{critical: map[string]*strictObjectRule{"id": nil, "name": nil, "full_name": nil}}
	repositoryObjectRule   = &strictObjectRule{critical: map[string]*strictObjectRule{
		"id":             nil,
		"name":           nil,
		"private":        nil,
		"default_branch": nil,
		"owner":          {critical: map[string]*strictObjectRule{"login": nil}},
	}}
)

// ReadVersion reads the installation version string.
func (c *Client) ReadVersion(ctx context.Context) (string, error) {
	body, _, err := c.connectionRead(ctx, nil, "api", "v1", "version")
	if err != nil {
		return "", err
	}
	var payload struct {
		Version *string `json:"version"`
	}
	if err := strictDecodeJSONObject(body, versionObjectRule, &payload); err != nil {
		return "", err
	}
	if payload.Version == nil || *payload.Version == "" {
		return "", ErrResponseMalformed
	}
	return *payload.Version, nil
}

// ReadCurrentUser reads the account behind the configured token.
func (c *Client) ReadCurrentUser(ctx context.Context) (ConnectionUser, error) {
	body, _, err := c.connectionRead(ctx, nil, "api", "v1", "user")
	if err != nil {
		return ConnectionUser{}, err
	}
	var payload struct {
		ID      *int64  `json:"id"`
		Login   *string `json:"login"`
		IsAdmin *bool   `json:"is_admin"`
	}
	if err := strictDecodeJSONObject(body, userObjectRule, &payload); err != nil {
		return ConnectionUser{}, err
	}
	if payload.ID == nil || *payload.ID <= 0 || payload.Login == nil || *payload.Login == "" || payload.IsAdmin == nil {
		return ConnectionUser{}, ErrResponseMalformed
	}
	return ConnectionUser{ID: *payload.ID, Login: *payload.Login, IsAdmin: *payload.IsAdmin}, nil
}

// ReadCurrentUserOrganizations reads one page of the credential's own
// organization list plus the advertised total. A page carrying more records
// than the requested limit is rejected during decoding.
func (c *Client) ReadCurrentUserOrganizations(ctx context.Context, page, limit int) ([]ConnectionOrganization, int64, error) {
	if limit < 1 {
		return nil, 0, errors.New("page limit must be positive")
	}
	body, total, err := c.connectionRead(ctx, pageQuery(page, limit), "api", "v1", "user", "orgs")
	if err != nil {
		return nil, 0, err
	}
	type organizationPayload struct {
		ID       *int64  `json:"id"`
		Name     *string `json:"name"`
		FullName *string `json:"full_name"`
	}
	payload := make([]organizationPayload, 0, limit)
	if err := strictDecodeJSONArray(body, limit, organizationObjectRule, func() any {
		payload = append(payload, organizationPayload{})
		return &payload[len(payload)-1]
	}); err != nil {
		return nil, 0, err
	}
	organizations := make([]ConnectionOrganization, 0, len(payload))
	for _, item := range payload {
		if item.ID == nil || *item.ID <= 0 || item.Name == nil || *item.Name == "" {
			return nil, 0, ErrResponseMalformed
		}
		organization := ConnectionOrganization{ID: *item.ID, Name: *item.Name}
		if item.FullName != nil {
			organization.FullName = *item.FullName
		}
		organizations = append(organizations, organization)
	}
	if total < 0 {
		return nil, 0, ErrTotalCountInvalid
	}
	return organizations, total, nil
}

// ReadOrganizationRepositories reads one page of an organization's
// repository list plus the advertised total. A page carrying more records
// than the requested limit is rejected during decoding.
func (c *Client) ReadOrganizationRepositories(ctx context.Context, organization string, page, limit int) ([]ConnectionRepository, int64, error) {
	if limit < 1 {
		return nil, 0, errors.New("page limit must be positive")
	}
	body, total, err := c.connectionRead(ctx, pageQuery(page, limit), "api", "v1", "orgs", organization, "repos")
	if err != nil {
		return nil, 0, err
	}
	payload := make([]connectionRepositoryPayload, 0, limit)
	if err := strictDecodeJSONArray(body, limit, repositoryObjectRule, func() any {
		payload = append(payload, connectionRepositoryPayload{})
		return &payload[len(payload)-1]
	}); err != nil {
		return nil, 0, err
	}
	repositories := make([]ConnectionRepository, 0, len(payload))
	for _, item := range payload {
		repository, err := item.validated()
		if err != nil {
			return nil, 0, err
		}
		repositories = append(repositories, repository)
	}
	if total < 0 {
		return nil, 0, ErrTotalCountInvalid
	}
	return repositories, total, nil
}

// ReadRepositoryByID reads one repository directly by its immutable id.
// The connection check uses it as the private-read capability proof.
func (c *Client) ReadRepositoryByID(ctx context.Context, id int64) (ConnectionRepository, error) {
	if id <= 0 {
		return ConnectionRepository{}, errors.New("repository id must be positive")
	}
	body, _, err := c.connectionRead(ctx, nil, "api", "v1", "repositories", strconv.FormatInt(id, 10))
	if err != nil {
		return ConnectionRepository{}, err
	}
	var payload connectionRepositoryPayload
	if err := strictDecodeJSONObject(body, repositoryObjectRule, &payload); err != nil {
		return ConnectionRepository{}, err
	}
	return payload.validated()
}

type connectionRepositoryPayload struct {
	ID    *int64  `json:"id"`
	Name  *string `json:"name"`
	Owner *struct {
		Login *string `json:"login"`
	} `json:"owner"`
	Private       *bool   `json:"private"`
	DefaultBranch *string `json:"default_branch"`
}

func (p connectionRepositoryPayload) validated() (ConnectionRepository, error) {
	if p.ID == nil || *p.ID <= 0 ||
		p.Name == nil || *p.Name == "" ||
		p.Owner == nil || p.Owner.Login == nil || *p.Owner.Login == "" ||
		p.Private == nil ||
		p.DefaultBranch == nil || *p.DefaultBranch == "" {
		return ConnectionRepository{}, ErrResponseMalformed
	}
	return ConnectionRepository{
		ID:            *p.ID,
		Owner:         *p.Owner.Login,
		Name:          *p.Name,
		DefaultBranch: *p.DefaultBranch,
		Private:       *p.Private,
	}, nil
}

func pageQuery(page, limit int) map[string]string {
	return map[string]string{
		"page":  strconv.Itoa(page),
		"limit": strconv.Itoa(limit),
	}
}

// connectionRead performs one bounded GET and returns the body plus the
// parsed X-Total-Count (-1 when the header is absent or invalid; list
// callers reject that). A non-200 status is returned as *StatusError with
// no body content.
func (c *Client) connectionRead(ctx context.Context, query map[string]string, segments ...string) ([]byte, int64, error) {
	// Defense in depth behind the adapter's observed-name validation: no
	// connection-read segment may be empty, a dot segment, or carry a
	// separator, so an observed value can never traverse the API path.
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, `/\`) {
			return nil, 0, ErrResponseMalformed
		}
	}
	endpoint, err := c.escapedEndpoint(segments...)
	if err != nil {
		return nil, 0, err
	}
	if len(query) > 0 {
		parsed, err := url.Parse(endpoint)
		if err != nil {
			return nil, 0, err
		}
		values := parsed.Query()
		for key, value := range query {
			values.Set(key, value)
		}
		parsed.RawQuery = values.Encode()
		endpoint = parsed.String()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create forgejo connection read request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	if token := strings.TrimSpace(c.Token); token != "" {
		request.Header.Set("Authorization", "token "+token)
	}
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, 0, fmt.Errorf("forgejo connection read: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, &StatusError{StatusCode: response.StatusCode}
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, 0, ErrResponseMalformed
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxConnectionReadBodyBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read forgejo connection response: %w", err)
	}
	if len(body) > maxConnectionReadBodyBytes || !utf8.Valid(body) {
		return nil, 0, ErrResponseMalformed
	}
	return body, parseTotalCount(response.Header), nil
}

// parseTotalCount accepts exactly one canonical non-negative decimal
// X-Total-Count value and returns -1 otherwise.
func parseTotalCount(header http.Header) int64 {
	values := header.Values("X-Total-Count")
	if len(values) != 1 {
		return -1
	}
	value := values[0]
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return -1
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return -1
		}
	}
	total, err := strconv.ParseInt(value, 10, 64)
	if err != nil || total < 0 {
		return -1
	}
	return total
}

// strictDecodeJSON decodes exactly one JSON document with no trailing data.
func strictDecodeJSON(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(target); err != nil {
		return ErrResponseMalformed
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrResponseMalformed
	}
	return nil
}

// strictObjectRule names the critical members of one JSON object level and
// carries an optional nested rule for members that are objects themselves.
type strictObjectRule struct {
	critical map[string]*strictObjectRule
}

// strictDecodeJSONObject verifies one JSON object against rule, then
// decodes it strictly. The preflight rejects any exact-duplicate member at
// a validated level and any member that case-insensitively aliases a
// critical name without matching it exactly; unknown Forgejo members
// remain allowed (once each) and are skipped wholesale, so duplicates
// inside their own substructures are not this preflight's concern.
func strictDecodeJSONObject(body []byte, rule *strictObjectRule, target any) error {
	if err := verifyStrictObject(body, rule); err != nil {
		return err
	}
	return strictDecodeJSON(body, target)
}

// strictDecodeJSONArray decodes exactly one JSON array with no trailing
// data, verifying each element against rule before decoding it into a
// target produced by next, and failing before more than limit elements are
// decoded.
func strictDecodeJSONArray(body []byte, limit int, rule *strictObjectRule, next func() any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil {
		return ErrResponseMalformed
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '[' {
		return ErrResponseMalformed
	}
	decoded := 0
	for decoder.More() {
		decoded++
		if decoded > limit {
			return ErrResponseMalformed
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return ErrResponseMalformed
		}
		if err := verifyStrictObject(raw, rule); err != nil {
			return err
		}
		if err := json.Unmarshal(raw, next()); err != nil {
			return ErrResponseMalformed
		}
	}
	closing, err := decoder.Token()
	if err != nil {
		return ErrResponseMalformed
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != ']' {
		return ErrResponseMalformed
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrResponseMalformed
	}
	return nil
}

func verifyStrictObject(body []byte, rule *strictObjectRule) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := verifyStrictObjectValue(decoder, rule); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrResponseMalformed
	}
	return nil
}

// verifyStrictObjectValue consumes one JSON object (or null) from decoder,
// enforcing the member rules for its level and recursing into critical
// members that carry a nested rule.
func verifyStrictObjectValue(decoder *json.Decoder, rule *strictObjectRule) error {
	opening, err := decoder.Token()
	if err != nil {
		return ErrResponseMalformed
	}
	if opening == nil {
		// JSON null; the typed decode decides whether null is acceptable.
		return nil
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return ErrResponseMalformed
	}
	seen := make(map[string]bool)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return ErrResponseMalformed
		}
		key, ok := keyToken.(string)
		if !ok {
			return ErrResponseMalformed
		}
		if seen[key] {
			return ErrResponseMalformed
		}
		seen[key] = true
		var nested *strictObjectRule
		matched := false
		for name, nestedRule := range rule.critical {
			if key == name {
				matched = true
				nested = nestedRule
				break
			}
			if strings.EqualFold(key, name) {
				return ErrResponseMalformed
			}
		}
		if matched && nested != nil {
			if err := verifyStrictObjectValue(decoder, nested); err != nil {
				return err
			}
			continue
		}
		if err := skipJSONValue(decoder); err != nil {
			return ErrResponseMalformed
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Token(json.Delim('}')) {
		return ErrResponseMalformed
	}
	return nil
}

// skipJSONValue consumes exactly one JSON value of any shape.
func skipJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || (delimiter != '{' && delimiter != '[') {
		return nil
	}
	depth := 1
	for depth > 0 {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if inner, ok := token.(json.Delim); ok {
			switch inner {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
	}
	return nil
}
