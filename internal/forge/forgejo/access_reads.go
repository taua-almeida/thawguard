package forgejo

import (
	"context"
	"errors"
	"strconv"
)

var errPageLimitInvalid = errors.New("page limit must be positive")

// Low-level bounded reads for the Forgejo shadow-access snapshot. They share
// the connection-read boundary: plain GETs, strict decoding, a 1 MiB body
// cap, and errors that never retain response data.

// AccessUser is one user record from a member or collaborator listing, the
// direct user read, or the nested permission response user.
type AccessUser struct {
	ID    int64
	Login string
}

// AccessTeam is one organization team. Only the immutable id is read; team
// names never enter the snapshot.
type AccessTeam struct {
	ID int64
}

// AccessPermission is the effective-permission response for one exact
// repository and collaborator. role_name is deliberately ignored.
type AccessPermission struct {
	Permission string
	User       AccessUser
}

var (
	accessUserObjectRule       = &strictObjectRule{critical: map[string]*strictObjectRule{"id": nil, "login": nil}}
	accessTeamObjectRule       = &strictObjectRule{critical: map[string]*strictObjectRule{"id": nil}}
	accessPermissionObjectRule = &strictObjectRule{critical: map[string]*strictObjectRule{
		"permission": nil,
		"user":       {critical: map[string]*strictObjectRule{"id": nil, "login": nil}},
	}}
)

// ReadOrganization reads one organization directly by its current name.
func (c *Client) ReadOrganization(ctx context.Context, organization string) (ConnectionOrganization, error) {
	body, _, err := c.connectionRead(ctx, nil, "api", "v1", "orgs", organization)
	if err != nil {
		return ConnectionOrganization{}, err
	}
	var payload struct {
		ID       *int64  `json:"id"`
		Name     *string `json:"name"`
		FullName *string `json:"full_name"`
	}
	if err := strictDecodeJSONObject(body, organizationObjectRule, &payload); err != nil {
		return ConnectionOrganization{}, err
	}
	if payload.ID == nil || *payload.ID <= 0 || payload.Name == nil || *payload.Name == "" {
		return ConnectionOrganization{}, ErrResponseMalformed
	}
	result := ConnectionOrganization{ID: *payload.ID, Name: *payload.Name}
	if payload.FullName != nil {
		result.FullName = *payload.FullName
	}
	return result, nil
}

// ReadOrganizationMembers reads one page of an organization's member list
// plus the advertised total.
func (c *Client) ReadOrganizationMembers(ctx context.Context, organization string, page, limit int) ([]AccessUser, int64, error) {
	return c.readAccessUserPage(ctx, page, limit, "api", "v1", "orgs", organization, "members")
}

// ReadOrganizationTeams reads one page of an organization's team list plus
// the advertised total.
func (c *Client) ReadOrganizationTeams(ctx context.Context, organization string, page, limit int) ([]AccessTeam, int64, error) {
	if limit < 1 {
		return nil, 0, errPageLimitInvalid
	}
	body, total, err := c.connectionRead(ctx, pageQuery(page, limit), "api", "v1", "orgs", organization, "teams")
	if err != nil {
		return nil, 0, err
	}
	type teamPayload struct {
		ID *int64 `json:"id"`
	}
	payload := make([]teamPayload, 0, limit)
	if err := strictDecodeJSONArray(body, limit, accessTeamObjectRule, func() any {
		payload = append(payload, teamPayload{})
		return &payload[len(payload)-1]
	}); err != nil {
		return nil, 0, err
	}
	teams := make([]AccessTeam, 0, len(payload))
	for _, item := range payload {
		if item.ID == nil || *item.ID <= 0 {
			return nil, 0, ErrResponseMalformed
		}
		teams = append(teams, AccessTeam{ID: *item.ID})
	}
	if total < 0 {
		return nil, 0, ErrTotalCountInvalid
	}
	return teams, total, nil
}

// ReadTeamRepositories reads one page of a team's repository list plus the
// advertised total.
func (c *Client) ReadTeamRepositories(ctx context.Context, teamID int64, page, limit int) ([]ConnectionRepository, int64, error) {
	if teamID <= 0 {
		return nil, 0, ErrResponseMalformed
	}
	return c.readRepositoryPage(ctx, page, limit, "api", "v1", "teams", strconv.FormatInt(teamID, 10), "repos")
}

// readRepositoryPage decodes one strict repository listing page; it backs
// both the organization and team repository reads.
func (c *Client) readRepositoryPage(ctx context.Context, page, limit int, segments ...string) ([]ConnectionRepository, int64, error) {
	if limit < 1 {
		return nil, 0, errPageLimitInvalid
	}
	body, total, err := c.connectionRead(ctx, pageQuery(page, limit), segments...)
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

// ReadTeamMembers reads one page of a team's member list plus the
// advertised total.
func (c *Client) ReadTeamMembers(ctx context.Context, teamID int64, page, limit int) ([]AccessUser, int64, error) {
	if teamID <= 0 {
		return nil, 0, ErrResponseMalformed
	}
	return c.readAccessUserPage(ctx, page, limit, "api", "v1", "teams", strconv.FormatInt(teamID, 10), "members")
}

// ReadRepositoryCollaborators reads one page of a repository's direct
// collaborator list plus the advertised total.
func (c *Client) ReadRepositoryCollaborators(ctx context.Context, owner, repository string, page, limit int) ([]AccessUser, int64, error) {
	return c.readAccessUserPage(ctx, page, limit, "api", "v1", "repos", owner, repository, "collaborators")
}

// ReadUserByUsername reads one user directly by username. The shadow
// snapshot uses it only as the username-at-link fallback and requires the
// returned immutable id to match separately.
func (c *Client) ReadUserByUsername(ctx context.Context, username string) (AccessUser, error) {
	body, _, err := c.connectionRead(ctx, nil, "api", "v1", "users", username)
	if err != nil {
		return AccessUser{}, err
	}
	var payload struct {
		ID    *int64  `json:"id"`
		Login *string `json:"login"`
	}
	if err := strictDecodeJSONObject(body, accessUserObjectRule, &payload); err != nil {
		return AccessUser{}, err
	}
	if payload.ID == nil || *payload.ID <= 0 || payload.Login == nil || *payload.Login == "" {
		return AccessUser{}, ErrResponseMalformed
	}
	return AccessUser{ID: *payload.ID, Login: *payload.Login}, nil
}

// ReadCollaboratorPermission reads the effective permission one exact user
// has on one exact repository. The response must carry the permission plus
// the nested user id and mutable login; role_name is ignored.
func (c *Client) ReadCollaboratorPermission(ctx context.Context, owner, repository, username string) (AccessPermission, error) {
	body, _, err := c.connectionRead(ctx, nil, "api", "v1", "repos", owner, repository, "collaborators", username, "permission")
	if err != nil {
		return AccessPermission{}, err
	}
	var payload struct {
		Permission *string `json:"permission"`
		User       *struct {
			ID    *int64  `json:"id"`
			Login *string `json:"login"`
		} `json:"user"`
	}
	if err := strictDecodeJSONObject(body, accessPermissionObjectRule, &payload); err != nil {
		return AccessPermission{}, err
	}
	if payload.Permission == nil || *payload.Permission == "" ||
		payload.User == nil || payload.User.ID == nil || *payload.User.ID <= 0 ||
		payload.User.Login == nil || *payload.User.Login == "" {
		return AccessPermission{}, ErrResponseMalformed
	}
	return AccessPermission{
		Permission: *payload.Permission,
		User:       AccessUser{ID: *payload.User.ID, Login: *payload.User.Login},
	}, nil
}

func (c *Client) readAccessUserPage(ctx context.Context, page, limit int, segments ...string) ([]AccessUser, int64, error) {
	if limit < 1 {
		return nil, 0, errPageLimitInvalid
	}
	body, total, err := c.connectionRead(ctx, pageQuery(page, limit), segments...)
	if err != nil {
		return nil, 0, err
	}
	type userPayload struct {
		ID    *int64  `json:"id"`
		Login *string `json:"login"`
	}
	payload := make([]userPayload, 0, limit)
	if err := strictDecodeJSONArray(body, limit, accessUserObjectRule, func() any {
		payload = append(payload, userPayload{})
		return &payload[len(payload)-1]
	}); err != nil {
		return nil, 0, err
	}
	users := make([]AccessUser, 0, len(payload))
	for _, item := range payload {
		if item.ID == nil || *item.ID <= 0 || item.Login == nil || *item.Login == "" {
			return nil, 0, ErrResponseMalformed
		}
		users = append(users, AccessUser{ID: *item.ID, Login: *item.Login})
	}
	if total < 0 {
		return nil, 0, ErrTotalCountInvalid
	}
	return users, total, nil
}
