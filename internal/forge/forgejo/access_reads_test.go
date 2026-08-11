package forgejo

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadOrganizationDecodesStrictly(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "ok", body: `{"id":7,"name":"fixture-org","full_name":"Fixture Organization"}`},
		{name: "missing id", body: `{"name":"fixture-org","full_name":""}`, wantErr: true},
		{name: "zero id", body: `{"id":0,"name":"fixture-org","full_name":""}`, wantErr: true},
		{name: "missing name", body: `{"id":7,"full_name":""}`, wantErr: true},
		{name: "duplicate id member", body: `{"id":7,"id":8,"name":"fixture-org","full_name":""}`, wantErr: true},
		{name: "case-aliased critical member", body: `{"id":7,"Name":"evil","name":"fixture-org","full_name":""}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := jsonServer(t, "/api/v1/orgs/fixture-org", tc.body, nil)
			defer server.Close()
			client := New(server.URL, "fixture-token")
			organization, err := client.ReadOrganization(context.Background(), "fixture-org")
			if tc.wantErr {
				if !errors.Is(err, ErrResponseMalformed) {
					t.Fatalf("expected malformed response, got %v", err)
				}
				return
			}
			if err != nil || organization.ID != 7 || organization.Name != "fixture-org" {
				t.Fatalf("organization = %+v err=%v", organization, err)
			}
		})
	}
}

func TestAccessUserListingsValidateRecordsAndTotals(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		total   string
		wantErr error
	}{
		{name: "ok", body: `[{"id":77,"login":"admin-user"}]`, total: "1"},
		{name: "missing login", body: `[{"id":77}]`, total: "1", wantErr: ErrResponseMalformed},
		{name: "zero id", body: `[{"id":0,"login":"admin-user"}]`, total: "1", wantErr: ErrResponseMalformed},
		{name: "duplicate member", body: `[{"id":77,"id":78,"login":"admin-user"}]`, total: "1", wantErr: ErrResponseMalformed},
		{name: "case-aliased member", body: `[{"ID":1,"id":77,"login":"admin-user"}]`, total: "1", wantErr: ErrResponseMalformed},
		{name: "missing total", body: `[{"id":77,"login":"admin-user"}]`, total: "", wantErr: ErrTotalCountInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.total != "" {
				headers["X-Total-Count"] = tc.total
			}
			server := jsonServer(t, "/api/v1/orgs/fixture-org/members", tc.body, headers)
			defer server.Close()
			client := New(server.URL, "fixture-token")
			members, total, err := client.ReadOrganizationMembers(context.Background(), "fixture-org", 1, 50)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil || total != 1 || len(members) != 1 || members[0].ID != 77 || members[0].Login != "admin-user" {
				t.Fatalf("members=%+v total=%d err=%v", members, total, err)
			}
		})
	}
}

func TestReadOrganizationTeamsReadsOnlyImmutableIDs(t *testing.T) {
	server := jsonServer(t, "/api/v1/orgs/fixture-org/teams",
		`[{"id":5,"name":"Owners","permission":"owner"},{"id":6}]`,
		map[string]string{"X-Total-Count": "2"})
	defer server.Close()
	client := New(server.URL, "fixture-token")
	teams, total, err := client.ReadOrganizationTeams(context.Background(), "fixture-org", 1, 50)
	if err != nil || total != 2 || len(teams) != 2 || teams[0].ID != 5 || teams[1].ID != 6 {
		t.Fatalf("teams=%+v total=%d err=%v", teams, total, err)
	}
}

func TestReadTeamListingsRequirePositiveTeamID(t *testing.T) {
	client := New("https://forge.example.test", "fixture-token")
	if _, _, err := client.ReadTeamRepositories(context.Background(), 0, 1, 50); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected rejection for team id 0, got %v", err)
	}
	if _, _, err := client.ReadTeamMembers(context.Background(), -1, 1, 50); !errors.Is(err, ErrResponseMalformed) {
		t.Fatalf("expected rejection for negative team id, got %v", err)
	}
}

func TestReadUserByUsernameRequiresCompleteIdentity(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "ok", body: `{"id":78,"login":"dev-user"}`},
		{name: "missing id", body: `{"login":"dev-user"}`, wantErr: true},
		{name: "empty login", body: `{"id":78,"login":""}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := jsonServer(t, "/api/v1/users/dev-user", tc.body, nil)
			defer server.Close()
			client := New(server.URL, "fixture-token")
			user, err := client.ReadUserByUsername(context.Background(), "dev-user")
			if tc.wantErr {
				if !errors.Is(err, ErrResponseMalformed) {
					t.Fatalf("expected malformed response, got %v", err)
				}
				return
			}
			if err != nil || user.ID != 78 || user.Login != "dev-user" {
				t.Fatalf("user = %+v err=%v", user, err)
			}
		})
	}
}

func TestReadCollaboratorPermissionDecodesStrictly(t *testing.T) {
	const path = "/api/v1/repos/fixture-org/alpha/collaborators/dev-user/permission"
	cases := []struct {
		name       string
		body       string
		status     int
		wantErr    bool
		wantStatus int
	}{
		{name: "ok ignoring role_name", body: `{"permission":"write","role_name":"anything","user":{"id":78,"login":"dev-user"}}`},
		{name: "missing permission", body: `{"user":{"id":78,"login":"dev-user"}}`, wantErr: true},
		{name: "empty permission", body: `{"permission":"","user":{"id":78,"login":"dev-user"}}`, wantErr: true},
		{name: "missing user", body: `{"permission":"write"}`, wantErr: true},
		{name: "null user", body: `{"permission":"write","user":null}`, wantErr: true},
		{name: "missing nested id", body: `{"permission":"write","user":{"login":"dev-user"}}`, wantErr: true},
		{name: "duplicate nested member", body: `{"permission":"write","user":{"id":78,"id":79,"login":"dev-user"}}`, wantErr: true},
		{name: "case-aliased permission", body: `{"Permission":"none","permission":"write","user":{"id":78,"login":"dev-user"}}`, wantErr: true},
		{name: "not found", body: `{}`, status: http.StatusNotFound, wantStatus: http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != path {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			client := New(server.URL, "fixture-token")
			permission, err := client.ReadCollaboratorPermission(context.Background(), "fixture-org", "alpha", "dev-user")
			if tc.wantStatus != 0 {
				var statusErr *StatusError
				if !errors.As(err, &statusErr) || statusErr.StatusCode != tc.wantStatus {
					t.Fatalf("expected status %d, got %v", tc.wantStatus, err)
				}
				return
			}
			if tc.wantErr {
				if !errors.Is(err, ErrResponseMalformed) {
					t.Fatalf("expected malformed response, got %v", err)
				}
				return
			}
			if err != nil || permission.Permission != "write" ||
				permission.User.ID != 78 || permission.User.Login != "dev-user" {
				t.Fatalf("permission = %+v err=%v", permission, err)
			}
		})
	}
}
