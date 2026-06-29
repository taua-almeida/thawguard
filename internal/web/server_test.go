package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/repository"
)

func TestRepositoriesPageShowsManualSetupContext(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: &fakeRepositoryStore{repositories: []domain.Repository{{Owner: "taua-almeida", Name: "thawguard", Forge: "forgejo", DefaultBranch: "main"}}}})
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/repositories", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, domain.RequiredStatusContext) {
		t.Fatalf("expected body to mention required context %s", domain.RequiredStatusContext)
	}
	if !strings.Contains(body, "taua-almeida/thawguard") {
		t.Fatalf("expected body to include repository full name, got %q", body)
	}
}

func TestCreateRepositoryPostsToStore(t *testing.T) {
	store := &fakeRepositoryStore{}
	server := NewServer(Config{AppName: "Thawguard", RepositoryStore: store})
	form := url.Values{
		"forge":          {"forgejo"},
		"base_url":       {"https://codeberg.org"},
		"owner":          {"taua-almeida"},
		"name":           {"thawguard"},
		"default_branch": {"main"},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/repositories", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.Routes().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if len(store.created) != 1 {
		t.Fatalf("expected 1 created repository, got %d", len(store.created))
	}
	if store.created[0].Owner != "taua-almeida" || store.created[0].Name != "thawguard" {
		t.Fatalf("unexpected create params: %+v", store.created[0])
	}
}

type fakeRepositoryStore struct {
	repositories []domain.Repository
	created      []repository.CreateParams
}

func (s *fakeRepositoryStore) List(ctx context.Context) ([]domain.Repository, error) {
	return s.repositories, nil
}

func (s *fakeRepositoryStore) Create(ctx context.Context, params repository.CreateParams) (domain.Repository, error) {
	s.created = append(s.created, params)
	repo := domain.Repository{ID: int64(len(s.repositories) + 1), Forge: params.Forge, BaseURL: params.BaseURL, Owner: params.Owner, Name: params.Name, DefaultBranch: params.DefaultBranch, Active: true}
	s.repositories = append(s.repositories, repo)
	return repo, nil
}
