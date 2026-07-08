package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/taua-almeida/thawguard/internal/audit"
	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestForgeOpenPullRequestSyncerCachesOpenPullRequests(t *testing.T) {
	ctx := context.Background()
	repositories := &fakeOpenPRRepositoryGetter{repo: domain.Repository{ID: 7, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeOpenPRStatusTokenGetter{token: "sync-token", found: true}
	upserter := &fakeOpenPRUpserter{}
	client := &fakeOpenPRForgeClient{prs: []domain.PullRequest{
		{Index: 11, State: "open", TargetBranch: "main", HeadSHA: "abcdef123456", Title: "Before webhook"},
		{Index: 12, State: "open", TargetBranch: "main", HeadSHA: "bbbbbb123456", Title: "Also open"},
	}}
	syncer := newForgeOpenPullRequestSyncer(repositories, tokens, upserter, []string{"taua-almeida/thawguard"}, func(repo domain.Repository, token string) (openPullRequestForgeClient, error) {
		if token != "sync-token" {
			t.Fatalf("unexpected token %q", token)
		}
		return client, nil
	})

	if err := syncer.SyncOpenPullRequests(ctx, 7, "main"); err != nil {
		t.Fatal(err)
	}
	if client.owner != "taua-almeida" || client.repo != "thawguard" || client.targetBranch != "main" {
		t.Fatalf("unexpected list request owner=%q repo=%q branch=%q", client.owner, client.repo, client.targetBranch)
	}
	if len(upserter.prs) != 2 {
		t.Fatalf("expected two cached PRs, got %+v", upserter.prs)
	}
	if len(upserter.closedAbsent) != 1 || upserter.closedAbsent[0].repositoryID != 7 || upserter.closedAbsent[0].targetBranch != "main" || len(upserter.closedAbsent[0].openIndexes) != 2 || upserter.closedAbsent[0].openIndexes[0] != 11 || upserter.closedAbsent[0].openIndexes[1] != 12 {
		t.Fatalf("expected branch cache to reconcile to current forge open PR list, got %+v", upserter.closedAbsent)
	}
	for _, pr := range upserter.prs {
		if pr.RepositoryID != 7 || pr.TargetBranch != "main" {
			t.Fatalf("expected synced repository and branch on cached PR, got %+v", pr)
		}
	}
}

func TestForgeOpenPullRequestSyncerRecordsAuditEvent(t *testing.T) {
	ctx := context.Background()
	repositories := &fakeOpenPRRepositoryGetter{repo: domain.Repository{ID: 7, Forge: "codeberg", BaseURL: "https://codeberg.org", Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeOpenPRStatusTokenGetter{token: "sync-token", found: true}
	upserter := &fakeOpenPRUpserter{closedAbsentCount: 3}
	client := &fakeOpenPRForgeClient{prs: []domain.PullRequest{{Index: 11, State: "open", TargetBranch: "main", HeadSHA: "abcdef123456"}}}
	auditor := &fakeOpenPRAuditRecorder{}
	syncer := newForgeOpenPullRequestSyncer(repositories, tokens, upserter, []string{"taua-almeida/thawguard"}, func(repo domain.Repository, token string) (openPullRequestForgeClient, error) {
		return client, nil
	}, auditor)

	if err := syncer.SyncOpenPullRequests(ctx, 7, "main"); err != nil {
		t.Fatal(err)
	}
	if len(auditor.events) != 1 {
		t.Fatalf("expected one audit event, got %+v", auditor.events)
	}
	event := auditor.events[0]
	if event.Action != audit.ActionRepositoryOpenPullRequestsSynced || event.SubjectType != audit.SubjectTypeRepository || event.SubjectID != "7" {
		t.Fatalf("unexpected audit event: %+v", event)
	}
	var details map[string]string
	if err := json.Unmarshal([]byte(event.DetailsJSON), &details); err != nil {
		t.Fatal(err)
	}
	if details["full_name"] != "taua-almeida/thawguard" || details["target_branch"] != "main" || details["open_count"] != "1" || details["closed_absent_count"] != "3" {
		t.Fatalf("unexpected audit details: %+v", details)
	}
}

func TestForgeOpenPullRequestSyncerRequiresAllowlistedRepository(t *testing.T) {
	repositories := &fakeOpenPRRepositoryGetter{repo: domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeOpenPRStatusTokenGetter{token: "sync-token", found: true}
	syncer := newForgeOpenPullRequestSyncer(repositories, tokens, &fakeOpenPRUpserter{}, []string{"other/repo"}, func(repo domain.Repository, token string) (openPullRequestForgeClient, error) {
		t.Fatal("client factory should not be called for repository outside allowlist")
		return nil, nil
	})

	err := syncer.SyncOpenPullRequests(context.Background(), 7, "main")
	if !errors.Is(err, ErrOpenPullRequestSyncRepositoryNotAllowed) {
		t.Fatalf("expected repository allowlist error, got %v", err)
	}
	if tokens.calls != 0 {
		t.Fatalf("expected no token lookup for repository outside allowlist, got %d", tokens.calls)
	}
}

func TestForgeOpenPullRequestSyncerRequiresStatusToken(t *testing.T) {
	repositories := &fakeOpenPRRepositoryGetter{repo: domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeOpenPRStatusTokenGetter{}
	syncer := newForgeOpenPullRequestSyncer(repositories, tokens, &fakeOpenPRUpserter{}, []string{"taua-almeida/thawguard"}, func(repo domain.Repository, token string) (openPullRequestForgeClient, error) {
		t.Fatal("client factory should not be called without token")
		return nil, nil
	})

	err := syncer.SyncOpenPullRequests(context.Background(), 7, "main")
	if !errors.Is(err, ErrOpenPullRequestSyncStatusTokenMissing) {
		t.Fatalf("expected status token missing error, got %v", err)
	}
}

func TestForgeOpenPullRequestSyncerRedactsTokenFromListErrors(t *testing.T) {
	repositories := &fakeOpenPRRepositoryGetter{repo: domain.Repository{ID: 7, Owner: "taua-almeida", Name: "thawguard"}}
	tokens := &fakeOpenPRStatusTokenGetter{token: "sync-token", found: true}
	client := &fakeOpenPRForgeClient{err: errors.New("forge said sync-token is invalid")}
	syncer := newForgeOpenPullRequestSyncer(repositories, tokens, &fakeOpenPRUpserter{}, []string{"taua-almeida/thawguard"}, func(repo domain.Repository, token string) (openPullRequestForgeClient, error) {
		return client, nil
	})

	err := syncer.SyncOpenPullRequests(context.Background(), 7, "main")
	if err == nil {
		t.Fatal("expected list error")
	}
	if strings.Contains(err.Error(), "sync-token") {
		t.Fatalf("expected token to be redacted, got %q", err.Error())
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("expected redacted marker, got %q", err.Error())
	}
}

type fakeOpenPRRepositoryGetter struct {
	repo domain.Repository
	err  error
}

func (g *fakeOpenPRRepositoryGetter) Get(ctx context.Context, id int64) (domain.Repository, error) {
	if g.err != nil {
		return domain.Repository{}, g.err
	}
	return g.repo, nil
}

type fakeOpenPRStatusTokenGetter struct {
	token string
	found bool
	err   error
	calls int
}

func (g *fakeOpenPRStatusTokenGetter) StatusToken(ctx context.Context, repositoryID int64) (string, bool, error) {
	g.calls++
	if g.err != nil {
		return "", false, g.err
	}
	return g.token, g.found, nil
}

type fakeOpenPRUpserter struct {
	prs               []domain.PullRequest
	closedAbsent      []fakeClosedAbsentOpenPRs
	closedAbsentCount int64
	err               error
}

type fakeClosedAbsentOpenPRs struct {
	repositoryID int64
	targetBranch string
	openIndexes  []int
}

func (u *fakeOpenPRUpserter) Upsert(ctx context.Context, pr domain.PullRequest) (domain.PullRequest, error) {
	if u.err != nil {
		return domain.PullRequest{}, u.err
	}
	u.prs = append(u.prs, pr)
	return pr, nil
}

func (u *fakeOpenPRUpserter) MarkAbsentOpenByTargetBranchClosed(ctx context.Context, repositoryID int64, targetBranch string, openIndexes []int) (int64, error) {
	if u.err != nil {
		return 0, u.err
	}
	u.closedAbsent = append(u.closedAbsent, fakeClosedAbsentOpenPRs{repositoryID: repositoryID, targetBranch: targetBranch, openIndexes: append([]int(nil), openIndexes...)})
	return u.closedAbsentCount, nil
}

type fakeOpenPRAuditRecorder struct {
	events []audit.Event
	err    error
}

func (r *fakeOpenPRAuditRecorder) Record(ctx context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return r.err
}

type fakeOpenPRForgeClient struct {
	prs          []domain.PullRequest
	err          error
	owner        string
	repo         string
	targetBranch string
}

func (c *fakeOpenPRForgeClient) ListOpenPullRequests(ctx context.Context, owner, repo, targetBranch string) ([]domain.PullRequest, error) {
	c.owner = owner
	c.repo = repo
	c.targetBranch = targetBranch
	if c.err != nil {
		return nil, c.err
	}
	return c.prs, nil
}
