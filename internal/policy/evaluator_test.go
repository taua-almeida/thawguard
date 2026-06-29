package policy

import (
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestEvaluateAllowsUnfrozenBranch(t *testing.T) {
	decision := Evaluate(Input{PullRequest: pr(1, "abc123")})
	if decision.State != domain.CommitStatusSuccess {
		t.Fatalf("expected success, got %s", decision.State)
	}
}

func TestEvaluateBlocksFrozenBranch(t *testing.T) {
	decision := Evaluate(Input{PullRequest: pr(1, "abc123"), ActiveFreeze: freeze("main")})
	if decision.State != domain.CommitStatusFailure || decision.Reason != "active_freeze" {
		t.Fatalf("expected active freeze failure, got %+v", decision)
	}
}

func TestEvaluateAllowsUniqueThawedPR(t *testing.T) {
	decision := Evaluate(Input{
		PullRequest:   pr(1, "abc123"),
		ActiveFreeze:  freeze("main"),
		ThawException: thaw(1, "abc123"),
		OpenPullRequests: []domain.PullRequest{
			pr(1, "abc123"),
			pr(2, "def456"),
		},
		Now: time.Date(2026, 6, 28, 0, 0, 0, 0, time.UTC),
	})

	if decision.State != domain.CommitStatusSuccess || decision.Reason != "thawed_exception" {
		t.Fatalf("expected thaw success, got %+v", decision)
	}
}

func TestEvaluateBlocksDuplicateHeadThaw(t *testing.T) {
	decision := Evaluate(Input{
		PullRequest:   pr(1, "abc123"),
		ActiveFreeze:  freeze("main"),
		ThawException: thaw(1, "abc123"),
		OpenPullRequests: []domain.PullRequest{
			pr(1, "abc123"),
			pr(2, "abc123"),
		},
	})

	if decision.State != domain.CommitStatusFailure || decision.Reason != "duplicate_head_sha" {
		t.Fatalf("expected duplicate-head failure, got %+v", decision)
	}
}

func pr(id int64, sha string) domain.PullRequest {
	return domain.PullRequest{ID: id, RepositoryID: 10, Index: int(id), State: "open", TargetBranch: "main", HeadSHA: sha}
}

func freeze(branch string) *domain.BranchFreeze {
	return &domain.BranchFreeze{ID: 1, RepositoryID: 10, Branch: branch, Active: true, Reason: "release window"}
}

func thaw(prID int64, sha string) *domain.ThawException {
	return &domain.ThawException{ID: 1, PullRequestID: prID, HeadSHA: sha, Active: true, Reason: "urgent fix"}
}
