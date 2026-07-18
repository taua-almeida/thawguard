package web

import (
	"testing"
	"time"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/domain"
)

func TestFreezeCreatedByLabelResolvesActorVariants(t *testing.T) {
	userID := int64(4)
	removedID := int64(9)
	usersByID := map[int64]auth.User{4: {ID: 4, Email: "rana.kall@example.test"}}

	cases := []struct {
		name   string
		freeze domain.BranchFreeze
		users  map[int64]auth.User
		want   string
	}{
		{name: "user found renders email", freeze: domain.BranchFreeze{CreatedByUserID: &userID, CreatedByKind: domain.ActorKindUser}, users: usersByID, want: "rana.kall@example.test"},
		{name: "bootstrap admin", freeze: domain.BranchFreeze{CreatedByKind: domain.ActorKindBootstrapAdmin}, users: usersByID, want: "bootstrap admin"},
		{name: "system renders via schedule", freeze: domain.BranchFreeze{CreatedByKind: domain.ActorKindSystem}, users: usersByID, want: "via schedule"},
		{name: "deleted user with kind", freeze: domain.BranchFreeze{CreatedByKind: domain.ActorKindUser}, users: usersByID, want: "a removed user"},
		{name: "deleted user without kind", freeze: domain.BranchFreeze{CreatedByUserID: &removedID}, users: usersByID, want: "a removed user"},
		{name: "pre-backfill gap omits label", freeze: domain.BranchFreeze{}, users: usersByID, want: ""},
		{name: "nil users map omits label", freeze: domain.BranchFreeze{CreatedByUserID: &userID, CreatedByKind: domain.ActorKindUser}, users: nil, want: ""},
	}
	for _, tc := range cases {
		if got := freezeCreatedByLabel(tc.freeze, tc.users); got != tc.want {
			t.Errorf("%s: expected %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestFreezeViewsFormatStartedLabelFromStartsAt(t *testing.T) {
	server := NewServer(Config{AppName: "Thawguard"})
	startsAt := time.Date(2026, 7, 16, 14, 5, 0, 0, time.UTC)
	createdAt := time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC)
	userID := int64(4)
	freezes := []domain.BranchFreeze{
		{ID: 1, RepositoryID: 7, Branch: "main", StartsAt: &startsAt, CreatedAt: createdAt, CreatedByUserID: &userID, CreatedByKind: domain.ActorKindUser},
		{ID: 2, RepositoryID: 7, Branch: "dev", CreatedAt: createdAt},
		{ID: 3, RepositoryID: 7, Branch: "release"},
	}
	usersByID := map[int64]auth.User{4: {ID: 4, Email: "rana.kall@example.test"}}

	views := server.freezeViews([]domain.Repository{{ID: 7}}, freezes, usersByID)

	if views[0].StartedLabel != "2026-07-16" {
		t.Fatalf("expected StartsAt date label, got %q", views[0].StartedLabel)
	}
	if views[0].StartedTitle != "2026-07-16T14:05:00Z" {
		t.Fatalf("expected full RFC3339 title, got %q", views[0].StartedTitle)
	}
	if views[0].CreatedByLabel != "rana.kall@example.test" {
		t.Fatalf("expected email label, got %q", views[0].CreatedByLabel)
	}
	if views[1].StartedLabel != "2026-07-15" {
		t.Fatalf("expected CreatedAt fallback date label, got %q", views[1].StartedLabel)
	}
	if views[2].StartedLabel != "" {
		t.Fatalf("expected no label for zero timestamps, got %q", views[2].StartedLabel)
	}
}
