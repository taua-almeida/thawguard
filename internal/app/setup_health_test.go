package app

import (
	"context"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

func TestLocalSetupHealthRunnerRecordsWarnings(t *testing.T) {
	recorder := &fakeSetupCheckRecorder{}
	runner := localSetupHealthRunner{recorder: recorder}
	repo := domain.Repository{ID: 42, DefaultBranch: "main"}

	results, err := runner.Run(context.Background(), repo)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 local setup results, got %d", len(results))
	}
	for _, result := range results {
		if result.Status != setupcheck.StatusWarning {
			t.Fatalf("expected warning status for local placeholder, got %+v", result)
		}
	}
	if recorder.repositoryID != repo.ID || recorder.branch != repo.DefaultBranch {
		t.Fatalf("unexpected record target: repo=%d branch=%q", recorder.repositoryID, recorder.branch)
	}
}

type fakeSetupCheckRecorder struct {
	repositoryID int64
	branch       string
	results      []setupcheck.Result
}

func (r *fakeSetupCheckRecorder) Record(ctx context.Context, repositoryID int64, branch string, results []setupcheck.Result) error {
	r.repositoryID = repositoryID
	r.branch = branch
	r.results = append([]setupcheck.Result(nil), results...)
	return nil
}
