package forgejo

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/taua-almeida/thawguard/internal/domain"
	"github.com/taua-almeida/thawguard/internal/forge"
	"github.com/taua-almeida/thawguard/internal/setupcheck"
)

func TestAdapterTreatsEmptyPullRequestListAsReadable(t *testing.T) {
	result, err := (Adapter{Client: &fakeClient{}}).InspectPullRequestRead(context.Background(), testRepository(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != setupcheck.CheckPullRequestReadAccess || result.Status != setupcheck.StatusOK {
		t.Fatalf("unexpected result %+v", result)
	}
}

func TestAdapterTreatsPullRequestAuthorizationDenialAsFailedEvidence(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			clientErr := &forge.ResponseError{Operation: "list open pull requests", StatusCode: status, Status: "denied", Snippet: "denied"}
			result, err := (Adapter{Client: &fakeClient{pullRequestErr: clientErr}}).InspectPullRequestRead(context.Background(), testRepository(), "main")
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != setupcheck.StatusFailed {
				t.Fatalf("expected failed evidence, got %+v", result)
			}
		})
	}
}

func TestAdapterReturnsOperationalPullRequestError(t *testing.T) {
	_, err := (Adapter{Client: &fakeClient{pullRequestErr: errors.New("network unavailable")}}).InspectPullRequestRead(context.Background(), testRepository(), "main")
	if err == nil {
		t.Fatal("expected operational error")
	}
}

func TestAdapterInspectsProtectedBranchWithExactContext(t *testing.T) {
	client := &fakeClient{protection: map[string]forge.BranchProtection{
		"main": {Branch: "main", Protected: true, RequiresStatusCheck: true, RequiredContexts: []string{domain.RequiredStatusContext}},
	}}
	inspection, err := (Adapter{Client: client}).InspectBranch(context.Background(), testRepository(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.Protected || len(inspection.Results) != 4 {
		t.Fatalf("unexpected inspection %+v", inspection)
	}
	for _, result := range inspection.Results {
		if result.Status != setupcheck.StatusOK {
			t.Fatalf("expected all checks OK, got %+v", inspection.Results)
		}
	}
}

func TestAdapterDoesNotAcceptSimilarContext(t *testing.T) {
	client := &fakeClient{protection: map[string]forge.BranchProtection{
		"main": {Branch: "main", Protected: true, RequiresStatusCheck: true, RequiredContexts: []string{domain.RequiredStatusContext + "-preview"}},
	}}
	inspection, err := (Adapter{Client: client}).InspectBranch(context.Background(), testRepository(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Results[3].Status != setupcheck.StatusFailed {
		t.Fatalf("expected exact-context failure, got %+v", inspection.Results[3])
	}
}

func TestAdapterReportsDisabledStatusChecksSeparately(t *testing.T) {
	client := &fakeClient{protection: map[string]forge.BranchProtection{
		"main": {Branch: "main", Protected: true},
	}}
	inspection, err := (Adapter{Client: client}).InspectBranch(context.Background(), testRepository(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Results[0].Status != setupcheck.StatusOK || inspection.Results[1].Status != setupcheck.StatusOK || inspection.Results[2].Status != setupcheck.StatusFailed || inspection.Results[3].Status != setupcheck.StatusFailed {
		t.Fatalf("unexpected separate results %+v", inspection.Results)
	}
}

func TestAdapterTranslatesNotFoundToUnprotectedEvidence(t *testing.T) {
	client := &fakeClient{protectionErr: map[string]error{"release": forge.ErrBranchProtectionNotFound}}
	inspection, err := (Adapter{Client: client}).InspectBranch(context.Background(), testRepository(), "release")
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Protected || inspection.Results[0].Status != setupcheck.StatusOK || inspection.Results[1].Status != setupcheck.StatusFailed {
		t.Fatalf("unexpected unprotected evidence %+v", inspection)
	}
}

func TestAdapterReturnsBranchOperationalError(t *testing.T) {
	client := &fakeClient{protectionErr: map[string]error{"main": errors.New("network unavailable")}}
	if _, err := (Adapter{Client: client}).InspectBranch(context.Background(), testRepository(), "main"); err == nil {
		t.Fatal("expected operational error")
	}
}

type fakeClient struct {
	pullRequestErr error
	protection     map[string]forge.BranchProtection
	protectionErr  map[string]error
}

func (c *fakeClient) ListOpenPullRequests(context.Context, string, string, string) ([]domain.PullRequest, error) {
	return nil, c.pullRequestErr
}

func (c *fakeClient) ReadBranchProtection(_ context.Context, _, _, branch string) (forge.BranchProtection, error) {
	if err := c.protectionErr[branch]; err != nil {
		return forge.BranchProtection{Branch: branch}, err
	}
	return c.protection[branch], nil
}

func testRepository() domain.Repository {
	return domain.Repository{Owner: "taua-almeida", Name: "thawguard", DefaultBranch: "main"}
}
