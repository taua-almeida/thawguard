package setupcheck

import "github.com/taua-almeida/thawguard/internal/domain"

type Status string

const (
	StatusOK      Status = "ok"
	StatusWarning Status = "warning"
	StatusFailed  Status = "failed"
)

type Result struct {
	Name        string
	Status      Status
	Description string
	Remediation string
}

type Report struct {
	CanPostStatuses        bool
	RequiredContextPresent bool
	WebhookConfigured      bool
}

func Evaluate(report Report) []Result {
	return []Result{
		{
			Name:        "Bot can post statuses",
			Status:      statusFromBool(report.CanPostStatuses),
			Description: "Thawguard must be able to publish commit statuses for PR head SHAs.",
			Remediation: "Use a Forgejo/Codeberg token with permission to write repository statuses.",
		},
		{
			Name:        "Required status context configured",
			Status:      statusFromBool(report.RequiredContextPresent),
			Description: "Branch protection must require the exact context " + domain.RequiredStatusContext + ".",
			Remediation: "Add " + domain.RequiredStatusContext + " to the branch protection required status checks.",
		},
		{
			Name:        "Pull request webhook configured",
			Status:      statusFromBool(report.WebhookConfigured),
			Description: "PR webhooks let Thawguard recompute status when PRs open, update, retarget, or close.",
			Remediation: "Configure pull_request webhooks with a shared secret and verify delivery health.",
		},
	}
}

func statusFromBool(ok bool) Status {
	if ok {
		return StatusOK
	}
	return StatusFailed
}

func ManualSetupSteps() []string {
	return []string{
		"Create or choose a Forgejo/Codeberg bot token that can post commit statuses.",
		"Add a pull_request webhook pointing at this Thawguard instance.",
		"Configure branch protection to require the exact status context " + domain.RequiredStatusContext + ".",
		"Run setup health checks before relying on a freeze.",
	}
}
