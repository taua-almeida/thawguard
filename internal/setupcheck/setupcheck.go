package setupcheck

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
