package companyoidc

import (
	"errors"
	"time"
)

// TestSignInEvidence is the one current successful Administrator Test sign-in
// proof for the exact saved Draft revision. Failed Test sign-ins never produce
// evidence, and a real Draft edit deletes it in the same transaction.
type TestSignInEvidence struct {
	ConfigRevision int64
	VerifiedAt     time.Time
}

func validateTestSignInEvidence(evidence TestSignInEvidence, currentRevision int64) error {
	if evidence.ConfigRevision <= 0 || evidence.ConfigRevision != currentRevision || evidence.VerifiedAt.IsZero() {
		return errors.New("company OIDC test sign-in evidence is malformed")
	}
	return nil
}

func cloneTestSignInEvidence(evidence *TestSignInEvidence) *TestSignInEvidence {
	if evidence == nil {
		return nil
	}
	cloned := *evidence
	return &cloned
}
