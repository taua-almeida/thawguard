package companyoidc

import (
	"testing"
	"time"
)

func TestSetupCheckRowsDeriveEveryFixedResultCode(t *testing.T) {
	const passed = "passed"
	const failed = "failed"
	const skipped = "not_checked"
	tests := []struct {
		code SetupCheckResultCode
		want [4]string
	}{
		{code: SetupCheckVerified, want: [4]string{passed, passed, passed, passed}},
		{code: SetupCheckDiscoveryUnavailable, want: [4]string{failed, skipped, skipped, skipped}},
		{code: SetupCheckDiscoveryInvalid, want: [4]string{failed, skipped, skipped, skipped}},
		{code: SetupCheckIssuerInvalid, want: [4]string{passed, failed, skipped, skipped}},
		{code: SetupCheckIssuerMismatch, want: [4]string{passed, failed, skipped, skipped}},
		{code: SetupCheckMetadataIncompatible, want: [4]string{passed, passed, failed, skipped}},
		{code: SetupCheckJWKSUnavailable, want: [4]string{passed, passed, passed, failed}},
		{code: SetupCheckJWKSInvalid, want: [4]string{passed, passed, passed, failed}},
		{code: SetupCheckJWKSNoCandidate, want: [4]string{passed, passed, passed, failed}},
	}
	for _, tc := range tests {
		t.Run(string(tc.code), func(t *testing.T) {
			if !tc.code.Valid() {
				t.Fatalf("fixed result code %q is not valid", tc.code)
			}
			rows := SetupCheckRows(&SetupCheck{ResultCode: tc.code})
			for i, row := range rows {
				if string(row.State) != tc.want[i] {
					t.Fatalf("row %d state = %q, want %q", i, row.State, tc.want[i])
				}
			}
		})
	}
	if SetupCheckResultCode("unknown").Valid() {
		t.Fatal("unknown result code was accepted")
	}
	rows := SetupCheckRows(nil)
	for i, row := range rows {
		if row.State != SetupCheckRowNotChecked {
			t.Fatalf("never-checked row %d state = %q", i, row.State)
		}
	}
	if rows[3].Label != "Public-key candidates published" {
		t.Fatalf("public-key row uses unapproved copy %q", rows[3].Label)
	}
}

func TestValidateSetupCheckRejectsMalformedTypedEvidence(t *testing.T) {
	checkedAt := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	savedIssuer := "https://id.example.test"
	one := int64(1)
	zero := int64(0)
	otherIssuer := "https://other.example.test"
	valid := []SetupCheck{
		{ConfigRevision: 3, ResultCode: SetupCheckVerified, PublicKeyCandidateCount: &one, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckIssuerMismatch, ObservedIssuer: &otherIssuer, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckJWKSNoCandidate, PublicKeyCandidateCount: &zero, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckDiscoveryUnavailable, CheckedAt: checkedAt},
	}
	for _, check := range valid {
		if err := validateSetupCheck(check, savedIssuer, 3); err != nil {
			t.Fatalf("valid %s evidence was rejected: %v", check.ResultCode, err)
		}
	}

	sameIssuer := savedIssuer
	whitespaceIssuer := " https://other.example.test"
	malformed := []SetupCheck{
		{ConfigRevision: 2, ResultCode: SetupCheckVerified, PublicKeyCandidateCount: &one, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: "unknown", CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckVerified, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckVerified, ObservedIssuer: &otherIssuer, PublicKeyCandidateCount: &one, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckIssuerMismatch, ObservedIssuer: &sameIssuer, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckIssuerMismatch, ObservedIssuer: &whitespaceIssuer, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckJWKSNoCandidate, PublicKeyCandidateCount: &one, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckDiscoveryInvalid, PublicKeyCandidateCount: &zero, CheckedAt: checkedAt},
		{ConfigRevision: 3, ResultCode: SetupCheckDiscoveryInvalid},
	}
	for i, check := range malformed {
		if err := validateSetupCheck(check, savedIssuer, 3); err == nil {
			t.Fatalf("malformed evidence %d was accepted: %+v", i, check)
		}
	}
}
