package companyoidc

import (
	"errors"
	"time"
)

type SetupCheckResultCode string

const (
	SetupCheckVerified             SetupCheckResultCode = "verified"
	SetupCheckDiscoveryUnavailable SetupCheckResultCode = "discovery_unavailable"
	SetupCheckDiscoveryInvalid     SetupCheckResultCode = "discovery_invalid"
	SetupCheckIssuerInvalid        SetupCheckResultCode = "issuer_invalid"
	SetupCheckIssuerMismatch       SetupCheckResultCode = "issuer_mismatch"
	SetupCheckMetadataIncompatible SetupCheckResultCode = "metadata_incompatible"
	SetupCheckJWKSUnavailable      SetupCheckResultCode = "jwks_unavailable"
	SetupCheckJWKSInvalid          SetupCheckResultCode = "jwks_invalid"
	SetupCheckJWKSNoCandidate      SetupCheckResultCode = "jwks_no_candidate"
)

func (code SetupCheckResultCode) Valid() bool {
	switch code {
	case SetupCheckVerified,
		SetupCheckDiscoveryUnavailable,
		SetupCheckDiscoveryInvalid,
		SetupCheckIssuerInvalid,
		SetupCheckIssuerMismatch,
		SetupCheckMetadataIncompatible,
		SetupCheckJWKSUnavailable,
		SetupCheckJWKSInvalid,
		SetupCheckJWKSNoCandidate:
		return true
	default:
		return false
	}
}

type SetupCheck struct {
	ConfigRevision          int64
	ResultCode              SetupCheckResultCode
	ObservedIssuer          *string
	PublicKeyCandidateCount *int64
	CheckedAt               time.Time
}

type SetupCheckReport struct {
	ResultCode              SetupCheckResultCode
	ObservedIssuer          *string
	PublicKeyCandidateCount *int64
}

type SetupCheckRowState string

const (
	SetupCheckRowPassed     SetupCheckRowState = "passed"
	SetupCheckRowFailed     SetupCheckRowState = "failed"
	SetupCheckRowNotChecked SetupCheckRowState = "not_checked"
)

type SetupCheckRow struct {
	Label string
	State SetupCheckRowState
}

func SetupCheckRows(check *SetupCheck) [4]SetupCheckRow {
	rows := [4]SetupCheckRow{
		{Label: "Discovery readable", State: SetupCheckRowNotChecked},
		{Label: "Issuer exact", State: SetupCheckRowNotChecked},
		{Label: "Required authorization-code metadata", State: SetupCheckRowNotChecked},
		{Label: "Public-key candidates published", State: SetupCheckRowNotChecked},
	}
	if check == nil {
		return rows
	}

	switch check.ResultCode {
	case SetupCheckVerified:
		for i := range rows {
			rows[i].State = SetupCheckRowPassed
		}
	case SetupCheckDiscoveryUnavailable, SetupCheckDiscoveryInvalid:
		rows[0].State = SetupCheckRowFailed
	case SetupCheckIssuerInvalid, SetupCheckIssuerMismatch:
		rows[0].State = SetupCheckRowPassed
		rows[1].State = SetupCheckRowFailed
	case SetupCheckMetadataIncompatible:
		rows[0].State = SetupCheckRowPassed
		rows[1].State = SetupCheckRowPassed
		rows[2].State = SetupCheckRowFailed
	case SetupCheckJWKSUnavailable, SetupCheckJWKSInvalid, SetupCheckJWKSNoCandidate:
		rows[0].State = SetupCheckRowPassed
		rows[1].State = SetupCheckRowPassed
		rows[2].State = SetupCheckRowPassed
		rows[3].State = SetupCheckRowFailed
	}
	return rows
}

func validateSetupCheck(check SetupCheck, savedIssuer string, currentRevision int64) error {
	if check.ConfigRevision <= 0 || check.ConfigRevision != currentRevision || !check.ResultCode.Valid() || check.CheckedAt.IsZero() {
		return errors.New("company OIDC setup-check evidence is malformed")
	}
	if check.ObservedIssuer != nil {
		normalized, err := normalizeIssuer(*check.ObservedIssuer)
		if err != nil || normalized != *check.ObservedIssuer {
			return errors.New("company OIDC setup-check evidence is malformed")
		}
	}

	switch check.ResultCode {
	case SetupCheckVerified:
		if check.ObservedIssuer != nil || check.PublicKeyCandidateCount == nil || *check.PublicKeyCandidateCount < 1 {
			return errors.New("company OIDC setup-check evidence is malformed")
		}
	case SetupCheckIssuerMismatch:
		if check.ObservedIssuer == nil || *check.ObservedIssuer == savedIssuer || check.PublicKeyCandidateCount != nil {
			return errors.New("company OIDC setup-check evidence is malformed")
		}
	case SetupCheckJWKSNoCandidate:
		if check.ObservedIssuer != nil || check.PublicKeyCandidateCount == nil || *check.PublicKeyCandidateCount != 0 {
			return errors.New("company OIDC setup-check evidence is malformed")
		}
	default:
		if check.ObservedIssuer != nil || check.PublicKeyCandidateCount != nil {
			return errors.New("company OIDC setup-check evidence is malformed")
		}
	}
	return nil
}

func cloneSetupCheck(check *SetupCheck) *SetupCheck {
	if check == nil {
		return nil
	}
	cloned := *check
	if check.ObservedIssuer != nil {
		value := *check.ObservedIssuer
		cloned.ObservedIssuer = &value
	}
	if check.PublicKeyCandidateCount != nil {
		value := *check.PublicKeyCandidateCount
		cloned.PublicKeyCandidateCount = &value
	}
	return &cloned
}
