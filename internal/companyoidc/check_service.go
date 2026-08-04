package companyoidc

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/taua-almeida/thawguard/internal/audit"
)

var (
	ErrNoDraft             = errors.New("no saved company OIDC Draft is available to check")
	ErrCheckStale          = errors.New("the company OIDC Draft changed during the metadata check; run it again")
	ErrCheckOutcomeUnknown = errors.New("the company OIDC metadata-check outcome could not be confirmed")
)

const checkSnapshotQuery = `
SELECT issuer, revision, enabled
FROM company_oidc_connections
WHERE id = 1`

type checkSnapshot struct {
	issuer   string
	revision int64
	enabled  bool
}

func (s *Service) Check(ctx context.Context, actorUserID int64) (SetupCheck, error) {
	if s == nil || s.db == nil {
		return SetupCheck{}, errors.New("company OIDC service has no database")
	}
	if s.secrets == nil {
		return SetupCheck{}, ErrConfiguration
	}
	if s.check == nil {
		return SetupCheck{}, errors.New("company OIDC metadata checker is not configured")
	}

	snapshot, err := s.checkSnapshot(ctx, actorUserID)
	if err != nil {
		return SetupCheck{}, err
	}
	report := s.check(ctx, snapshot.issuer)
	check := SetupCheck{
		ConfigRevision:          snapshot.revision,
		ResultCode:              report.ResultCode,
		ObservedIssuer:          report.ObservedIssuer,
		PublicKeyCandidateCount: report.PublicKeyCandidateCount,
		CheckedAt:               s.now().UTC(),
	}
	if err := validateSetupCheck(check, snapshot.issuer, snapshot.revision); err != nil {
		return SetupCheck{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return SetupCheck{}, fmt.Errorf("begin company OIDC setup-check persistence: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return SetupCheck{}, err
	}
	current, found, err := loadCheckSnapshot(ctx, tx)
	if err != nil {
		return SetupCheck{}, err
	}
	if !found || current.revision != snapshot.revision || current.issuer != snapshot.issuer {
		return SetupCheck{}, ErrCheckStale
	}
	if current.enabled {
		return SetupCheck{}, ErrEnabled
	}
	if err := replaceSetupCheck(ctx, tx, check); err != nil {
		return SetupCheck{}, err
	}
	if err := recordMetadataChecked(ctx, tx, actorUserID, check); err != nil {
		return SetupCheck{}, err
	}
	if err := tx.Commit(); err != nil {
		return SetupCheck{}, ErrCheckOutcomeUnknown
	}
	return *cloneSetupCheck(&check), nil
}

func (s *Service) checkSnapshot(ctx context.Context, actorUserID int64) (checkSnapshot, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return checkSnapshot{}, fmt.Errorf("begin company OIDC setup-check snapshot: %w", err)
	}
	defer tx.Rollback()
	if err := lockEnabledAdminActor(ctx, tx, actorUserID); err != nil {
		return checkSnapshot{}, err
	}
	snapshot, found, err := loadCheckSnapshot(ctx, tx)
	if err != nil {
		return checkSnapshot{}, err
	}
	if !found {
		return checkSnapshot{}, ErrNoDraft
	}
	if snapshot.enabled {
		return checkSnapshot{}, ErrEnabled
	}
	if err := tx.Commit(); err != nil {
		return checkSnapshot{}, fmt.Errorf("commit company OIDC setup-check snapshot: %w", err)
	}
	return snapshot, nil
}

func loadCheckSnapshot(ctx context.Context, tx *sql.Tx) (checkSnapshot, bool, error) {
	var snapshot checkSnapshot
	var enabled int64
	err := tx.QueryRowContext(ctx, checkSnapshotQuery).Scan(&snapshot.issuer, &snapshot.revision, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return checkSnapshot{}, false, nil
	}
	if err != nil {
		return checkSnapshot{}, false, fmt.Errorf("read company OIDC setup-check snapshot: %w", err)
	}
	if !validExactIssuer(snapshot.issuer) || snapshot.revision <= 0 || enabled < 0 || enabled > 1 {
		return checkSnapshot{}, false, errors.New("company OIDC setup-check snapshot is malformed")
	}
	snapshot.enabled = enabled == 1
	return snapshot, true, nil
}

func replaceSetupCheck(ctx context.Context, tx *sql.Tx, check SetupCheck) error {
	var observedIssuer any
	if check.ObservedIssuer != nil {
		observedIssuer = *check.ObservedIssuer
	}
	var candidateCount any
	if check.PublicKeyCandidateCount != nil {
		candidateCount = *check.PublicKeyCandidateCount
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO company_oidc_setup_checks(
  connection_id, config_revision, result_code, observed_issuer,
  public_key_candidate_count, checked_at
)
VALUES (1, ?, ?, ?, ?, ?)
ON CONFLICT(connection_id) DO UPDATE SET
  config_revision = excluded.config_revision,
  result_code = excluded.result_code,
  observed_issuer = excluded.observed_issuer,
  public_key_candidate_count = excluded.public_key_candidate_count,
  checked_at = excluded.checked_at`,
		check.ConfigRevision,
		string(check.ResultCode),
		observedIssuer,
		candidateCount,
		formatCompanyOIDCTime(check.CheckedAt),
	)
	if err != nil {
		return fmt.Errorf("replace company OIDC setup-check evidence: %w", err)
	}
	return nil
}

func recordMetadataChecked(
	ctx context.Context,
	tx *sql.Tx,
	actorUserID int64,
	check SetupCheck,
) error {
	details, err := json.Marshal(struct {
		Revision   int64                `json:"revision"`
		ResultCode SetupCheckResultCode `json:"result_code"`
	}{
		Revision:   check.ConfigRevision,
		ResultCode: check.ResultCode,
	})
	if err != nil {
		return errors.New("encode company OIDC metadata-check audit evidence")
	}
	actor := actorUserID
	if err := audit.NewStoreTx(tx).Record(ctx, audit.Event{
		ActorUserID: &actor,
		Action:      audit.ActionOIDCConnectionMetadataChecked,
		SubjectType: audit.SubjectTypeOIDCConnection,
		SubjectID:   strconv.FormatInt(singletonConnectionID, 10),
		DetailsJSON: string(details),
	}); err != nil {
		return fmt.Errorf("record company OIDC metadata-check audit event: %w", err)
	}
	return nil
}
