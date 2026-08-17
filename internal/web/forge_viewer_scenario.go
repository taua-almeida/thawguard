package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

const (
	forgeViewerBaselineValue = "qualifying_explicit_access"

	forgeViewerCurrentOutcome       = "Current Viewer retained"
	forgeViewerAddedOutcome         = "Scenario adds Viewer"
	forgeViewerIndeterminateOutcome = "Viewer eligibility indeterminate"
	forgeViewerNoChangeOutcome      = "Scenario adds nothing"
)

type forgeViewerScenarioReason string

const (
	forgeViewerReasonCurrentViewer      forgeViewerScenarioReason = "current_viewer"
	forgeViewerReasonBaselineOff        forgeViewerScenarioReason = "baseline_off"
	forgeViewerReasonAccountDisabled    forgeViewerScenarioReason = "account_disabled"
	forgeViewerReasonAdminReadAll       forgeViewerScenarioReason = "admin_read_all"
	forgeViewerReasonScopedReadPresent  forgeViewerScenarioReason = "scoped_read_already_present"
	forgeViewerReasonEvidenceGateFailed forgeViewerScenarioReason = "evidence_gate_failed"
	forgeViewerReasonSupportingEvidence forgeViewerScenarioReason = "supporting_evidence"
	forgeViewerReasonConfirmedAbsent    forgeViewerScenarioReason = "confirmed_absent"
	forgeViewerReasonPairIndeterminate  forgeViewerScenarioReason = "pair_indeterminate"
)

type forgeViewerScenarioQuery struct {
	RepositoryID int64
	BaselineOn   bool
}

type forgeViewerScenarioCounts struct {
	CurrentViewer       int
	AddedViewer         int
	IndeterminateViewer int
	NoChange            int
}

type forgeViewerScenarioRowView struct {
	DisplayName string
	Email       string
	Disabled    bool
	IsAdmin     bool
	ScopedRoles []string

	Linked         bool
	UsernameAtLink string

	EvidenceLabel      string
	EvidenceTone       string
	EvidenceDetail     string
	EvidenceObservedAt string
	EvidenceAge        string

	ScenarioOutcome string
	ScenarioTone    string
	ScenarioDetail  string
}

type forgeViewerScenarioPageData struct {
	AppName     string
	PageTitle   string
	Theme       string
	ActivePage  string
	CurrentUser currentUserView
	CSRFToken   string
	CSRFField   string
	Toasts      []toastView

	HasConnection        bool
	HasBoundRepositories bool
	RepositoryOptions    []forgeAccessRepositoryOption
	HasSelection         bool
	SelectedRepository   forgeconnection.AccessShadowBoundRepository
	BaselineOn           bool

	Shadow             forgeShadowSectionView
	GateLabel          string
	GateTone           string
	GateDetail         string
	HasNewerAttempt    bool
	NewerAttemptDetail string

	Counts forgeViewerScenarioCounts
	Rows   []forgeViewerScenarioRowView
}

func (s *Server) handleForgeViewerScenario(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	if s.cfg.AuthService == nil || s.cfg.ForgeAccessShadowService == nil {
		s.renderErrorPage(w, http.StatusServiceUnavailable, false)
		return
	}
	query, err := parseForgeViewerScenarioQuery(r.URL)
	if err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, false)
		return
	}
	selected := query.RepositoryID > 0
	view, err := s.cfg.ForgeAccessShadowService.View(r.Context())
	if err != nil {
		s.logForgeViewerScenarioFailure(r, "shadow_read", err)
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return
	}

	data := forgeViewerScenarioPageData{
		AppName:              s.cfg.AppName,
		PageTitle:            "Viewer access scenario",
		ActivePage:           "forge-access",
		CurrentUser:          currentUserFromSession(session),
		CSRFToken:            session.CSRFToken,
		CSRFField:            csrfFormField,
		HasConnection:        view.HasConnection,
		HasBoundRepositories: len(view.BoundRepositories) > 0,
		RepositoryOptions:    forgeAccessRepositoryOptions(view.BoundRepositories, query.RepositoryID, selected),
		BaselineOn:           query.BaselineOn,
	}
	if !selected {
		s.renderPageStatus(w, http.StatusOK, "layouts/forge-viewer-scenario", data)
		return
	}
	boundRepository, found := forgeAccessBoundRepository(view.BoundRepositories, query.RepositoryID)
	if !found {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}

	linkedUserIDs := make([]int64, 0, len(view.LinkedUsers))
	for _, linkedUser := range view.LinkedUsers {
		linkedUserIDs = append(linkedUserIDs, linkedUser.UserID)
	}
	users, err := s.cfg.AuthService.ListRepositoryAccessUsers(r.Context(), query.RepositoryID, linkedUserIDs)
	if err != nil {
		s.logForgeViewerScenarioFailure(r, "auth_union_read", err)
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return
	}
	gateQualified, gateLabel, gateTone, gateDetail := forgeRoleEvidenceGate(view, query.RepositoryID)
	rows, counts, err := forgeViewerScenarioRows(
		view,
		query.RepositoryID,
		query.BaselineOn,
		gateQualified,
		users,
	)
	if err != nil {
		s.logForgeViewerScenarioFailure(r, "composition", err)
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return
	}

	data.HasSelection = true
	data.SelectedRepository = boundRepository
	data.Shadow = forgeShadowSection(view)
	data.GateLabel = gateLabel
	data.GateTone = gateTone
	data.GateDetail = gateDetail
	data.HasNewerAttempt, data.NewerAttemptDetail = forgeRoleEvidenceNewerAttempt(view)
	data.Rows = rows
	data.Counts = counts
	s.renderPageStatus(w, http.StatusOK, "layouts/forge-viewer-scenario", data)
}

func parseForgeViewerScenarioQuery(requestURL *url.URL) (forgeViewerScenarioQuery, error) {
	if requestURL == nil {
		return forgeViewerScenarioQuery{}, errors.New("viewer scenario query is missing")
	}
	if requestURL.RawQuery == "" {
		return forgeViewerScenarioQuery{}, nil
	}
	var query forgeViewerScenarioQuery
	for part := range strings.SplitSeq(requestURL.RawQuery, "&") {
		key, value, found := strings.Cut(part, "=")
		if !found || key == "" || value == "" {
			return forgeViewerScenarioQuery{}, errors.New("viewer scenario query is malformed")
		}
		switch key {
		case "repository_id":
			if query.RepositoryID != 0 {
				return forgeViewerScenarioQuery{}, errors.New("repository id is invalid")
			}
			repositoryID, err := canonicalPositiveForgeAccessValue(value)
			if err != nil {
				return forgeViewerScenarioQuery{}, errors.New("repository id is invalid")
			}
			query.RepositoryID = repositoryID
		case "viewer_baseline":
			if query.BaselineOn || value != forgeViewerBaselineValue {
				return forgeViewerScenarioQuery{}, errors.New("viewer baseline is invalid")
			}
			query.BaselineOn = true
		default:
			return forgeViewerScenarioQuery{}, errors.New("viewer scenario query key is unsupported")
		}
	}
	if query.RepositoryID == 0 {
		return forgeViewerScenarioQuery{}, errors.New("repository id is invalid")
	}
	return query, nil
}

func forgeViewerScenarioRows(
	view forgeconnection.AccessShadowView,
	repositoryID int64,
	baselineOn bool,
	gateQualified bool,
	users []auth.RepositoryAccessUser,
) ([]forgeViewerScenarioRowView, forgeViewerScenarioCounts, error) {
	if view.IdentityCount < 0 || view.IdentityCount != len(view.LinkedUsers) {
		return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario linked user data is malformed")
	}
	linkedByUserID := make(map[int64]forgeconnection.AccessShadowLinkedUser, len(view.LinkedUsers))
	for _, linkedUser := range view.LinkedUsers {
		if linkedUser.UserID <= 0 {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario linked user data is malformed")
		}
		if _, duplicate := linkedByUserID[linkedUser.UserID]; duplicate {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario linked user data is malformed")
		}
		linkedByUserID[linkedUser.UserID] = linkedUser
	}

	boundRepositoryIDs := make(map[int64]bool, len(view.BoundRepositories))
	for _, repository := range view.BoundRepositories {
		boundRepositoryIDs[repository.RepositoryID] = true
	}
	pairs := make(map[[2]int64]forgeconnection.AccessShadowPairRow, len(view.Pairs))
	selectedPairCount := 0
	if !view.WithinLimits && len(view.Pairs) != 0 {
		return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario pair data is malformed")
	}
	for _, pair := range view.Pairs {
		key := [2]int64{pair.UserID, pair.RepositoryID}
		if pair.IdentityID <= 0 || pair.UserID <= 0 || pair.RepositoryID <= 0 ||
			!boundRepositoryIDs[pair.RepositoryID] {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario pair data is malformed")
		}
		if _, duplicate := pairs[key]; duplicate {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario pair data is malformed")
		}
		linkedUser, linked := linkedByUserID[pair.UserID]
		if !linked || linkedUser.UserDisplayName != pair.UserDisplayName ||
			linkedUser.UserEmail != pair.UserEmail || linkedUser.UserDisabled != pair.UserDisabled ||
			linkedUser.UsernameAtLink != pair.UsernameAtLink {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario pair data is malformed")
		}
		pairs[key] = pair
		if pair.RepositoryID == repositoryID {
			selectedPairCount++
		}
	}
	if view.WithinLimits {
		if selectedPairCount != len(linkedByUserID) {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario selected pair data is malformed")
		}
	}

	rows := make([]forgeViewerScenarioRowView, 0, len(users))
	var counts forgeViewerScenarioCounts
	seenAuthUserIDs := make(map[int64]bool, len(users))
	resolvedLinkedUserCount := 0
	for _, user := range users {
		if user.UserID <= 0 || seenAuthUserIDs[user.UserID] || !canonicalRepositoryRoleSet(user.Roles) {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario auth user data is malformed")
		}
		seenAuthUserIDs[user.UserID] = true
		linkedUser, linked := linkedByUserID[user.UserID]
		if len(user.Roles) == 0 && !linked {
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario auth user data is malformed")
		}
		if linked {
			if linkedUser.UserDisplayName != user.DisplayName || linkedUser.UserEmail != user.Email ||
				linkedUser.UserDisabled != user.Disabled {
				return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario joined user data is contradictory")
			}
			resolvedLinkedUserCount++
		}

		pair, pairExists := pairs[[2]int64{user.UserID, repositoryID}]
		evidenceOutcome := classifyForgeRoleEvidence(
			gateQualified,
			pairExists,
			pair.Observed,
			forgeRoleEvidenceSnapshotRunID(view.LatestSnapshot),
			pair.LatestRunID,
			pair.LatestReason,
		)
		reason, err := classifyForgeViewerScenario(
			baselineOn,
			user.Disabled,
			user.IsAdmin,
			user.Roles,
			gateQualified,
			evidenceOutcome,
		)
		if err != nil {
			return nil, forgeViewerScenarioCounts{}, err
		}
		outcome, tone, detail, err := forgeViewerScenarioPresentation(reason)
		if err != nil {
			return nil, forgeViewerScenarioCounts{}, err
		}

		row := forgeViewerScenarioRowView{
			DisplayName:     user.DisplayName,
			Email:           user.Email,
			Disabled:        user.Disabled,
			IsAdmin:         user.IsAdmin,
			ScopedRoles:     make([]string, 0, len(user.Roles)),
			Linked:          linked,
			EvidenceLabel:   evidenceOutcome,
			ScenarioOutcome: outcome,
			ScenarioTone:    tone,
			ScenarioDetail:  detail,
		}
		for _, role := range user.Roles {
			row.ScopedRoles = append(row.ScopedRoles, role.Label())
		}
		identityDetail := forgeRoleEvidenceMissingIdentity
		if linked {
			row.UsernameAtLink = linkedUser.UsernameAtLink
			identityDetail = "Current local account linkage"
		}
		if !view.WithinLimits {
			identityDetail = forgeRoleEvidenceOverLimitDetail
		}
		row.EvidenceTone, row.EvidenceDetail = forgeRoleEvidenceOutcomePresentation(
			evidenceOutcome,
			gateQualified,
			pairExists,
			pair,
			view.LatestSnapshot,
			identityDetail,
		)
		if row.EvidenceDetail == "" && !gateQualified {
			row.EvidenceDetail = "The strict evidence gate did not qualify for this request."
		}
		if reason == forgeViewerReasonPairIndeterminate {
			if row.EvidenceDetail == "" {
				return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario indeterminate evidence detail is missing")
			}
			row.ScenarioDetail = "Viewer eligibility remains indeterminate. Evidence detail: " + row.EvidenceDetail
		}
		if forgeRoleEvidencePairAnchored(
			pairExists,
			pair.Observed,
			forgeRoleEvidenceSnapshotRunID(view.LatestSnapshot),
			pair.LatestRunID,
		) {
			row.EvidenceObservedAt = pair.LatestObservedAt.UTC().Format("2006-01-02 15:04:05 UTC")
			row.EvidenceAge = forgeShadowAge(view.LatestSnapshot.Age)
		}
		switch outcome {
		case forgeViewerCurrentOutcome:
			counts.CurrentViewer++
		case forgeViewerAddedOutcome:
			counts.AddedViewer++
		case forgeViewerIndeterminateOutcome:
			counts.IndeterminateViewer++
		case forgeViewerNoChangeOutcome:
			counts.NoChange++
		default:
			return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario outcome is unrecognized")
		}
		rows = append(rows, row)
	}
	if resolvedLinkedUserCount != len(linkedByUserID) {
		return nil, forgeViewerScenarioCounts{}, errors.New("viewer scenario linked user is absent from auth output")
	}
	return rows, counts, nil
}

func (s *Server) logForgeViewerScenarioFailure(r *http.Request, stage string, err error) {
	s.cfg.Logger.ErrorContext(r.Context(), "forge Viewer scenario failed",
		"method", r.Method,
		"route", "/settings/forge-access/viewer-scenario",
		"status", http.StatusInternalServerError,
		"stage", stage,
		"error", err,
	)
}

func canonicalRepositoryRoleSet(roles auth.RoleSet) bool {
	canonical := auth.RepositoryRoles()
	previous := -1
	for _, role := range roles {
		index := slices.Index(canonical, role)
		if index <= previous {
			return false
		}
		previous = index
	}
	return true
}

func classifyForgeViewerScenario(
	baselineOn bool,
	disabled bool,
	isAdmin bool,
	roles auth.RoleSet,
	gateQualified bool,
	evidenceOutcome string,
) (forgeViewerScenarioReason, error) {
	switch {
	case roles.Contains(auth.RoleViewer):
		return forgeViewerReasonCurrentViewer, nil
	case !baselineOn:
		return forgeViewerReasonBaselineOff, nil
	case disabled:
		return forgeViewerReasonAccountDisabled, nil
	case isAdmin:
		return forgeViewerReasonAdminReadAll, nil
	case roles.Contains(auth.RoleFreezer) || roles.Contains(auth.RoleThawApprover):
		return forgeViewerReasonScopedReadPresent, nil
	case !gateQualified:
		return forgeViewerReasonEvidenceGateFailed, nil
	}
	switch evidenceOutcome {
	case forgeRoleEvidenceSupportingOutcome:
		return forgeViewerReasonSupportingEvidence, nil
	case forgeRoleEvidenceAbsentOutcome:
		return forgeViewerReasonConfirmedAbsent, nil
	case forgeRoleEvidenceIndeterminateOutcome:
		return forgeViewerReasonPairIndeterminate, nil
	default:
		return "", errors.New("viewer scenario evidence outcome is unrecognized")
	}
}

func forgeViewerScenarioPresentation(reason forgeViewerScenarioReason) (string, string, string, error) {
	switch reason {
	case forgeViewerReasonCurrentViewer:
		return forgeViewerCurrentOutcome, "info", "The current Viewer role is retained. No role is removed by this scenario.", nil
	case forgeViewerReasonSupportingEvidence:
		return forgeViewerAddedOutcome, "info", "Qualifying explicit-access evidence supports adding Viewer. Every current role is retained and no role is removed.", nil
	case forgeViewerReasonEvidenceGateFailed:
		return forgeViewerIndeterminateOutcome, "warning", "Viewer eligibility remains indeterminate. See the global evidence gate above for the blocking facts.", nil
	case forgeViewerReasonPairIndeterminate:
		return forgeViewerIndeterminateOutcome, "warning", "Viewer eligibility remains indeterminate. Review the evidence detail for this population member.", nil
	case forgeViewerReasonBaselineOff:
		return forgeViewerNoChangeOutcome, "neutral", "The Viewer baseline is off, so the scenario adds nothing. Every current role is retained.", nil
	case forgeViewerReasonAccountDisabled:
		return forgeViewerNoChangeOutcome, "neutral", "Viewer is withheld while this account is disabled. Recalculate after the account is enabled.", nil
	case forgeViewerReasonAdminReadAll:
		return forgeViewerNoChangeOutcome, "neutral", "Administrator read-all makes Viewer redundant. No fallback role is proposed; recalculate after Administrator authority changes.", nil
	case forgeViewerReasonScopedReadPresent:
		return forgeViewerNoChangeOutcome, "neutral", "The current Freezer or Thaw approver action role is retained and already includes repository read. Recalculate after that action role is removed.", nil
	case forgeViewerReasonConfirmedAbsent:
		return forgeViewerNoChangeOutcome, "neutral", forgeRoleEvidenceAbsentOutcome + " " + forgeRoleEvidenceAbsenceCaveat, nil
	default:
		return "", "", "", errors.New("viewer scenario reason is unrecognized")
	}
}
