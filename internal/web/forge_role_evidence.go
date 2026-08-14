package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/taua-almeida/thawguard/internal/auth"
	"github.com/taua-almeida/thawguard/internal/forgeconnection"
)

const (
	forgeRoleEvidenceSupportingOutcome    = "Supporting explicit-access evidence"
	forgeRoleEvidenceAbsentOutcome        = "No explicit access observed in the complete credential-visible snapshot."
	forgeRoleEvidenceIndeterminateOutcome = "Indeterminate evidence"
	forgeRoleEvidenceAbsenceCaveat        = "This is not provider-global absence, recommends no removal, and changes nothing."
	forgeRoleEvidenceOverLimitDetail      = "Identity detail was not loaded because the current identity × repository scope exceeds the shipped limits."
	forgeRoleEvidenceMissingIdentity      = "No linked Forgejo identity in this loaded scope"
)

type forgeRoleEvidenceRepositoryOption struct {
	Value    string
	Label    string
	Selected bool
}

type forgeRoleEvidenceRowView struct {
	DisplayName       string
	Email             string
	Disabled          bool
	IsAdmin           bool
	ScopedRoles       []string
	IdentityDetail    string
	ObservedAt        string
	ObservedAge       string
	Outcome           string
	OutcomeBadgeLabel string
	OutcomeTone       string
	OutcomeDetail     string
}

type forgeRoleEvidenceCounts struct {
	SupportingActive    int
	AbsentActive        int
	IndeterminateActive int
	Disabled            int
}

type forgeRoleEvidencePageData struct {
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
	RepositoryOptions    []forgeRoleEvidenceRepositoryOption
	HasSelection         bool
	SelectedRepository   forgeconnection.AccessShadowBoundRepository

	Shadow             forgeShadowSectionView
	GateQualified      bool
	GateLabel          string
	GateTone           string
	GateDetail         string
	HasNewerAttempt    bool
	NewerAttemptDetail string

	Counts        forgeRoleEvidenceCounts
	Rows          []forgeRoleEvidenceRowView
	RowsAvailable bool
}

func (s *Server) handleForgeRoleEvidence(w http.ResponseWriter, r *http.Request) {
	session, ok := s.requireAdminView(w, r)
	if !ok {
		return
	}
	if s.cfg.AuthService == nil || s.cfg.ForgeAccessShadowService == nil {
		s.renderErrorPage(w, http.StatusServiceUnavailable, false)
		return
	}
	repositoryID, selected, err := parseForgeRoleEvidenceQuery(r.URL)
	if err != nil {
		s.renderErrorPage(w, http.StatusBadRequest, false)
		return
	}
	view, err := s.cfg.ForgeAccessShadowService.View(r.Context())
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return
	}

	data := forgeRoleEvidencePageData{
		AppName:              s.cfg.AppName,
		PageTitle:            "Current role and Forge evidence",
		ActivePage:           "forge-access",
		CurrentUser:          currentUserFromSession(session),
		CSRFToken:            session.CSRFToken,
		CSRFField:            csrfFormField,
		HasConnection:        view.HasConnection,
		HasBoundRepositories: len(view.BoundRepositories) > 0,
		RepositoryOptions:    forgeRoleEvidenceRepositoryOptions(view.BoundRepositories, repositoryID, selected),
	}
	if !selected {
		s.renderPageStatus(w, http.StatusOK, "layouts/forge-role-evidence", data)
		return
	}
	boundRepository, found := forgeRoleEvidenceBoundRepository(view.BoundRepositories, repositoryID)
	if !found {
		s.renderErrorPage(w, http.StatusNotFound, false)
		return
	}
	holders, err := s.cfg.AuthService.ListRepositoryRoleHolders(r.Context(), repositoryID)
	if err != nil {
		s.renderErrorPage(w, http.StatusInternalServerError, false)
		return
	}

	data.HasSelection = true
	data.SelectedRepository = boundRepository
	data.Shadow = forgeShadowSection(view)
	data.GateQualified, data.GateLabel, data.GateTone, data.GateDetail = forgeRoleEvidenceGate(view, repositoryID)
	data.HasNewerAttempt, data.NewerAttemptDetail = forgeRoleEvidenceNewerAttempt(view)
	data.Rows, data.Counts = forgeRoleEvidenceRows(view, repositoryID, data.GateQualified, holders)
	data.RowsAvailable = len(data.Rows) > 0
	s.renderPageStatus(w, http.StatusOK, "layouts/forge-role-evidence", data)
}

func parseForgeRoleEvidenceQuery(requestURL *url.URL) (int64, bool, error) {
	if requestURL == nil {
		return 0, false, errors.New("role evidence query is missing")
	}
	if requestURL.RawQuery == "" {
		return 0, false, nil
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return 0, false, errors.New("role evidence query is malformed")
	}
	repositoryID, ok := forgeAccessConfirmationRepositoryID(values, "repository_id")
	if !ok {
		return 0, false, errors.New("repository id is invalid")
	}
	return repositoryID, true, nil
}

func forgeRoleEvidenceRepositoryOptions(
	repositories []forgeconnection.AccessShadowBoundRepository,
	selectedID int64,
	selected bool,
) []forgeRoleEvidenceRepositoryOption {
	options := make([]forgeRoleEvidenceRepositoryOption, 0, len(repositories)+1)
	options = append(options, forgeRoleEvidenceRepositoryOption{
		Label:    "Choose a bound repository",
		Selected: !selected,
	})
	for _, repository := range repositories {
		options = append(options, forgeRoleEvidenceRepositoryOption{
			Value:    strconv.FormatInt(repository.RepositoryID, 10),
			Label:    repository.RepositoryFullName,
			Selected: selected && repository.RepositoryID == selectedID,
		})
	}
	return options
}

func forgeRoleEvidenceBoundRepository(
	repositories []forgeconnection.AccessShadowBoundRepository,
	repositoryID int64,
) (forgeconnection.AccessShadowBoundRepository, bool) {
	for _, repository := range repositories {
		if repository.RepositoryID == repositoryID {
			return repository, true
		}
	}
	return forgeconnection.AccessShadowBoundRepository{}, false
}

func forgeRoleEvidenceGate(
	view forgeconnection.AccessShadowView,
	repositoryID int64,
) (bool, string, string, string) {
	_, repositoryBound := forgeRoleEvidenceBoundRepository(view.BoundRepositories, repositoryID)
	switch {
	case !view.HasConnection:
		return false, forgeRoleEvidenceIndeterminateOutcome, "warning", "No Forge connection is configured."
	case !repositoryBound:
		return false, forgeRoleEvidenceIndeterminateOutcome, "warning", "The selected repository is not currently bound."
	}

	blockers := make([]string, 0, 7)
	if !view.WithinLimits {
		blockers = append(blockers, forgeRoleEvidenceOverLimitDetail)
	}
	if !view.SetupEvidenceCurrent {
		blockers = append(blockers, "Forge connection setup evidence is not current.")
	}
	if view.IdentityCount < 0 || view.BindingCount < 0 {
		blockers = append(blockers, "The current identity and repository counts are invalid.")
	}
	if view.LatestSnapshot == nil {
		blockers = append(blockers, "No completed credential-visible snapshot exists.")
	} else {
		if !view.LatestSnapshot.ScopeCurrent {
			blockers = append(blockers, "The completed snapshot does not describe the current identity and repository scope.")
		}
		if !view.LatestSnapshot.Fresh() {
			blockers = append(blockers, "The completed snapshot is at least ten minutes old.")
		}
		if view.LatestSnapshot.UnknownCount != 0 {
			blockers = append(blockers, "The completed snapshot contains unknown pair evidence.")
		}
		pairCount := int64(view.IdentityCount) * int64(view.BindingCount)
		if view.LatestSnapshot.PairCount != pairCount {
			blockers = append(blockers, "The completed snapshot pair count does not match the current identity and repository scope.")
		}
	}
	if len(blockers) > 0 {
		return false, forgeRoleEvidenceIndeterminateOutcome, "warning", strings.Join(blockers, " ")
	}
	return true, "Qualifying completed evidence", "success", "The current complete credential-visible snapshot qualifies for this comparison."
}

func forgeRoleEvidenceNewerAttempt(view forgeconnection.AccessShadowView) (bool, string) {
	if view.LatestSnapshot == nil || view.LatestAttempt == nil ||
		view.NewestRunID <= view.LatestSnapshot.RunID {
		return false, ""
	}
	label, _, detail := forgeShadowAttemptPresentation(*view.LatestAttempt)
	return true, fmt.Sprintf(
		"Latest attempt: %s (%s). %s It has not replaced or invalidated the completed snapshot.",
		label,
		forgeShadowRunTriggerLabel(view.LatestAttempt.Trigger),
		detail,
	)
}

func forgeRoleEvidenceRows(
	view forgeconnection.AccessShadowView,
	repositoryID int64,
	gateQualified bool,
	holders []auth.RepositoryRoleHolder,
) ([]forgeRoleEvidenceRowView, forgeRoleEvidenceCounts) {
	pairs := make(map[[2]int64]forgeconnection.AccessShadowPairRow, len(view.Pairs))
	for _, pair := range view.Pairs {
		key := [2]int64{pair.UserID, pair.RepositoryID}
		pairs[key] = pair
	}

	rows := make([]forgeRoleEvidenceRowView, 0, len(holders))
	var counts forgeRoleEvidenceCounts
	for _, holder := range holders {
		pair, pairExists := pairs[[2]int64{holder.UserID, repositoryID}]
		outcome := classifyForgeRoleEvidence(
			gateQualified,
			pairExists,
			pair.Observed,
			forgeRoleEvidenceSnapshotRunID(view.LatestSnapshot),
			pair.LatestRunID,
			pair.LatestReason,
		)
		row := forgeRoleEvidenceRowView{
			DisplayName:       holder.DisplayName,
			Email:             holder.Email,
			Disabled:          holder.Disabled,
			IsAdmin:           holder.IsAdmin,
			ScopedRoles:       make([]string, 0, len(holder.Roles)),
			Outcome:           outcome,
			OutcomeBadgeLabel: outcome,
		}
		for _, role := range holder.Roles {
			row.ScopedRoles = append(row.ScopedRoles, role.Label())
		}
		switch {
		case !view.WithinLimits:
			row.IdentityDetail = forgeRoleEvidenceOverLimitDetail
		case !pairExists:
			row.IdentityDetail = forgeRoleEvidenceMissingIdentity
		default:
			row.IdentityDetail = "Forgejo username at link (historical): " + pair.UsernameAtLink
		}
		if pairExists && pair.Observed {
			row.ObservedAt = pair.LatestObservedAt.UTC().Format("2006-01-02 15:04:05 UTC")
			if view.LatestSnapshot != nil && pair.LatestRunID == view.LatestSnapshot.RunID {
				row.ObservedAge = forgeShadowAge(view.LatestSnapshot.Age)
			}
		}
		row.OutcomeTone, row.OutcomeDetail = forgeRoleEvidenceOutcomePresentation(
			outcome,
			gateQualified,
			pairExists,
			pair,
			view.LatestSnapshot,
			row.IdentityDetail,
		)
		if holder.Disabled {
			counts.Disabled++
		} else {
			switch outcome {
			case forgeRoleEvidenceSupportingOutcome:
				counts.SupportingActive++
			case forgeRoleEvidenceAbsentOutcome:
				counts.AbsentActive++
			default:
				counts.IndeterminateActive++
			}
		}
		rows = append(rows, row)
	}
	return rows, counts
}

func forgeRoleEvidenceSnapshotRunID(snapshot *forgeconnection.AccessShadowSnapshot) int64 {
	if snapshot == nil {
		return 0
	}
	return snapshot.RunID
}

func classifyForgeRoleEvidence(
	gateQualified bool,
	pairExists bool,
	pairObserved bool,
	snapshotRunID int64,
	pairRunID int64,
	latestReason forgeconnection.AccessObservationReason,
) string {
	switch {
	case !gateQualified:
		return forgeRoleEvidenceIndeterminateOutcome
	case !pairExists:
		return forgeRoleEvidenceIndeterminateOutcome
	case !pairObserved:
		return forgeRoleEvidenceIndeterminateOutcome
	case snapshotRunID <= 0 || pairRunID <= 0 || snapshotRunID != pairRunID:
		return forgeRoleEvidenceIndeterminateOutcome
	}
	switch latestReason.State() {
	case forgeconnection.AccessStateConfirmedPresent:
		return forgeRoleEvidenceSupportingOutcome
	case forgeconnection.AccessStateConfirmedAbsent:
		return forgeRoleEvidenceAbsentOutcome
	default:
		return forgeRoleEvidenceIndeterminateOutcome
	}
}

func forgeRoleEvidenceOutcomePresentation(
	outcome string,
	gateQualified bool,
	pairExists bool,
	pair forgeconnection.AccessShadowPairRow,
	snapshot *forgeconnection.AccessShadowSnapshot,
	identityDetail string,
) (string, string) {
	switch outcome {
	case forgeRoleEvidenceSupportingOutcome:
		return "info", forgeShadowReasonText(pair.LatestReason) + " This evidence does not preserve or predict authority and changes nothing."
	case forgeRoleEvidenceAbsentOutcome:
		return "success", forgeRoleEvidenceAbsentOutcome + " " + forgeRoleEvidenceAbsenceCaveat
	}
	var detail string
	switch {
	case !gateQualified:
		return "warning", ""
	case !pairExists:
		detail = identityDetail + "."
	case !pair.Observed:
		detail = "The linked identity and repository pair has not been observed."
	case snapshot == nil || snapshot.RunID <= 0 || pair.LatestRunID <= 0 || snapshot.RunID != pair.LatestRunID:
		detail = "The pair observation does not belong to the qualifying completed snapshot."
	default:
		detail = forgeShadowReasonText(pair.LatestReason)
	}
	return "warning", detail
}
