// Package forgeconnection owns the Administrator-only Forgejo Connection
// Preview: one saved Forgejo installation and organization, a write-only
// Administrator-attested service PAT, a non-mutating connection check, and
// the read-only preview of repositories visible to that credential.
//
// The preview is evidence of credential visibility only. It never binds
// local repositories, never reads or writes repository grants, and never
// proves provider-side scopes: Forgejo cannot documentably report an
// existing PAT's exact scopes, so every claim stays "Administrator
// attested", never "provider verified".
package forgeconnection

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// ProviderForgejo is the only provider this service accepts. The schema can
// hold other provider rows later; the service does not.
const ProviderForgejo = "forgejo"

const forgeConnectionTimeFormat = "2006-01-02T15:04:05.000000000Z"

// CheckResultCode is the strict sanitized result of one connection check.
type CheckResultCode string

const (
	// CheckVisibleInventoryObserved records a stable snapshot of the
	// credential-visible inventory with observed private-read capability:
	// at least one visible private repository was read directly.
	CheckVisibleInventoryObserved CheckResultCode = "visible_inventory_observed"
	// CheckVisibleInventoryObservedPrivateReadUnproven records a stable
	// snapshot in which no private repository was visible, so private-read
	// capability remains unproven.
	CheckVisibleInventoryObservedPrivateReadUnproven CheckResultCode = "visible_inventory_observed_private_read_unproven"
	CheckUnavailable                                 CheckResultCode = "unavailable"
	CheckInvalidResponse                             CheckResultCode = "invalid_response"
	CheckAuthenticationFailed                        CheckResultCode = "authentication_failed"
	CheckAuthorizationFailed                         CheckResultCode = "authorization_failed"
	CheckServiceUserIsAdmin                          CheckResultCode = "service_user_is_admin"
	CheckServiceUserChanged                          CheckResultCode = "service_user_changed"
	CheckOrganizationUnavailable                     CheckResultCode = "organization_unavailable"
	CheckOrganizationChanged                         CheckResultCode = "organization_changed"
	CheckPaginationIncomplete                        CheckResultCode = "pagination_incomplete"
	CheckInventoryLimitExceeded                      CheckResultCode = "inventory_limit_exceeded"
)

func (code CheckResultCode) Valid() bool {
	switch code {
	case CheckVisibleInventoryObserved,
		CheckVisibleInventoryObservedPrivateReadUnproven,
		CheckUnavailable,
		CheckInvalidResponse,
		CheckAuthenticationFailed,
		CheckAuthorizationFailed,
		CheckServiceUserIsAdmin,
		CheckServiceUserChanged,
		CheckOrganizationUnavailable,
		CheckOrganizationChanged,
		CheckPaginationIncomplete,
		CheckInventoryLimitExceeded:
		return true
	default:
		return false
	}
}

// Observed reports whether the code is a successful inventory snapshot.
func (code CheckResultCode) Observed() bool {
	return code == CheckVisibleInventoryObserved ||
		code == CheckVisibleInventoryObservedPrivateReadUnproven
}

// Connection is the public read model. It never carries PAT material.
type Connection struct {
	ID                  int64
	Provider            string
	DisplayName         string
	BaseURL             string
	OrganizationSlug    string
	Revision            int64
	CheckGeneration     int64
	PATAttestedAt       time.Time
	ServiceUserRemoteID string // immutable once bound; empty before binding
	Organization        *Organization
	SetupCheck          *SetupCheck
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Bound reports whether the first successful check has established the
// immutable service-user and organization identities.
func (c Connection) Bound() bool {
	return c.ServiceUserRemoteID != "" && c.Organization != nil
}

// Organization is the bound organization observed through the credential.
// RemoteID is immutable; slug and display name refresh on later checks.
type Organization struct {
	RemoteID    string
	Slug        string
	DisplayName string
	ObservedAt  time.Time
}

// SetupCheck is the sanitized current check evidence for a connection. It is
// current only while ConfigRevision and CheckGeneration match the connection.
type SetupCheck struct {
	ConfigRevision                int64
	CheckGeneration               int64
	ResultCode                    CheckResultCode
	ObservedVersion               string
	VisibleRepositoryCount        *int64
	VisiblePrivateRepositoryCount *int64
	CheckedAt                     time.Time
}

// VisibleRepository is one repository visible to the attested credential at
// its observed check generation. Presence or disappearance is preview
// evidence only, never authority, eligibility, absence, or identity.
type VisibleRepository struct {
	RemoteID                string
	Owner                   string
	Name                    string
	DefaultBranch           string
	Private                 bool
	ObservedCheckGeneration int64
	ObservedAt              time.Time
}

type CreateInput struct {
	DisplayName      string
	BaseURL          string
	OrganizationSlug string
	ServicePAT       string
	// PATAttested must be explicitly true: the Administrator attests the PAT
	// belongs to a dedicated non-site-Administrator organization owner and
	// was created read-only in All-resources mode with no write scopes.
	PATAttested bool
}

type EditInput struct {
	DisplayName      string
	BaseURL          string
	OrganizationSlug string
	ReplacementPAT   string
	// ReplacementPATAttested must be true whenever ReplacementPAT is set;
	// a replacement always requires a fresh attestation.
	ReplacementPATAttested bool
	// ExpectedConnectionID pins the command to one never-reused internal id,
	// so a form issued before a reset can never edit a recreated connection
	// even at a matching revision.
	ExpectedConnectionID int64
	ExpectedRevision     int64
}

type ResetInput struct {
	// ExpectedConnectionID pins the reset to one never-reused internal id.
	ExpectedConnectionID int64
	ExpectedRevision     int64
	// ConfirmReset must be explicitly true; reset deletes the connection and
	// every cascaded preview and evidence row.
	ConfirmReset bool
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

var (
	ErrConflict            = errors.New("the Forge connection changed; reload it before saving again")
	ErrConfiguration       = errors.New("service PAT encryption is not configured")
	ErrAuthorization       = errors.New("only an enabled Administrator can change the Forge connection")
	ErrOutcomeUnknown      = errors.New("the Forge connection save outcome could not be confirmed")
	ErrNoConnection        = errors.New("no saved Forge connection is available")
	ErrCheckStale          = errors.New("the Forge connection changed during the check; run it again")
	ErrCheckIncomplete     = errors.New("the Forge connection check could not be completed")
	ErrCheckOutcomeUnknown = errors.New("the Forge connection check outcome could not be confirmed")
)

const (
	maxDisplayNameBytes      = 80
	maxOrganizationSlugBytes = 255
	// maxServicePATBytes bounds the write-only secret input, matching the
	// conservative bounded-secret conventions used elsewhere.
	maxServicePATBytes = 1024
)

func normalizeDisplayName(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", ValidationError{Message: "display name must be valid UTF-8"}
	}
	value = strings.TrimSpace(value)
	if len(value) < 1 || len(value) > maxDisplayNameBytes {
		return "", ValidationError{Message: "display name must be between 1 and 80 bytes"}
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", ValidationError{Message: "display name contains invalid characters"}
		}
	}
	return value, nil
}

// normalizeOrganizationSlug accepts the character set Forgejo allows for
// user and organization names, which is also safe as one URL path segment.
func normalizeOrganizationSlug(value string) (string, error) {
	value = strings.Trim(value, " \t\n\r\v\f")
	if len(value) < 1 || len(value) > maxOrganizationSlugBytes {
		return "", ValidationError{Message: "organization must be between 1 and 255 bytes"}
	}
	for i := range len(value) {
		character := value[i]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return "", ValidationError{Message: "organization may contain only letters, digits, '-', '_', and '.'"}
	}
	if value == "." || value == ".." {
		return "", ValidationError{Message: "organization is not a valid Forgejo name"}
	}
	return value, nil
}

func validateServicePAT(value string) error {
	if len(value) < 1 || len(value) > maxServicePATBytes {
		return ValidationError{Message: "service PAT must be between 1 and 1024 bytes"}
	}
	for i := range len(value) {
		if value[i] <= 0x20 || value[i] >= 0x7f {
			return ValidationError{Message: "service PAT must contain only printable ASCII without spaces"}
		}
	}
	return nil
}

// validRemoteID accepts the canonical decimal text this service persists for
// remote Forgejo identifiers: a positive signed 64-bit integer.
func validRemoteID(value string) bool {
	if len(value) < 1 || len(value) > 19 {
		return false
	}
	if value[0] < '1' || value[0] > '9' {
		return false
	}
	for i := range len(value) {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	// 19 digits can exceed int64; compare against the maximum literally.
	const maxInt64 = "9223372036854775807"
	return len(value) < len(maxInt64) || value <= maxInt64
}

// validRemoteName bounds mutable observed names (organization slug and
// display name, repository owner, name, and default branch) to 1-255 bytes
// of control-free UTF-8.
func validRemoteName(value string) bool {
	if len(value) < 1 || len(value) > 255 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func formatForgeConnectionTime(value time.Time) string {
	return value.UTC().Format(forgeConnectionTimeFormat)
}

func parseForgeConnectionTime(value string) (time.Time, error) {
	parsed, err := time.Parse(forgeConnectionTimeFormat, value)
	if err != nil || formatForgeConnectionTime(parsed) != value {
		return time.Time{}, errors.New("forge connection timestamp is malformed")
	}
	return parsed, nil
}
