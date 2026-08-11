// Package forgeidentity owns explicit Forgejo identity linking: the
// Administrator-managed OAuth client for the saved Forge connection, the
// session/browser/state/PKCE-bound link ceremony, and the linked numeric
// identities. Linking proves identity only. Nothing here grants repository
// roles, reads memberships, persists provider tokens, or changes any
// connection, binding, or repository-owned state.
package forgeidentity

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// CallbackPath is the fixed origin-form path of the link callback. The
// generated redirect URI is the root-only canonical PublicURL plus exactly
// this path; the same string is displayed, stored, authorized, and sent to
// the token endpoint.
const CallbackPath = "/account/forgejo/callback"

const (
	forgeIdentityTimeFormat = "2006-01-02T15:04:05.000000000Z"

	linkTransactionTTL   = 10 * time.Minute
	linkCleanupLimit     = 100
	maxSessionIDBytes    = 512
	maxClientIDBytes     = 255
	maxClientSecretBytes = 1024
	maxCiphertextBytes   = 8192
	maxAuthorizeURLBytes = 8192
	maxUsernameBytes     = 255

	linkStateDigestPurpose   = "thawguard:forgeidentity-link-state:v1"
	linkSessionDigestPurpose = "thawguard:forgeidentity-link-session:v1"
	linkBrowserDigestPurpose = "thawguard:forgeidentity-link-browser:v1"
)

var (
	ErrUnavailable    = errors.New("Forgejo identity linking is not available")
	ErrAuthorization  = errors.New("Forgejo identity linking requires a current enabled session with a local credential")
	ErrAdminOnly      = errors.New("only an enabled Administrator can change the Forgejo OAuth client")
	ErrConflict       = errors.New("the Forgejo OAuth client changed; reload before saving again")
	ErrConfiguration  = errors.New("OAuth client secret encryption is not configured")
	ErrOutcomeUnknown = errors.New("the Forgejo identity outcome could not be confirmed")
	ErrLinkInProgress = errors.New("a Forgejo link attempt is already in progress for this account")
	ErrIdentityStale  = errors.New("the Forgejo identity is no longer in the submitted state")
)

// LinkResultCode is the strict sanitized outcome of one callback. It never
// carries provider text.
type LinkResultCode string

const (
	LinkLinked                   LinkResultCode = "linked"
	LinkProviderDenied           LinkResultCode = "provider_denied"
	LinkProviderUnavailable      LinkResultCode = "provider_unavailable"
	LinkProviderInvalid          LinkResultCode = "provider_invalid"
	LinkCollision                LinkResultCode = "remote_identity_collision"
	LinkAlreadyLinked            LinkResultCode = "already_linked"
	LinkStale                    LinkResultCode = "stale"
	LinkConfigurationUnavailable LinkResultCode = "configuration_unavailable"
)

// Identity is the public read model of one linked identity. It carries the
// username observed at link time only, never the remote numeric id.
type Identity struct {
	ID             int64
	ConnectionID   int64
	UserID         int64
	UsernameAtLink string
	LinkedAt       time.Time
}

// OAuthClient is the public read model of the saved OAuth client
// configuration. The client secret never leaves the package.
type OAuthClient struct {
	ConnectionID int64
	Enabled      bool
	ClientID     string
	BoundBaseURL string
	Revision     int64
}

// AccountStatus is the /account card state for one user.
type AccountStatus string

const (
	// AccountUnavailable covers every reason linking cannot start: no
	// connection, unconfigured or disabled OAuth client, a stale bound base
	// URL, or missing secret encryption. The card never explains which.
	AccountUnavailable AccountStatus = "unavailable"
	AccountReady       AccountStatus = "ready"
	AccountInProgress  AccountStatus = "in_progress"
	AccountLinked      AccountStatus = "linked"
)

// AccountView is everything the /account Forgejo card needs for one user.
// Revisions are exposed only as hidden form fences for the start command.
type AccountView struct {
	Status             AccountStatus
	Identity           *Identity
	ConnectionID       int64
	ConnectionRevision int64
	OAuthRevision      int64
}

type SaveOAuthClientInput struct {
	ExpectedConnectionID       int64
	ExpectedConnectionRevision int64
	// ExpectedOAuthRevision is 0 for the first save and the current positive
	// revision afterwards. Every save requires a fresh client secret.
	ExpectedOAuthRevision int64
	ClientID              string
	ClientSecret          string
}

type DisableOAuthClientInput struct {
	ExpectedConnectionID       int64
	ExpectedConnectionRevision int64
	ExpectedOAuthRevision      int64
}

type StartLinkInput struct {
	ActorUserID int64
	SessionID   string
	// ExpectedConnectionID and ExpectedOAuthRevision fence the start against
	// the exact configuration the /account card rendered.
	ExpectedConnectionID  int64
	ExpectedOAuthRevision int64
}

// LinkStart carries the rendered ceremony. BrowserToken must reach the
// browser only as the purpose cookie, after the continuation page rendered.
type LinkStart struct {
	AuthorizationURL string
	BrowserToken     string
	Handle           StartHandle
}

// StartHandle is the request-local opaque cancellation handle for one
// committed pending row. It never leaves the request that created it.
type StartHandle struct {
	stateDigest []byte
}

type CallbackInput struct {
	RawQuery     string
	SessionID    string
	BrowserToken string
}

type UnlinkInput struct {
	ActorUserID int64
	SessionID   string
	// IdentityID is the exact never-reused identity row id being removed.
	IdentityID int64
}

type PurgeInput struct {
	ActorUserID  int64
	SessionID    string
	TargetUserID int64
	IdentityID   int64
	// ConfirmPurge must be explicitly true; purge destroys the identity row.
	ConfirmPurge bool
}

type ValidationError struct {
	Message string
}

func (e ValidationError) Error() string { return e.Message }

func IsValidationError(err error) bool {
	var validationErr ValidationError
	return errors.As(err, &validationErr)
}

func validateClientID(value string) error {
	if len(value) < 1 || len(value) > maxClientIDBytes || !utf8.ValidString(value) {
		return ValidationError{Message: "OAuth client ID must be between 1 and 255 bytes"}
	}
	for _, character := range value {
		if character < 0x21 || character >= 0x7f {
			return ValidationError{Message: "OAuth client ID must contain only printable ASCII without spaces"}
		}
	}
	return nil
}

func validateClientSecret(value string) error {
	if len(value) < 1 || len(value) > maxClientSecretBytes {
		return ValidationError{Message: "OAuth client secret must be between 1 and 1024 bytes"}
	}
	for i := range len(value) {
		if value[i] <= 0x20 || value[i] >= 0x7f {
			return ValidationError{Message: "OAuth client secret must contain only printable ASCII without spaces"}
		}
	}
	return nil
}

// validRemoteUserID accepts the canonical decimal text of a positive signed
// 64-bit Forgejo user id.
func validRemoteUserID(value string) bool {
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
	const maxInt64 = "9223372036854775807"
	return len(value) < len(maxInt64) || value <= maxInt64
}

// validUsernameAtLink bounds the display-only username observed at link
// time: 1-255 bytes of control-free UTF-8.
func validUsernameAtLink(value string) bool {
	if len(value) < 1 || len(value) > maxUsernameBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validSessionID(sessionID string) bool {
	return len(sessionID) > 0 && len(sessionID) <= maxSessionIDBytes
}

// validBoundBaseURL re-validates a stored base URL shape without importing
// the connection package's full canonicalizer: absolute http(s), bounded,
// no query, fragment, or backslash.
func validBoundBaseURL(value string) bool {
	if len(value) < 1 || len(value) > 2048 {
		return false
	}
	if strings.ContainsAny(value, "\\#? \t\r\n") {
		return false
	}
	return strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "http://")
}

func formatForgeIdentityTime(value time.Time) string {
	return value.UTC().Format(forgeIdentityTimeFormat)
}

func parseForgeIdentityTime(value string) (time.Time, error) {
	parsed, err := time.Parse(forgeIdentityTimeFormat, value)
	if err != nil || formatForgeIdentityTime(parsed) != value {
		return time.Time{}, errors.New("forge identity timestamp is malformed")
	}
	return parsed, nil
}
