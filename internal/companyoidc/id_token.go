package companyoidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const (
	maxCompactIDTokenSize  = 32 << 10
	maxProtectedHeaderSize = 4 << 10
	idTokenClockSkew       = 60 * time.Second
	maxNumericDateSize     = 64
	maxSignificandDigits   = 32
	maxDecimalExponent     = 18
	maxNumericDateSeconds  = int64(253402300799)
)

var errIDTokenValidation = errors.New("company OIDC ID token validation failed")

type idTokenVerifier struct {
	issuer               string
	clientID             string
	keys                 trustedJWKS
	nonceDigest          [sha256.Size]byte
	transactionCreatedAt time.Time
	now                  func() time.Time
}

type verifiedIDToken struct {
	subject string
}

type protectedIDTokenHeader struct {
	kid string
}

type numericDate struct {
	seconds *big.Rat
}

func (v idTokenVerifier) verify(token string) (verifiedIDToken, error) {
	if v.issuer == "" || v.clientID == "" || v.keys.keys == nil ||
		v.transactionCreatedAt.IsZero() || v.now == nil {
		return verifiedIDToken{}, errIDTokenValidation
	}
	header, signed, err := preflightCompactIDToken(token)
	if err != nil {
		return verifiedIDToken{}, errIDTokenValidation
	}
	key, ok := v.keys.keys[header.kid]
	if !ok || key == nil {
		return verifiedIDToken{}, errIDTokenValidation
	}
	payload, err := signed.Verify(key)
	if err != nil {
		return verifiedIDToken{}, errIDTokenValidation
	}
	claims, err := decodeVerifiedIDTokenClaims(payload)
	if err != nil {
		return verifiedIDToken{}, errIDTokenValidation
	}
	now := v.now().UTC()
	if !claims.valid(v, now) {
		return verifiedIDToken{}, errIDTokenValidation
	}
	return verifiedIDToken{subject: claims.subject}, nil
}

func preflightCompactIDToken(token string) (protectedIDTokenHeader, *jose.JSONWebSignature, error) {
	if len(token) == 0 || len(token) > maxCompactIDTokenSize {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	segments := strings.Split(token, ".")
	if len(segments) != 3 {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	decoded := make([][]byte, len(segments))
	for i, segment := range segments {
		if segment == "" {
			return protectedIDTokenHeader{}, nil, errIDTokenValidation
		}
		value, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil || base64.RawURLEncoding.EncodeToString(value) != segment {
			return protectedIDTokenHeader{}, nil, errIDTokenValidation
		}
		decoded[i] = value
	}
	if len(decoded[0]) > maxProtectedHeaderSize ||
		!utf8.Valid(decoded[0]) || !utf8.Valid(decoded[1]) || !json.Valid(decoded[1]) {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}

	headerObject, ok := decodeJSONObject(decoded[0])
	if !ok {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	if len(headerObject) < 2 || len(headerObject) > 3 {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	for member := range headerObject {
		if !slices.Contains([]string{"alg", "kid", "typ"}, member) {
			return protectedIDTokenHeader{}, nil, errIDTokenValidation
		}
	}
	algorithm, ok := requiredJSONString(headerObject, "alg")
	if !ok || algorithm != "RS256" {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	kid, ok := requiredJSONString(headerObject, "kid")
	if !ok || len(kid) == 0 || len(kid) > maxJWKKeyIDBytes {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	if typ, present := headerObject["typ"]; present && !exactJSONString(typ, "JWT") {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}

	signed, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return protectedIDTokenHeader{}, nil, errIDTokenValidation
	}
	return protectedIDTokenHeader{kid: kid}, signed, nil
}

type verifiedIDTokenClaims struct {
	issuer             string
	subject            string
	audience           []string
	authorizedParty    string
	hasAuthorizedParty bool
	expiresAt          numericDate
	issuedAt           numericDate
	notBefore          numericDate
	hasNotBefore       bool
	nonce              string
}

func decodeVerifiedIDTokenClaims(payload []byte) (verifiedIDTokenClaims, error) {
	object, ok := decodeJSONObject(payload)
	if !ok {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}
	issuer, ok := requiredJSONString(object, "iss")
	if !ok {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}
	subject, ok := requiredJSONString(object, "sub")
	if !ok || subject == "" {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}
	audience, ok := parseAudience(object["aud"])
	if !ok {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}

	claims := verifiedIDTokenClaims{
		issuer:   issuer,
		subject:  subject,
		audience: audience,
	}
	if _, present := object["azp"]; present {
		claims.authorizedParty, ok = requiredJSONString(object, "azp")
		if !ok || claims.authorizedParty == "" {
			return verifiedIDTokenClaims{}, errIDTokenValidation
		}
		claims.hasAuthorizedParty = true
	}
	claims.expiresAt, ok = parseRequiredNumericDate(object, "exp")
	if !ok {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}
	claims.issuedAt, ok = parseRequiredNumericDate(object, "iat")
	if !ok {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}
	if raw, present := object["nbf"]; present {
		claims.notBefore, ok = parseNumericDate(raw)
		if !ok {
			return verifiedIDTokenClaims{}, errIDTokenValidation
		}
		claims.hasNotBefore = true
	}
	claims.nonce, ok = requiredJSONString(object, "nonce")
	if !ok || !canonicalTestToken(claims.nonce) {
		return verifiedIDTokenClaims{}, errIDTokenValidation
	}
	return claims, nil
}

func parseAudience(raw jsonRawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var audience []string
	if firstJSONByte(raw) == '"' {
		var value string
		if err := strictJSONUnmarshal(raw, &value); err != nil || value == "" {
			return nil, false
		}
		audience = []string{value}
	} else if err := strictJSONUnmarshal(raw, &audience); err != nil || len(audience) == 0 {
		return nil, false
	}

	seen := make(map[string]struct{}, len(audience))
	for _, value := range audience {
		if value == "" {
			return nil, false
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, false
		}
		seen[value] = struct{}{}
	}
	return audience, true
}

func firstJSONByte(raw []byte) byte {
	for _, value := range raw {
		switch value {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return value
		}
	}
	return 0
}

func parseRequiredNumericDate(object map[string]jsonRawMessage, member string) (numericDate, bool) {
	raw, present := object[member]
	if !present {
		return numericDate{}, false
	}
	return parseNumericDate(raw)
}

func parseNumericDate(raw []byte) (numericDate, bool) {
	if len(raw) == 0 || len(raw) > maxNumericDateSize {
		return numericDate{}, false
	}

	i := 0
	if raw[i] == '-' {
		i++
		if i == len(raw) {
			return numericDate{}, false
		}
	}
	integerStart := i
	if raw[i] == '0' {
		i++
		if i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			return numericDate{}, false
		}
	} else {
		if raw[i] < '1' || raw[i] > '9' {
			return numericDate{}, false
		}
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
		}
	}
	integerEnd := i
	fractionDigits := 0
	if i < len(raw) && raw[i] == '.' {
		i++
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			i++
			fractionDigits++
		}
		if fractionDigits == 0 {
			return numericDate{}, false
		}
	}
	if integerEnd-integerStart+fractionDigits > maxSignificandDigits {
		return numericDate{}, false
	}

	exponent := 0
	if i < len(raw) && (raw[i] == 'e' || raw[i] == 'E') {
		i++
		exponentNegative := false
		if i < len(raw) && (raw[i] == '+' || raw[i] == '-') {
			exponentNegative = raw[i] == '-'
			i++
		}
		if i == len(raw) || raw[i] < '0' || raw[i] > '9' {
			return numericDate{}, false
		}
		for i < len(raw) && raw[i] >= '0' && raw[i] <= '9' {
			digit := int(raw[i] - '0')
			if exponent > (maxDecimalExponent-digit)/10 {
				return numericDate{}, false
			}
			exponent = exponent*10 + digit
			i++
		}
		if exponentNegative {
			exponent = -exponent
		}
	}
	if i != len(raw) {
		return numericDate{}, false
	}

	seconds, ok := new(big.Rat).SetString(string(raw))
	if !ok {
		return numericDate{}, false
	}
	if seconds.Sign() < 0 || seconds.Cmp(big.NewRat(maxNumericDateSeconds, 1)) > 0 {
		return numericDate{}, false
	}
	return numericDate{seconds: seconds}, true
}

func (claims verifiedIDTokenClaims) valid(verifier idTokenVerifier, now time.Time) bool {
	if claims.issuer != verifier.issuer || !slices.Contains(claims.audience, verifier.clientID) {
		return false
	}
	if claims.hasAuthorizedParty && claims.authorizedParty != verifier.clientID {
		return false
	}
	if len(claims.audience) > 1 && !claims.hasAuthorizedParty {
		return false
	}
	nonceDigest := testSignInDigest(testSignInNonceDigestPurpose, claims.nonce)
	if subtle.ConstantTimeCompare(nonceDigest[:], verifier.nonceDigest[:]) != 1 {
		return false
	}

	nowSeconds := timeAsRationalSeconds(now)
	createdSeconds := timeAsRationalSeconds(verifier.transactionCreatedAt)
	skewSeconds := big.NewRat(int64(idTokenClockSkew/time.Second), 1)
	if nowSeconds.Cmp(new(big.Rat).Add(claims.expiresAt.seconds, skewSeconds)) >= 0 {
		return false
	}
	if claims.hasNotBefore && claims.notBefore.seconds.Cmp(new(big.Rat).Add(nowSeconds, skewSeconds)) > 0 {
		return false
	}
	if claims.issuedAt.seconds.Cmp(new(big.Rat).Sub(createdSeconds, skewSeconds)) < 0 {
		return false
	}
	if claims.issuedAt.seconds.Cmp(new(big.Rat).Add(nowSeconds, skewSeconds)) > 0 {
		return false
	}
	return claims.expiresAt.seconds.Cmp(claims.issuedAt.seconds) > 0
}

func timeAsRationalSeconds(value time.Time) *big.Rat {
	seconds := big.NewRat(value.Unix(), 1)
	if nanoseconds := value.Nanosecond(); nanoseconds != 0 {
		seconds.Add(seconds, big.NewRat(int64(nanoseconds), int64(time.Second)))
	}
	return seconds
}
