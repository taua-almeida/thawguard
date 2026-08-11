package forgeidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	// maxProviderJSONDepth bounds nesting for provider responses: the root
	// object plus three levels of ancillary structure.
	maxProviderJSONDepth = 4
	// maxProviderJSONMembers bounds the values one container may carry.
	maxProviderJSONMembers = 128
)

var errProviderJSONInvalid = errors.New("provider JSON is invalid")

// strictProviderObject validates exactly one bounded JSON object and
// returns its root members. Every object level rejects duplicate member
// names; the root additionally rejects ASCII-case-fold aliases of the
// critical keys, so encoding/json's case-insensitive matching can never
// redefine a validated member. Trailing data is rejected.
func strictProviderObject(body []byte, criticalKeys []string) (map[string]json.RawMessage, bool) {
	if err := validateProviderJSONShape(body, criticalKeys); err != nil {
		return nil, false
	}
	var object map[string]json.RawMessage
	if err := strictProviderDecode(body, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func providerJSONString(object map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := object[key]
	if !ok {
		return "", false
	}
	var value string
	if err := strictProviderDecode(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// providerJSONPositiveInt requires the member to be a canonical positive
// JSON integer literal within signed int64 range and returns its exact
// decimal text. A quoted numeric string is rejected: encoding/json would
// otherwise decode it into json.Number.
func providerJSONPositiveInt(object map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := object[key]
	if !ok {
		return "", false
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] == '"' {
		return "", false
	}
	var value json.Number
	if err := strictProviderDecode(raw, &value); err != nil {
		return "", false
	}
	text := value.String()
	if !validRemoteUserID(text) {
		return "", false
	}
	return text, true
}

func strictProviderDecode(body []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return errProviderJSONInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errProviderJSONInvalid
	}
	return nil
}

func validateProviderJSONShape(body []byte, criticalKeys []string) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	opening, err := decoder.Token()
	if err != nil {
		return errProviderJSONInvalid
	}
	if delimiter, ok := opening.(json.Delim); !ok || delimiter != '{' {
		return errProviderJSONInvalid
	}
	if err := validateProviderJSONObject(decoder, 1, criticalKeys); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errProviderJSONInvalid
	}
	return nil
}

// validateProviderJSONObject consumes one already-opened object at depth,
// enforcing member and depth bounds. criticalKeys is non-nil only at the
// root level.
func validateProviderJSONObject(decoder *json.Decoder, depth int, criticalKeys []string) error {
	members := make(map[string]struct{})
	for decoder.More() {
		if len(members) == maxProviderJSONMembers {
			return errProviderJSONInvalid
		}
		token, err := decoder.Token()
		if err != nil {
			return errProviderJSONInvalid
		}
		member, ok := token.(string)
		if !ok {
			return errProviderJSONInvalid
		}
		if _, duplicate := members[member]; duplicate {
			return errProviderJSONInvalid
		}
		members[member] = struct{}{}
		for _, critical := range criticalKeys {
			if member != critical && strings.EqualFold(member, critical) {
				return errProviderJSONInvalid
			}
		}
		if err := validateProviderJSONValue(decoder, depth); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Token(json.Delim('}')) {
		return errProviderJSONInvalid
	}
	return nil
}

func validateProviderJSONArray(decoder *json.Decoder, depth int) error {
	elements := 0
	for decoder.More() {
		if elements == maxProviderJSONMembers {
			return errProviderJSONInvalid
		}
		if err := validateProviderJSONValue(decoder, depth); err != nil {
			return err
		}
		elements++
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Token(json.Delim(']')) {
		return errProviderJSONInvalid
	}
	return nil
}

func validateProviderJSONValue(decoder *json.Decoder, depth int) error {
	token, err := decoder.Token()
	if err != nil {
		return errProviderJSONInvalid
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= maxProviderJSONDepth {
		return errProviderJSONInvalid
	}
	switch delimiter {
	case '{':
		return validateProviderJSONObject(decoder, depth+1, nil)
	case '[':
		return validateProviderJSONArray(decoder, depth+1)
	default:
		return errProviderJSONInvalid
	}
}
