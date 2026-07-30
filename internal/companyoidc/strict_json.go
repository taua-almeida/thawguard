package companyoidc

import (
	"bytes"
	stdjson "encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	josejson "github.com/go-jose/go-jose/v4/json"
)

const (
	maxJSONNestingDepth    = 32
	maxJSONContainerValues = 4096
)

var errInvalidJSON = errors.New("invalid JSON")

type jsonRawMessage = josejson.RawMessage

func strictJSONUnmarshal(body []byte, target any) error {
	return strictJSONUnmarshalWithRootContainerLimit(body, target, maxJSONContainerValues)
}

func strictJSONUnmarshalWithRootContainerLimit(body []byte, target any, rootContainerLimit int) error {
	if rootContainerLimit <= 0 || !utf8.Valid(body) {
		return errInvalidJSON
	}
	if err := validateJSONStructure(body, rootContainerLimit); err != nil {
		return errInvalidJSON
	}
	if err := josejson.Unmarshal(body, target); err != nil {
		return errInvalidJSON
	}
	return nil
}

func validateJSONStructure(body []byte, containerLimit int) error {
	decoder := stdjson.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, 0, containerLimit); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

func validateJSONValue(decoder *stdjson.Decoder, depth, containerLimit int) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, ok := token.(stdjson.Delim)
	if !ok {
		return nil
	}
	if depth >= maxJSONNestingDepth {
		return errInvalidJSON
	}

	switch delimiter {
	case '{':
		return validateJSONObject(decoder, depth+1, containerLimit)
	case '[':
		return validateJSONArray(decoder, depth+1, containerLimit)
	default:
		return errInvalidJSON
	}
}

func validateJSONObject(decoder *stdjson.Decoder, depth, containerLimit int) error {
	members := make(map[string]struct{})
	for decoder.More() {
		if len(members) == containerLimit {
			return errInvalidJSON
		}

		token, err := decoder.Token()
		if err != nil {
			return err
		}
		member, ok := token.(string)
		if !ok {
			return errInvalidJSON
		}
		if _, duplicate := members[member]; duplicate {
			return errInvalidJSON
		}
		members[member] = struct{}{}

		if err := validateJSONValue(decoder, depth, maxJSONContainerValues); err != nil {
			return err
		}
	}

	closing, err := decoder.Token()
	if err != nil || closing != stdjson.Delim('}') {
		return errInvalidJSON
	}
	return nil
}

func validateJSONArray(decoder *stdjson.Decoder, depth, containerLimit int) error {
	elements := 0
	for decoder.More() {
		if elements == containerLimit {
			return errInvalidJSON
		}
		if err := validateJSONValue(decoder, depth, maxJSONContainerValues); err != nil {
			return err
		}
		elements++
	}

	closing, err := decoder.Token()
	if err != nil || closing != stdjson.Delim(']') {
		return errInvalidJSON
	}
	return nil
}

func decodeJSONObject(body []byte) (map[string]jsonRawMessage, bool) {
	var object map[string]jsonRawMessage
	if err := strictJSONUnmarshal(body, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func requiredJSONString(object map[string]jsonRawMessage, key string) (string, bool) {
	raw, ok := object[key]
	if !ok {
		return "", false
	}
	var value string
	if err := strictJSONUnmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}

func requiredStringSlice(object map[string]jsonRawMessage, key string) ([]string, bool) {
	raw, ok := object[key]
	if !ok {
		return nil, false
	}
	var values []string
	if err := strictJSONUnmarshal(raw, &values); err != nil || values == nil {
		return nil, false
	}
	return values, true
}

func exactJSONString(raw jsonRawMessage, wanted string) bool {
	var value string
	return strictJSONUnmarshal(raw, &value) == nil && value == wanted
}
