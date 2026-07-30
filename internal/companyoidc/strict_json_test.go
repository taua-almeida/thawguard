package companyoidc

import (
	"strconv"
	"strings"
	"testing"
)

func TestStrictJSONNestingDepthBoundary(t *testing.T) {
	t.Run("depth 32", func(t *testing.T) {
		var target any
		if err := strictJSONUnmarshal(nestedJSONArray(maxJSONNestingDepth), &target); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("depth 33", func(t *testing.T) {
		var target any
		assertInvalidJSON(t, strictJSONUnmarshal(nestedJSONArray(maxJSONNestingDepth+1), &target))
	})
}

func TestStrictJSONRequiresOneUTF8Value(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`{"value":1} {"value":2}`),
		[]byte("{\"value\":\"\xff\"}"),
	} {
		var target any
		assertInvalidJSON(t, strictJSONUnmarshal(body, &target))
	}
}

func TestStrictJSONMaximumBodyRejectsExcessiveDepth(t *testing.T) {
	body := nestedJSONArray(maxJSONNestingDepth + 1)
	body = append(body, strings.Repeat(" ", setupCheckMaxBodySize-len(body))...)
	if len(body) != setupCheckMaxBodySize {
		t.Fatalf("test body size = %d, want %d", len(body), setupCheckMaxBodySize)
	}

	var target any
	assertInvalidJSON(t, strictJSONUnmarshal(body, &target))
}

func TestStrictJSONContainerLimits(t *testing.T) {
	for _, count := range []int{maxJSONContainerValues, maxJSONContainerValues + 1} {
		t.Run("object "+strconv.Itoa(count), func(t *testing.T) {
			var target map[string]jsonRawMessage
			err := strictJSONUnmarshal(jsonObjectWithMembers(count), &target)
			if count == maxJSONContainerValues {
				if err != nil || len(target) != count {
					t.Fatalf("strictJSONUnmarshal object = %d members, error %v", len(target), err)
				}
				return
			}
			assertInvalidJSON(t, err)
		})

		t.Run("array "+strconv.Itoa(count), func(t *testing.T) {
			var target []jsonRawMessage
			err := strictJSONUnmarshal(jsonArrayWithElements(count, "null"), &target)
			if count == maxJSONContainerValues {
				if err != nil || len(target) != count {
					t.Fatalf("strictJSONUnmarshal array = %d elements, error %v", len(target), err)
				}
				return
			}
			assertInvalidJSON(t, err)
		})
	}
}

func TestStrictJSONRejectsNestedDuplicateMembers(t *testing.T) {
	body := []byte(`{"outer":[{"member":1,"member":2}]}`)
	var target map[string]jsonRawMessage
	assertInvalidJSON(t, strictJSONUnmarshal(body, &target))
}

func TestStrictJSONPreservesValidLargeIgnoredNumbers(t *testing.T) {
	body := []byte(`{"known":"value","extension":1e400}`)
	var target struct {
		Known string `json:"known"`
	}
	if err := strictJSONUnmarshal(body, &target); err != nil {
		t.Fatal(err)
	}
	if target.Known != "value" {
		t.Fatalf("known value = %q", target.Known)
	}

	var raw map[string]jsonRawMessage
	if err := strictJSONUnmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	if got := string(raw["extension"]); got != "1e400" {
		t.Fatalf("extension number = %q, want original spelling", got)
	}
}

func TestStrictJSONRejectsExcessiveJWKSKeysBeforeTargetMaterialization(t *testing.T) {
	accepted := jsonMaterializationCanary{}
	if err := strictJSONUnmarshalWithRootContainerLimit(
		jsonArrayWithElements(maxJWKSKeys, "{}"),
		&accepted,
		maxJWKSKeys,
	); err != nil {
		t.Fatal(err)
	}
	if !accepted.called {
		t.Fatal("bounded JWKS did not reach target decoder")
	}

	rejected := jsonMaterializationCanary{}
	assertInvalidJSON(t, strictJSONUnmarshalWithRootContainerLimit(
		jsonArrayWithElements(maxJWKSKeys+1, "{}"),
		&rejected,
		maxJWKSKeys,
	))
	if rejected.called {
		t.Fatal("excessive-key JWKS reached target decoder")
	}
}

func TestStrictJSONRejectedRemainderDoesNotIncreaseAllocations(t *testing.T) {
	small := jsonArrayWithElements(maxJWKSKeys+1, "null")
	large := maximumJSONWithUnparsedContainerRemainder()
	if len(large) != setupCheckMaxBodySize {
		t.Fatalf("large body size = %d, want %d", len(large), setupCheckMaxBodySize)
	}

	smallAllocs := rejectedJSONAllocations(small, maxJWKSKeys)
	largeAllocs := rejectedJSONAllocations(large, maxJWKSKeys)
	if largeAllocs > smallAllocs+2 {
		t.Fatalf("rejected JSON allocations scale with unparsed remainder: small %.0f, large %.0f", smallAllocs, largeAllocs)
	}
}

type jsonMaterializationCanary struct {
	called bool
}

func (c *jsonMaterializationCanary) UnmarshalJSON([]byte) error {
	c.called = true
	return nil
}

func assertInvalidJSON(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("strictJSONUnmarshal accepted invalid JSON")
	}
	if err.Error() != "invalid JSON" {
		t.Fatalf("strictJSONUnmarshal error = %q, want sanitized error", err)
	}
}

func nestedJSONArray(depth int) []byte {
	return []byte(strings.Repeat("[", depth) + "null" + strings.Repeat("]", depth))
}

func jsonObjectWithMembers(count int) []byte {
	var body strings.Builder
	body.WriteByte('{')
	for i := range count {
		if i > 0 {
			body.WriteByte(',')
		}
		body.WriteString(`"member`)
		body.WriteString(strconv.Itoa(i))
		body.WriteString(`":null`)
	}
	body.WriteByte('}')
	return []byte(body.String())
}

func jsonArrayWithElements(count int, element string) []byte {
	var body strings.Builder
	body.WriteByte('[')
	for i := range count {
		if i > 0 {
			body.WriteByte(',')
		}
		body.WriteString(element)
	}
	body.WriteByte(']')
	return []byte(body.String())
}

func jwksWithKeyCount(count int) []byte {
	return append(append([]byte(`{"keys":`), jsonArrayWithElements(count, "{}")...), '}')
}

func maximumJSONWithUnparsedContainerRemainder() []byte {
	var body strings.Builder
	body.Grow(setupCheckMaxBodySize)
	body.WriteByte('[')
	for i := range maxJWKSKeys {
		if i > 0 {
			body.WriteByte(',')
		}
		body.WriteString("null")
	}
	body.WriteString(",[ ")

	first := true
	for {
		entrySize := len("{}")
		if !first {
			entrySize++
		}
		if body.Len()+entrySize+len("]] ") > setupCheckMaxBodySize {
			break
		}
		if !first {
			body.WriteByte(',')
		}
		body.WriteString("{}")
		first = false
	}
	body.WriteString("]] ")
	body.WriteString(strings.Repeat(" ", setupCheckMaxBodySize-body.Len()))
	return []byte(body.String())
}

func rejectedJSONAllocations(body []byte, containerLimit int) float64 {
	return testing.AllocsPerRun(5, func() {
		var target any
		if err := strictJSONUnmarshalWithRootContainerLimit(body, &target, containerLimit); err == nil {
			panic("test JSON unexpectedly passed structural validation")
		}
	})
}
