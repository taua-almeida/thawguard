package repositoryscope

import (
	"reflect"
	"testing"
)

func TestZeroValueDeniesAllRepositories(t *testing.T) {
	var scope ReadScope

	predicate, args := scope.SQLPredicate("repository_id")
	if predicate != "1 = 0" {
		t.Fatalf("expected deny-all predicate, got %q", predicate)
	}
	if len(args) != 0 {
		t.Fatalf("expected no arguments, got %+v", args)
	}
}

func TestAllPermitsEveryRepository(t *testing.T) {
	predicate, args := All().SQLPredicate("repository_id")
	if predicate != "1 = 1" {
		t.Fatalf("expected unrestricted predicate, got %q", predicate)
	}
	if len(args) != 0 {
		t.Fatalf("expected no arguments, got %+v", args)
	}
}

func TestIDsNormalizesToDeterministicBoundedScope(t *testing.T) {
	scope := IDs(7, 3, 7, 0, -2, 3)

	predicate, args := scope.SQLPredicate("id")
	if predicate != "id IN (?, ?)" {
		t.Fatalf("expected two-placeholder predicate, got %q", predicate)
	}
	if !reflect.DeepEqual(args, []any{int64(3), int64(7)}) {
		t.Fatalf("expected sorted deduplicated arguments, got %+v", args)
	}
	if !reflect.DeepEqual(scope, IDs(3, 7)) {
		t.Fatalf("expected equal grant sets to produce identical scopes, got %+v", scope)
	}
}

func TestIDsWithoutPositiveIDsNormalizesToZeroDenyAll(t *testing.T) {
	for name, scope := range map[string]ReadScope{
		"no ids":      IDs(),
		"invalid ids": IDs(0, -1),
		"zero value":  {},
	} {
		if !reflect.DeepEqual(scope, ReadScope{}) {
			t.Fatalf("%s: expected the canonical deny-all scope, got %+v", name, scope)
		}
		if predicate, _ := scope.SQLPredicate("id"); predicate != "1 = 0" {
			t.Fatalf("%s: expected deny-all predicate, got %q", name, predicate)
		}
	}
}

func TestIDsCopiesCallerSlice(t *testing.T) {
	ids := []int64{5, 9}
	scope := IDs(ids...)
	ids[0] = 999

	_, args := scope.SQLPredicate("id")
	if !reflect.DeepEqual(args, []any{int64(5), int64(9)}) {
		t.Fatalf("expected scope insulated from caller mutation, got %+v", args)
	}
}
