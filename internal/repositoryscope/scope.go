// Package repositoryscope carries the set of repositories a read query may
// return. A ReadScope is derived from a session's authorization snapshot and
// handed to stores, which apply it inside SQL so invisible rows never leave
// the database. It is deliberately not a query builder or an authorization
// framework: it answers one question — which repository IDs may this read
// see — as a single parameterized predicate.
package repositoryscope

import (
	"slices"
	"strings"
)

// ReadScope names the repositories a read query may return. The zero value
// denies every repository, so an unset or forgotten scope fails closed.
// Its state is unexported; a permitting scope can only be built through All
// or IDs.
type ReadScope struct {
	all bool
	// ids holds the visible repository IDs, normalized by IDs to positive,
	// deduplicated, ascending values in a slice this scope owns.
	ids []int64
}

// All returns a scope over every repository, for admins and for internal
// paths that are intentionally unrestricted.
func All() ReadScope {
	return ReadScope{all: true}
}

// IDs returns a scope over exactly the given repository IDs. Non-positive
// IDs are dropped, duplicates collapse, and the kept IDs are copied and
// sorted so equal grant sets always produce identical scopes. No kept IDs
// normalizes to the zero deny-all scope.
func IDs(ids ...int64) ReadScope {
	kept := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			kept = append(kept, id)
		}
	}
	slices.Sort(kept)
	kept = slices.Compact(kept)
	if len(kept) == 0 {
		return ReadScope{}
	}
	return ReadScope{ids: kept}
}

// SQLPredicate returns a parameterized visibility predicate over column and
// the arguments it binds. The column must be a code-owned identifier such as
// "id" or "repository_id", never user input. A deny-all scope yields "1 = 0",
// an all-repositories scope yields "1 = 1", and a bounded scope yields a
// "column IN (?, …)" predicate.
func (s ReadScope) SQLPredicate(column string) (string, []any) {
	if s.all {
		return "1 = 1", nil
	}
	if len(s.ids) == 0 {
		return "1 = 0", nil
	}
	placeholders := make([]string, len(s.ids))
	args := make([]any, len(s.ids))
	for i, id := range s.ids {
		placeholders[i] = "?"
		args[i] = id
	}
	return column + " IN (" + strings.Join(placeholders, ", ") + ")", args
}
