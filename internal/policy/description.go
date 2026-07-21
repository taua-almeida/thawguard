package policy

import (
	"strings"
	"unicode/utf8"
)

const (
	// FreezeDescriptionMaxLength is the tightest commit-status description
	// limit across the forges Thawguard targets. Forgejo and GitHub both cap
	// status descriptions at 255 characters, so building to that bound keeps
	// the text intact instead of letting a provider truncate it mid-word.
	FreezeDescriptionMaxLength = 255

	manualFreezeDescription    = "Branch is frozen; merge is blocked by Thawguard"
	scheduledFreezeDescription = "Frozen by Thawguard scheduler"

	descriptionEllipsis = "…"

	// A reason clipped shorter than this carries no information worth the
	// punctuation, so it is dropped instead of rendered as noise.
	minimumReasonRunes = 8
)

// FreezeDescriptionInput carries the attribution Thawguard can actually prove
// about an active freeze. Both fields are optional: a freeze an operator
// started by hand has no schedule name, and reasons are optional everywhere.
type FreezeDescriptionInput struct {
	// ScheduleName is the name of the schedule that materialized this freeze.
	// Empty for manual freezes.
	ScheduleName string
	// Reason is the operator-supplied reason, if one was given.
	Reason string
}

// BuildFreezeDescription renders the commit-status description for a frozen
// branch.
//
// It never invents attribution: a freeze with no schedule is described as a
// plain freeze rather than a scheduled one, and an absent reason produces no
// trailing colon or dangling separator. The result always fits within
// FreezeDescriptionMaxLength runes, trimming the reason before the attribution
// so the text never loses the part that says who froze the branch.
func BuildFreezeDescription(in FreezeDescriptionInput) string {
	name := collapseDescriptionWhitespace(in.ScheduleName)
	reason := collapseDescriptionWhitespace(in.Reason)

	lead := manualFreezeDescription
	if name != "" {
		lead = buildScheduledLead(name)
	}

	if reason == "" {
		return lead
	}

	const separator = ": "
	budget := FreezeDescriptionMaxLength - utf8.RuneCountInString(lead) - len(separator)
	if budget < minimumReasonRunes {
		return lead
	}
	return lead + separator + truncateRunes(reason, budget)
}

// buildScheduledLead keeps the closing parenthesis attached to the schedule
// name, so an over-long name is clipped inside the parentheses rather than
// swallowing them.
func buildScheduledLead(name string) string {
	prefix := scheduledFreezeDescription + "; Scheduled ("
	const suffix = ")"

	// Unreachable with the current prefix length; kept because truncateRunes
	// requires a positive budget, and a future copy change to the prefix must
	// degrade to the bare attribution rather than panic.
	budget := FreezeDescriptionMaxLength - utf8.RuneCountInString(prefix) - len(suffix)
	if budget < minimumReasonRunes {
		return scheduledFreezeDescription
	}
	return prefix + truncateRunes(name, budget) + suffix
}

// truncateRunes clips s to max runes, spending the last rune on an ellipsis so
// the reader can tell the text was cut. It counts runes rather than bytes so a
// multi-byte character is never split in half.
func truncateRunes(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	kept := []rune(s)[:max-1]
	return strings.TrimRight(string(kept), " ") + descriptionEllipsis
}

// collapseDescriptionWhitespace flattens a value into the single line a commit
// status renders: runs of whitespace (including newlines and tabs in reasons
// stored before validation covered the manual path) collapse to single spaces.
func collapseDescriptionWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
