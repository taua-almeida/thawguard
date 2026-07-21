package policy

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestBuildFreezeDescription(t *testing.T) {
	tests := []struct {
		name  string
		input FreezeDescriptionInput
		want  string
	}{
		{
			name:  "manual freeze without a reason keeps the existing description",
			input: FreezeDescriptionInput{},
			want:  "Branch is frozen; merge is blocked by Thawguard",
		},
		{
			name:  "manual freeze with a reason appends it",
			input: FreezeDescriptionInput{Reason: "Release cut in progress"},
			want:  "Branch is frozen; merge is blocked by Thawguard: Release cut in progress",
		},
		{
			name:  "scheduled freeze without a reason names the schedule",
			input: FreezeDescriptionInput{ScheduleName: "Nightly release lock"},
			want:  "Frozen by Thawguard scheduler; Scheduled (Nightly release lock)",
		},
		{
			name:  "scheduled freeze with a reason names both",
			input: FreezeDescriptionInput{ScheduleName: "Christmas shutdown", Reason: "Holiday code freeze"},
			want:  "Frozen by Thawguard scheduler; Scheduled (Christmas shutdown): Holiday code freeze",
		},
		{
			name:  "blank reason produces no trailing punctuation",
			input: FreezeDescriptionInput{ScheduleName: "Nightly release lock", Reason: "   "},
			want:  "Frozen by Thawguard scheduler; Scheduled (Nightly release lock)",
		},
		{
			name:  "blank schedule name does not claim scheduler attribution",
			input: FreezeDescriptionInput{ScheduleName: "  ", Reason: "Manual hold"},
			want:  "Branch is frozen; merge is blocked by Thawguard: Manual hold",
		},
		{
			name:  "internal whitespace collapses to a single line",
			input: FreezeDescriptionInput{ScheduleName: "Nightly   release  lock", Reason: "QA  verification"},
			want:  "Frozen by Thawguard scheduler; Scheduled (Nightly release lock): QA verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildFreezeDescription(tt.input); got != tt.want {
				t.Fatalf("BuildFreezeDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildFreezeDescriptionNeverExceedsProviderLimit(t *testing.T) {
	tests := []struct {
		name  string
		input FreezeDescriptionInput
	}{
		{
			name:  "long reason",
			input: FreezeDescriptionInput{Reason: strings.Repeat("reason ", 200)},
		},
		{
			name:  "long schedule name",
			input: FreezeDescriptionInput{ScheduleName: strings.Repeat("schedule ", 200)},
		},
		{
			name: "long name and long reason",
			input: FreezeDescriptionInput{
				ScheduleName: strings.Repeat("schedule ", 200),
				Reason:       strings.Repeat("reason ", 200),
			},
		},
		{
			name:  "multi-byte reason clipped mid-run",
			input: FreezeDescriptionInput{Reason: strings.Repeat("é", 400)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildFreezeDescription(tt.input)
			if count := utf8.RuneCountInString(got); count > FreezeDescriptionMaxLength {
				t.Fatalf("BuildFreezeDescription() returned %d runes, want at most %d", count, FreezeDescriptionMaxLength)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("BuildFreezeDescription() returned invalid UTF-8: %q", got)
			}
			if strings.HasSuffix(got, ": ") || strings.HasSuffix(got, ":") {
				t.Fatalf("BuildFreezeDescription() left dangling punctuation: %q", got)
			}
		})
	}
}

func TestBuildFreezeDescriptionKeepsAttributionWhenClipping(t *testing.T) {
	got := BuildFreezeDescription(FreezeDescriptionInput{
		ScheduleName: "Nightly release lock",
		Reason:       strings.Repeat("reason ", 200),
	})

	const wantPrefix = "Frozen by Thawguard scheduler; Scheduled (Nightly release lock): "
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("BuildFreezeDescription() = %q, want prefix %q", got, wantPrefix)
	}
	if !strings.HasSuffix(got, descriptionEllipsis) {
		t.Fatalf("BuildFreezeDescription() = %q, want a trailing ellipsis to mark the clip", got)
	}
}

func TestBuildFreezeDescriptionClipsNameInsideParentheses(t *testing.T) {
	got := BuildFreezeDescription(FreezeDescriptionInput{ScheduleName: strings.Repeat("schedule ", 200)})

	if !strings.HasPrefix(got, "Frozen by Thawguard scheduler; Scheduled (") {
		t.Fatalf("BuildFreezeDescription() = %q, want the scheduler attribution intact", got)
	}
	if !strings.HasSuffix(got, ")") {
		t.Fatalf("BuildFreezeDescription() = %q, want the closing parenthesis kept", got)
	}
}

// The evaluator's active-freeze description must be BuildFreezeDescription's
// output for that freeze, so the forge status names the schedule and reason
// truthfully. A freeze with neither keeps the original manual copy that
// several forge and status tests assert verbatim.
func TestActiveFreezeDescriptionComesFromBuilder(t *testing.T) {
	bare := freeze("main")
	bare.Reason = ""
	decision := Evaluate(Input{PullRequest: pr(1, "sha-1"), ActiveFreeze: bare})
	if decision.Description != manualFreezeDescription {
		t.Fatalf("evaluator description = %q, want %q", decision.Description, manualFreezeDescription)
	}

	withReason := freeze("main")
	decision = Evaluate(Input{PullRequest: pr(1, "sha-1"), ActiveFreeze: withReason})
	if want := manualFreezeDescription + ": release window"; decision.Description != want {
		t.Fatalf("evaluator description = %q, want %q", decision.Description, want)
	}

	scheduled := freeze("main")
	scheduled.ScheduleName = "Nightly release lock"
	decision = Evaluate(Input{PullRequest: pr(1, "sha-1"), ActiveFreeze: scheduled})
	want := BuildFreezeDescription(FreezeDescriptionInput{ScheduleName: "Nightly release lock", Reason: "release window"})
	if decision.Description != want {
		t.Fatalf("evaluator description = %q, want %q", decision.Description, want)
	}
	if want != "Frozen by Thawguard scheduler; Scheduled (Nightly release lock): release window" {
		t.Fatalf("scheduled description copy drifted: %q", want)
	}
}
