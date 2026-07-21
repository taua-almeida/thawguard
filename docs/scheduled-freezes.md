# Scheduled freezes

Thawguard freezes branches on a schedule in two ways:

- **One-time scheduled freezes** — a single pending window with a future start time and an optional planned unfreeze for one exact repository and managed branch.
- **Recurring schedules** — named schedules that freeze the same exact branch repeatedly, either on weekly rules or on manually entered dated windows.

Both require an enforcement-active repository before they can freeze anything, and both publish the same real `thawguard/freeze` commit status through the same durable convergence path as manual freezes.

## Coverage is a union

Freeze coverage is additive. A branch is frozen while **any** source covers the current moment: a manual freeze, a one-time scheduled freeze, or any active recurring schedule's rule or window. Sources never cancel each other — ending one leaves the branch frozen if another still covers it. When several active schedules target the same repository and branch, the schedule detail page shows their combined coverage so the handover between overlapping windows is visible.

## Recurring schedules

A recurring schedule belongs to one exact repository and managed branch and has:

- a **name**, shown in the UI and in forge-facing status descriptions;
- a **kind**, either *weekly* or *dated* — the kind determines how the schedule's entries are interpreted and cannot be changed after creation;
- an explicit **IANA timezone** (for example `America/Sao_Paulo`), persisted by zone name rather than UTC offset so the schedule follows the zone's daylight-saving rules;
- an optional **reason**, included in status descriptions when present;
- an **active/paused** state. A paused schedule never freezes its branch.

A weekly schedule needs at least one rule, and a dated schedule at least one date window, before it can be activated.

### Weekly rules

Each weekly rule is a start weekday and time and an end weekday and time, at minute precision, in the schedule's timezone. An end at or before its start wraps into the following week, so a single rule expresses windows like "Friday 18:00 → Monday 08:00". Rules repeat every week; there is no month or year recurrence.

### Dated windows

Each dated window is a named local start and end wall-clock timestamp in the schedule's timezone — "these local dates and times", not fixed UTC instants. Windows are entered manually, one at a time; Thawguard ships no holiday calendars and never invents dates. Past windows are retained internally but no longer rendered.

## Timezones and daylight saving

Schedule boundaries are resolved through the zone's real DST rules:

- A wall time **skipped** by a spring-forward transition resolves to the first valid instant after the gap, for both starts and ends.
- A wall time **repeated** by a fall-back transition resolves so coverage is never shortened: a start takes the first occurrence, an end takes the second.
- A dated window entirely swallowed by a transition covers nothing rather than guessing.

The schedule's coverage preview shows a plain-language note when a previewed boundary falls on a DST transition, so the resolved instant is never a surprise.

## Status descriptions and attribution

Forge commit-status descriptions state only what Thawguard can prove:

- A manual freeze reads `Branch is frozen; merge is blocked by Thawguard`, followed by `: <reason>` when a reason was given.
- A schedule-materialized freeze reads `Frozen by Thawguard scheduler; Scheduled (<schedule name>)`, followed by the optional reason.

Descriptions are built to the tightest provider limit (255 characters), trimming the reason before the attribution so the text never loses who froze the branch. When a dated window and a weekly rule cover the same moment, the dated window's name is used for attribution; coverage itself remains the union either way.

## Ending a scheduled freeze early

An operator can end a freeze that a schedule materialized. The schedule stays active but is **suppressed** until its next scheduled window: it will not re-freeze the branch before that instant, and it resumes normally when the next window starts. Other overlapping manual, one-time, or recurring sources still keep the branch frozen under the union model. The manual end and the resume time are recorded in the audit trail, and the schedule detail page shows the suppression while it lasts.

## One-time scheduled freezes

One-time scheduled freezes remain pending until their start time. While pending, the reason, future start time, and optional planned unfreeze can be edited; repository and branch are immutable. **Start Now** activates a still-pending schedule immediately through the normal convergence path, preserving any future planned unfreeze. Only pending one-time schedules can be edited, cancelled, or started now.

## Roles

Creating recurring schedules, adding or removing rules and windows, activating, pausing, and deleting them requires the Administrator or Freezer role. For one-time scheduled freezes, creation and cancellation require Freezer, while editing a pending schedule and Start Now allow Administrator or Freezer. Viewers see everything read-only.

## Boundary

Scheduled freezes are cooperative enforcement for trusted teams. They prevent accidental merges and keep freeze windows auditable. They are not a hard security boundary against forge writers who can post or override commit statuses with sufficient permission.
