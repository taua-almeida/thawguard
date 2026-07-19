// datetime.js — browser-local datetime support for freeze forms (imported by
// main.js so the shell keeps exactly two external <script src> tags).
//
// Server-rendered contract, two flavors:
//
// * /freezes: a [data-local-datetime] input starts disabled and pairs with a
//   <noscript> warning, because a planned unfreeze is only meaningful when
//   the browser can interpret the value in the user's local timezone. This
//   module enables the input.
// * /scheduled-freezes: pickers stay enabled without JS (times are then
//   interpreted as UTC, matching the page's <noscript> note). The server
//   renders every timestamp as UTC inside <time datetime="<RFC3339>"> plus a
//   [data-timezone-note] reading "Times shown in UTC."; this module rewrites
//   the text to the browser's local timezone and updates the note. Edit-panel
//   pickers carry the stored UTC value in [data-utc-datetime] for local
//   prefill (absent after a failed submit, so the submitted text survives).
//
// Both flavors keep the form's hidden [data-timezone-offset-minutes] field
// current so the server can convert local values to UTC. The offset is read
// at the chosen time, not "now", so values across a DST transition convert
// correctly. Everything runs inside applyLocalDatetimes so htmx swaps just
// re-apply it; all transforms are idempotent.

export function applyLocalDatetimes(root = document) {
  root.querySelectorAll("[data-local-datetime]").forEach((input) => {
    input.disabled = false;
  });
  root.querySelectorAll("input[data-utc-datetime]").forEach((input) => {
    const parsed = new Date(input.dataset.utcDatetime);
    if (!Number.isNaN(parsed.getTime())) {
      input.value = localPickerValue(parsed);
    }
  });
  root.querySelectorAll("[data-timezone-offset-minutes]").forEach((field) => {
    updateTimezoneOffset(field.form);
  });
  root.querySelectorAll("time[datetime]").forEach((el) => {
    const parsed = new Date(el.dateTime);
    if (Number.isNaN(parsed.getTime())) return;
    if (!el.title) el.title = el.textContent.trim();
    el.textContent = localDisplayValue(parsed);
  });
  root.querySelectorAll("[data-timezone-note]").forEach((note) => {
    note.textContent = `Times shown in your local timezone (${utcOffsetLabel(new Date().getTimezoneOffset())}). Stored as UTC.`;
  });
}

export function initLocalDatetimes() {
  applyLocalDatetimes();
  document.addEventListener("change", (event) => {
    if (event.target.matches?.("[data-local-datetime], input[type='datetime-local']")) {
      updateTimezoneOffset(event.target.form);
    }
  });
  document.addEventListener("submit", (event) => {
    if (event.target.querySelector?.("[data-timezone-offset-minutes]")) {
      updateTimezoneOffset(event.target);
    }
  });
}

function updateTimezoneOffset(form) {
  if (!form) return;
  const offsetField = form.querySelector("[data-timezone-offset-minutes]");
  if (!offsetField) return;
  const picker = form.querySelector("[data-local-datetime], input[type='datetime-local']");
  const chosen = picker?.value ? new Date(picker.value) : new Date();
  if (!Number.isNaN(chosen.getTime())) {
    offsetField.value = String(chosen.getTimezoneOffset());
  }
}

function pad(value) {
  return String(value).padStart(2, "0");
}

// "YYYY-MM-DDTHH:MM" in local time, the value format datetime-local expects.
function localPickerValue(date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// "YYYY-MM-DD HH:MM" in local time for <time> element text.
function localDisplayValue(date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

// getTimezoneOffset is minutes behind UTC, so positive means "UTC−…" (west).
function utcOffsetLabel(offsetMinutes) {
  const sign = offsetMinutes > 0 ? "−" : "+";
  const abs = Math.abs(offsetMinutes);
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
}
