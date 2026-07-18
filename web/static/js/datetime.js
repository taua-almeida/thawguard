// datetime.js — browser-local datetime support for freeze forms (imported by
// main.js so the shell keeps exactly two external <script src> tags).
//
// Server-rendered contract: a [data-local-datetime] input starts disabled and
// pairs with a <noscript> warning, because a planned unfreeze is only
// meaningful when the browser can interpret the value in the user's local
// timezone. This module enables the input and keeps the form's hidden
// [data-timezone-offset-minutes] field current so the server can convert the
// local value to UTC. The offset is read at the chosen time, not "now", so
// values across a DST transition convert correctly.

export function applyLocalDatetimes(root = document) {
  root.querySelectorAll("[data-local-datetime]").forEach((input) => {
    input.disabled = false;
    updateTimezoneOffset(input.form);
  });
}

export function initLocalDatetimes() {
  applyLocalDatetimes();
  document.addEventListener("change", (event) => {
    if (event.target.matches?.("[data-local-datetime]")) {
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
  const picker = form.querySelector("[data-local-datetime]");
  const chosen = picker?.value ? new Date(picker.value) : new Date();
  if (!Number.isNaN(chosen.getTime())) {
    offsetField.value = String(chosen.getTimezoneOffset());
  }
}
