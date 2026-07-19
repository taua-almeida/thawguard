// dialog.js — opener and dismisser for native <dialog> modals (ui/modal
// primitive).
//
// A button carrying data-dialog-open opens the <dialog> whose id matches the
// button's aria-controls attribute, via showModal() (which traps focus and
// enables Esc-to-close natively). Focus returns to the opener when the
// dialog closes. Ported from design/ui-architecture-spike stdlib app.js.
//
// Dismiss buttons (formmethod="dialog") close on click here rather than via
// native dialog form submission: htmx calls preventDefault() on every submit
// event of an hx-post form, which would cancel the browser's built-in
// formmethod="dialog" close and leave the dialog stuck open. Closing on
// click means no submit event is ever dispatched, so htmx stays out of it.
// Without JS the native formmethod="dialog" behavior still applies.
export function initDialogs() {
  document.addEventListener("click", (event) => {
    const dismisser = event.target.closest('button[formmethod="dialog"]');
    if (dismisser) {
      const dialog = dismisser.closest("dialog");
      if (dialog instanceof HTMLDialogElement) {
        event.preventDefault();
        dialog.close();
      }
      return;
    }
    const opener = event.target.closest("[data-dialog-open]");
    if (!opener) {
      return;
    }
    const dialog = document.getElementById(opener.getAttribute("aria-controls"));
    if (!(dialog instanceof HTMLDialogElement)) {
      return;
    }
    dialog.showModal();
    dialog.addEventListener("close", () => opener.focus(), { once: true });
  });
}

// A server can re-open a dialog after a validation error by rendering the
// `open` attribute (values preserved, error callout inside). That renders
// as an in-flow non-modal dialog — the no-JS fallback — so upgrade it to
// showModal() for focus trapping and Esc-to-close. Runs at load and after
// every htmx swap; dialogs already shown modally are left alone.
export function upgradeOpenDialogs() {
  document.querySelectorAll("dialog[open]").forEach((dialog) => {
    if (dialog.matches(":modal")) {
      return;
    }
    dialog.close();
    dialog.showModal();
  });
}
