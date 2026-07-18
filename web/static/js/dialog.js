// dialog.js — opener for native <dialog> modals (ui/modal primitive).
//
// A button carrying data-dialog-open opens the <dialog> whose id matches the
// button's aria-controls attribute, via showModal() (which traps focus and
// enables Esc-to-close natively). Focus returns to the opener when the
// dialog closes. Ported from design/ui-architecture-spike stdlib app.js.
// This is the whole file: closing is handled by <form method="dialog">
// inside the modal markup, not by script.
export function initDialogs() {
  document.addEventListener("click", (event) => {
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
