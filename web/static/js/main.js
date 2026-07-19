// main.js — the single script entry point for the app shell (loaded as an
// ES module; dialog.js and datetime.js are imported here so the shell carries
// exactly two external <script src> tags: htmx.min.js and this file).
//
// htmx response-handling policy (decided in design/ui-architecture-spike):
//
// * 5xx responses SWAP. Thawguard error handlers render swappable error
//   panel fragments, so replacing the target with the server's error panel
//   beats htmx's silent default. We opt in via htmx:beforeSwap below.
// * 4xx guard failures keep htmx's default of NOT swapping: 4xx bodies are
//   full-page login/permission responses, not fragments; the surrounding
//   page state stays intact and the action's own error reporting applies.
// * Server-side requirement (not enforceable here, documented for 0.7):
//   any endpoint that returns both a full page and an htmx fragment for the
//   same URL must send "Vary: HX-Request" so shared caches never serve a
//   fragment to a full-page navigation or vice versa.
import { initDialogs, upgradeOpenDialogs } from "./dialog.js";
import { applyLocalDatetimes, initLocalDatetimes } from "./datetime.js";

initDialogs();
initLocalDatetimes();
upgradeOpenDialogs();

// Freeze-form branch filtering and selection echo. All hooks are declarative
// data-* attributes and every listener is delegated, so htmx swaps need no
// re-binding: a [data-branch-filter] select narrows its form's
// [data-branch-options] select to options whose data-repository matches, and
// [data-preview-repository] / [data-preview-branch] echo the current choice.
// Without JS the branch select simply shows every managed branch; the server
// validates the pair on submit.
function applyBranchFilters(root = document) {
  root.querySelectorAll("[data-branch-filter]").forEach((repo) => {
    const branch = repo.form?.querySelector("[data-branch-options]");
    if (!branch) return;
    let first = null;
    for (const option of branch.options) {
      const match = option.dataset.repository === repo.value;
      option.hidden = !match;
      option.disabled = !match;
      if (match && first === null) first = option;
    }
    const selected = branch.options[branch.selectedIndex];
    if ((!selected || selected.disabled) && first !== null) {
      branch.value = first.value;
    }
    updateSelectionEcho(repo, branch);
  });
}

function updateSelectionEcho(repo, branch) {
  const repoOut = document.querySelector("[data-preview-repository]");
  const branchOut = document.querySelector("[data-preview-branch]");
  if (repoOut) {
    repoOut.textContent = repo.options[repo.selectedIndex]?.textContent?.trim() || "Selected repository";
  }
  if (branchOut) {
    branchOut.textContent = branch?.value.trim() || "branch";
  }
}

applyBranchFilters();

document.addEventListener("change", (event) => {
  const target = event.target;
  if (target.matches?.("[data-branch-filter]")) {
    applyBranchFilters();
  } else if (target.matches?.("[data-branch-options]")) {
    const repo = target.form?.querySelector("[data-branch-filter]");
    if (repo) updateSelectionEcho(repo, target);
  }
});

document.addEventListener("htmx:afterSwap", () => {
  applyBranchFilters();
  applyLocalDatetimes();
  upgradeOpenDialogs();
});

document.addEventListener("htmx:beforeSwap", (event) => {
  // 409 carries a renderable fragment: the thaw shared-head confirmation
  // interstitial is an honest Conflict response, not an error page.
  if (
    event.detail.xhr &&
    (event.detail.xhr.status >= 500 || event.detail.xhr.status === 409)
  ) {
    event.detail.shouldSwap = true;
  }
});
