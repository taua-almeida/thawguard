const recoveryFragment = window.location.hash;
history.replaceState(null, "", "/password-recovery");

const form = document.getElementById("password-recovery-form");
const tokenField = document.getElementById("password-recovery-token");
const unavailable = document.getElementById("password-recovery-unavailable");
const tokenMatch = recoveryFragment.match(/^#token=([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/);

if (tokenMatch && form && tokenField) {
  tokenField.value = tokenMatch[1];
  form.hidden = false;
} else if (unavailable) {
  unavailable.hidden = false;
}
