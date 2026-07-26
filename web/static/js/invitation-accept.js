// Copy the fragment and scrub it from the address bar before touching the DOM,
// so the bearer never survives in history or gets picked up by anything else.
const invitationFragment = window.location.hash;
history.replaceState(null, "", "/invitations/accept");

const form = document.getElementById("invitation-accept-form");
const tokenField = document.getElementById("invitation-accept-token");
const unavailable = document.getElementById("invitation-accept-unavailable");
// Exactly one canonical base64url encoding of 32 bytes: 43 characters whose
// final character has its low bits zero.
const tokenMatch = invitationFragment.match(/^#token=([A-Za-z0-9_-]{42}[AEIMQUYcgkosw048])$/);

if (tokenMatch && form && tokenField) {
  tokenField.value = tokenMatch[1];
  form.hidden = false;
} else if (unavailable) {
  unavailable.hidden = false;
}
