const navigationLink = document.querySelector("#oidc-provider-navigation a");

if (navigationLink instanceof HTMLAnchorElement) {
  window.location.replace(navigationLink.href);
}
