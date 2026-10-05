/*
  app.js
  ======
  Small progressive enhancement for SecureVault.

  Any <form data-confirm="message"> asks for confirmation before submitting.
  Used for the Delete buttons on the dashboard.

  Why a separate file? Our Content-Security-Policy ("default-src 'self'")
  blocks inline scripts and onclick="" attributes, which is a strong defence
  against XSS. Scripts must be loaded from our own /static folder instead.

  Loaded with "defer", so the HTML is fully parsed before this runs.
  If JavaScript is disabled, the forms still work; they just skip the prompt.
*/

// Find every form that asks for confirmation.
const formsNeedingConfirmation = document.querySelectorAll("form[data-confirm]");

formsNeedingConfirmation.forEach((form) => {
  // Run this check each time the form is about to be submitted.
  form.addEventListener("submit", (event) => {
    const message = form.dataset.confirm; // reads data-confirm="..."
    if (!window.confirm(message)) {
      event.preventDefault(); // user clicked Cancel: stop the submission
    }
  });
});