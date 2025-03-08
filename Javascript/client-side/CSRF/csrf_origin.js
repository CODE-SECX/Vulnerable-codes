// No origin/referrer validation
function checkLoginVulnerable() {
    // No validation of origin or referrer
    if (document.cookie.includes('loggedIn=true')) {
      performSensitiveAction();
    }
  }
  