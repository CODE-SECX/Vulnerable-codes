// Missing security flags in session cookies
function setSessionCookieVulnerable(sessionId) {
    document.cookie = `sessionId=${sessionId}`;  // Missing secure, httpOnly, sameSite flags
  }
  