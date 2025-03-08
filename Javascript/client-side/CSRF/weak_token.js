// Weak CSRF token generation
function generateWeakCSRFToken() {
    return Math.random().toString(36).substring(2);  // Weak random generation
  }
  