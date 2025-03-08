// Inadequate token validation
function validateTokenVulnerable(userToken, storedToken) {
    // Simple string comparison can be vulnerable to timing attacks
    if (userToken == storedToken) {  // Using == instead of === and no constant-time comparison
      return true;
    }
    return false;
  }
  