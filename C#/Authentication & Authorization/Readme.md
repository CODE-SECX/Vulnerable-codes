## Authorization Vulnerability Rules:

## Detection Rules Coverage:

1. **Missing Authorization Attribute** - Detects methods without `[Authorize]` or `[AllowAnonymous]`
2. **Hardcoded Authorization Bypass** - Finds hardcoded conditions that always grant access
3. **Insecure Direct Object Reference** - Identifies object access without authorization checks
4. **Missing CSRF Protection** - Detects POST/PUT/DELETE without anti-forgery tokens
5. **Weak Role-Based Authorization** - Finds overly permissive role assignments
6. **Elevation of Privilege Risk** - Detects privilege modification without proper checks
7. **Missing Input Validation** - Finds authorization checks without input validation
8. **Insecure AllowAnonymous Usage** - Identifies inappropriate anonymous access
9. **Authorization Based on Client Data** - Detects decisions based on client-controlled data
10. **Missing API Authorization** - Finds API endpoints without proper protection


## Session Management Vulnerability Rules:

### **High Severity Issues:**
1. **Insecure Session Cookie Configuration** - Missing HttpOnly, Secure, SameSite flags
2. **Session Fixation** - No session regeneration after authentication
3. **Insecure Session Storage** - Storing sensitive data directly in sessions
4. **Session Data Tampering** - Storing authorization data client-side
5. **Session Hijacking Risk** - Missing security headers and HTTPS enforcement
6. **Session Regeneration Missing** - No regeneration after privilege changes
7. **Session Storage in URL** - Exposing session IDs in URLs
8. **Weak Session Token Generation** - Using predictable token generation

### **Medium Severity Issues:**
9. **Missing Session Timeout** - No proper timeout configuration
10. **Session State Exposure** - Leaking session data in responses
11. **Insecure Session Validation** - Missing null/empty checks
12. **Concurrent Session Issues** - No concurrent session management
13. **Insecure Session Logout** - Incomplete session cleanup
14. **Session Cookie Domain Issues** - Improper domain configuration

## Key Vulnerability Patterns Detected:

- **Cookie Security**: Missing HttpOnly, Secure, SameSite attributes
- **Session Lifecycle**: Improper creation, validation, and destruction
- **Data Storage**: Sensitive information in session state
- **Authentication Flow**: Session fixation and regeneration issues
- **Authorization**: Client-side role/permission storage
- **Timeout Management**: Missing or excessive timeout values
- **Concurrent Access**: Multiple session handling problems
- **Token Generation**: Weak randomness in session identifiers

## Vulnerable Code Examples Include:

- Insecure session configuration in Startup.cs
- Session fixation during login process
- Storing passwords, SSNs, and tokens in sessions
- Exposing session data in API responses
- Missing session validation and null checks
- Storing roles and permissions in session
- Incomplete logout implementation
- Session IDs in URLs and query parameters
- Weak token generation using DateTime/GUID
- Missing session regeneration after password changes
- Custom session managers with security flaws
