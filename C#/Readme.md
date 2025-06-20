# 🛎️ Authentication Vulnerability Rules:

### Coverage Areas:

✅ **Authorization**: Missing attributes, bypasses, IDOR  
✅ **Credentials**: Hardcoded, default, weak storage  
✅ **JWT**: Weak keys, algorithm confusion, expiration  
✅ **Session**: Fixation, insecure cookies  
✅ **Cryptography**: Weak algorithms, poor randomness  
✅ **Input Validation**: Missing validation, SQL injection  
✅ **Brute Force**: Rate limiting, account lockout  
✅ **Information Disclosure**: Error messages  
✅ **CSRF**: Missing protection  
✅ **MFA**: Missing requirements  
✅ **Deserialization**: Unsafe deserialization  
✅ **Timing Attacks**: Vulnerable comparisons  



# 🛎️ Authorization Vulnerability Rules:

### Detection Rules Coverage:

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


# 🛎️ Session Management Vulnerability Rules:

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

# 🛎️ Cryptographic Vulnerabilities


## Weak Cryptography Rules:

1. **MD5 Hash Algorithm**
2. **SHA-1 Hash Algorithm**
3. **DES Encryption**
4. **3DES / TripleDES**
5. **RC2 Encryption**
6. **Weak RSA Key Sizes (< 2048 bits)**
7. **Weak DSA Key Sizes** 
8. **Insecure Random Generation (System.Random for crypto)**
9. **Weak AES Key Sizes (< 256 bits)**
10. **ECB Cipher Mode**
11. **Hardcoded Cryptographic Keys or Secrets**
12. **Weak PBKDF2 Iteration Count**
13. **Insecure SSL/TLS Protocols (e.g., SSL 2.0, 3.0, TLS 1.0, 1.1)**
14. **Use of Obsolete or Broken Algorithms (e.g., HMACMD5)** 
15. **Custom or Homegrown Cryptographic Implementations** 
16. **Static IVs or Predictable IVs for Symmetric Encryption** 
17. **Insufficient Key Derivation Practices (e.g., no salt)** 
18. **Use of SHA-2 Without HMAC for Authentication** 
19. **Use of Deprecated .NET APIs (e.g., CryptoServiceProvider)** 
20. **Lack of Authenticated Encryption (e.g., AES without GCM or HMAC)** 



## Key Management Vulnerability Rules:

1. **Hardcoded Private Keys in Code** - Detects embedded certificates and private keys
2. **Hardcoded API Keys and Secrets** - Finds API keys, tokens, and secrets in source code
3. **Insecure Key Storage in Memory** - Identifies keys stored in regular strings/arrays
4. **Key Derivation Without Salt** - Detects PBKDF2/key derivation without proper salt
5. **Insecure Key Exchange Implementation** - Finds weak key exchange implementations
6. **Missing Key Rotation Implementation** - Identifies static/const key usage
7. **Insecure Key Transmission** - Detects keys sent over potentially insecure channels
8. **Weak Key Generation Entropy** - Finds use of System.Random for cryptographic keys
9. **Insecure Key Backup and Recovery** - Detects plaintext key backup to files
10. **Missing Key Validation** - Identifies crypto operations without key validation
11. **Insecure Key Derivation Function Usage** - Finds deprecated key derivation methods
12. **Improper Key Lifecycle Management** - Detects missing 'using' statements for crypto objects
13. **Certificate Validation Bypass** - Identifies bypassed certificate validation
14. **Key Material in Exception Messages** - Finds keys exposed in error messages/logs
15. **Insecure Key Agreement Protocol** - Detects unauthenticated key agreement implementations

# 🛎️ Path Traversal Vulnerabilities

1. **File.ReadAllText** - Detects reading files with user input
2. **File.ReadAllBytes** - Detects reading file bytes with user input  
3. **File.WriteAllText** - Detects writing files with user input (Critical severity)
4. **FileStream Constructor** - Detects FileStream creation with user input
5. **Directory.GetFiles** - Detects directory listing with user input
6. **Path.Combine** - Detects path combination with user input
7. **File.Open** - Detects file opening with user input
8. **File.Delete** - Detects file deletion with user input (Critical severity)
9. **StreamReader Constructor** - Detects StreamReader creation with user input
10. **DirectoryInfo Constructor** - Detects DirectoryInfo creation with user input
11. **FileInfo Constructor** - Detects FileInfo creation with user input

# 🛎️ Deserialization Vulnerabilities

1. **Critical Severity:**
   - `BinaryFormatter` - Extremely dangerous, can execute arbitrary code
   - `SoapFormatter` - Similar risks to BinaryFormatter
   - `LosFormatter` - Used in ASP.NET, highly vulnerable
   - `ObjectStateFormatter` - Another ASP.NET formatter with similar risks

2. **High Severity:**
   - `NetDataContractSerializer` - Can be exploited with crafted payloads
   - `Newtonsoft.Json` with `TypeNameHandling` - Allows type confusion attacks

3. **Medium Severity:**
   - `JavaScriptSerializer` - Legacy serializer with potential issues
   - `XmlSerializer` - Can be vulnerable to XXE and other XML attacks
   - Unsafe `JsonConvert.DeserializeObject` calls
   - `MessagePack` deserialization

# 🛎️ XML Vulnerabilities

1. **XXE (XML External Entity) Attacks** - The most critical XML vulnerability
2. **XML Bomb/Billion Laughs Attacks** - DoS through exponential entity expansion
3. **Unsafe XML Deserialization** - Potential for various injection attacks
4. **XSLT Processing Vulnerabilities** - XXE through stylesheets
5. **XML Schema Validation Issues** - XXE through schema imports

# 🛎️ Configuration & Environment

## Information Disclosure

1. **Hardcoded Credentials** - Detects passwords, API keys, tokens, and connection strings hardcoded in source code
2. **Detailed Exception Exposure** - Finds cases where exception details are exposed to users
3. **Debug Information in Production** - Identifies debug statements containing sensitive data
4. **SQL Connection String Exposure** - Detects connection strings with embedded credentials
5. **Sensitive Data in Logs** - Finds logging statements that include sensitive information
6. **Configuration Secrets in Code** - Detects hardcoded configuration values with sensitive data
7. **Detailed Error Messages in APIs** - Identifies API responses exposing internal error details
8. **Directory/File Path Exposure** - Detects code that might expose file system information

## Security Misconfiguration :

1. **Debug Mode in Production** - Detects debug settings enabled in production environments
2. **Insecure SSL/TLS Configuration** - Finds weak TLS settings and disabled certificate validation
3. **Insecure HTTP Headers** - Identifies missing or misconfigured security headers
4. **Weak Authentication Configuration** - Detects weak password policies and authentication settings
5. **Insecure Session Configuration** - Finds insecure session and cookie settings
6. **Insecure CORS Configuration** - Identifies overly permissive CORS policies
7. **Insecure Database Connection** - Detects unencrypted or insecure database connections
8. **Insecure Logging Configuration** - Finds logging configs that expose sensitive data
9. **Insecure API Configuration** - Identifies APIs with missing authentication/authorization
10. **Insecure Cryptographic Configuration** - Detects weak crypto algorithms and settings
11. **Insecure ViewState Configuration** - Finds Web Forms ViewState security issues
12. **Insecure File Upload Configuration** - Identifies dangerous file upload settings

## Logging & Monitoring:

1. **Sensitive Data in Log Messages** - Detects passwords, tokens, SSNs, credit cards, etc. being logged
2. **Exception Stack Trace Logging** - Catches full exception details that may expose system info
3. **SQL Query Logging** - Identifies SQL queries with sensitive data being logged
4. **Request/Response Body Logging** - Detects HTTP content logging that may contain sensitive data
5. **File Path Disclosure** - Catches file paths that might expose directory structure
6. **Connection String Logging** - Critical rule to detect database credentials in logs
7. **Debug Information in Production** - Identifies debug logs that might expose sensitive data
8. **Authentication Token Logging** - Detects JWT, API keys, bearer tokens in logs
9. **Session Data Logging** - Catches session information being logged
10. **Unstructured Sensitive Data Logging** - Detects dangerous string interpolation in logs
