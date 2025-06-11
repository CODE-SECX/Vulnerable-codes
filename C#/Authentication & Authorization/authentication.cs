using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using System.Security.Cryptography;
using System.Text;

namespace ComprehensiveVulnerableAuthExamples
{
    // VULNERABLE: Missing Authorization Attribute
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetSensitiveUserData()  // No [Authorize] attribute
        {
            return Ok("Sensitive user data");
        }

        [HttpDelete]  // Missing CSRF protection too
        public IActionResult DeleteUser()  // No [Authorize] attribute
        {
            return Ok("User deleted");
        }
    }

    // VULNERABLE: Hardcoded Credentials
    public class DatabaseService
    {
        // VULNERABLE: Hardcoded database credentials
        private readonly string connectionString = "Server=localhost;Database=MyApp;User=sa;Password=MyP@ssw0rd123;";
        private readonly string apiKey = "sk-1234567890abcdef";  // Hardcoded API key
        private readonly string jwtSecret = "my-super-secret-key";  // Hardcoded JWT secret
        
        public void Connect()
        {
            // Connection logic with hardcoded credentials
        }
    }

    // VULNERABLE: Default Credentials Usage
    public class DefaultCredentialsService
    {
        public bool ValidateUser(string username, string password)
        {
            // VULNERABLE: Default admin credentials
            if (username == "admin" && password == "admin")
                return true;
            
            // VULNERABLE: Default test credentials
            if (username == "test" && password == "password")
                return true;
                
            // VULNERABLE: Default guest credentials
            if (username == "guest" && password == "guest")
                return true;
                
            return false;
        }
    }

    // VULNERABLE: Weak Password Policy
    public class IdentityConfiguration
    {
        public void ConfigureIdentity(IdentityOptions options)
        {
            // VULNERABLE: Weak password requirements
            options.Password.RequiredLength = 4;           // Too short
            options.Password.RequireDigit = false;         // No digit required
            options.Password.RequireUppercase = false;     // No uppercase required
            options.Password.RequireLowercase = false;     // No lowercase required
            options.Password.RequireNonAlphanumeric = false; // No special chars required
            
            // VULNERABLE: Weak lockout policy
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);  // Too short
            options.Lockout.MaxFailedAccessAttempts = 20;  // Too many attempts allowed
            options.Lockout.AllowedForNewUsers = false;    // Lockout disabled for new users
        }
    }

    // VULNERABLE: JWT Token Vulnerabilities
    public class JwtService
    {
        // VULNERABLE: Weak JWT secret key (too short)
        private readonly string secretKey = "weak";
        
        public string GenerateToken(string username)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // VULNERABLE: Weak signing key
            var key = Encoding.ASCII.GetBytes(secretKey);
            
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[] { new Claim("username", username) }),
                // VULNERABLE: Token expires in 1 year
                Expires = DateTime.UtcNow.AddYears(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        
        public void ConfigureJwtValidation()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = false,  // VULNERABLE: Signature not validated
                ValidateLifetime = false,          // VULNERABLE: Expiration not checked
                ValidAlgorithms = null,            // VULNERABLE: Algorithm confusion possible
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("short"))  // Weak key
            };
        }
    }

    // VULNERABLE: Session Fixation
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpPost]  // Missing CSRF protection
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ValidateCredentials(model.Username, model.Password))
            {
                var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] 
                {
                    new Claim(ClaimTypes.Name, model.Username)
                }, "cookie"));
                
                // VULNERABLE: No session regeneration after authentication
                await HttpContext.SignInAsync(principal);
                // Should call: HttpContext.Session.Clear(); or similar
                
                return Ok("Logged in successfully");
            }
            
            // VULNERABLE: Information disclosure - specific error message
            return BadRequest("Invalid username - user not found");
        }
        
        private bool ValidateCredentials(string username, string password)
        {
            return true; // Simplified for example
        }
    }

    // VULNERABLE: Authentication State Manipulation
    public class SessionController : Controller
    {
        public IActionResult Login(string username, string password)
        {
            // VULNERABLE: Direct session manipulation without proper validation
            Session["IsAuthenticated"] = true;
            Session["UserId"] = username;
            Session["UserRole"] = "admin";  // Direct role assignment
            
            // VULNERABLE: Direct user principal manipulation
            HttpContext.User = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, username),
                new Claim(ClaimTypes.Role, "admin")
            }));
            
            return RedirectToAction("Dashboard");
        }
    }

    // VULNERABLE: Missing Brute Force Protection
    [ApiController]
    public class LoginController : ControllerBase
    {
        // VULNERABLE: No rate limiting, no account lockout
        [HttpPost]
        public IActionResult Login(LoginModel model)
        {
            // No protection against brute force attacks
            if (ValidateUser(model.Username, model.Password))
            {
                return Ok("Success");
            }
            return Unauthorized("Failed");
        }
        
        // VULNERABLE: Password reset without rate limiting
        [HttpPost]
        public IActionResult ResetPassword(string email, string newPassword)
        {
            // VULNERABLE: No token validation, no current password check
            ChangeUserPassword(email, newPassword);
            return Ok("Password reset");
        }
        
        private bool ValidateUser(string username, string password) => true;
        private void ChangeUserPassword(string email, string password) { }
    }

    // VULNERABLE: Weak Encryption and Password Storage
    public class CryptoService
    {
        // VULNERABLE: Using MD5 for password hashing
        public string HashPassword(string password)
        {
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hash);
            }
        }
        
        // VULNERABLE: Using SHA1
        public string CreateSignature(string data)
        {
            using (var sha1 = SHA1.Create())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Convert.ToBase64String(hash);
            }
        }
        
        // VULNERABLE: Using DES encryption
        public byte[] EncryptData(byte[] data, byte[] key)
        {
            using (var des = new DESCryptoServiceProvider())
            {
                return des.CreateEncryptor(key, key).TransformFinalBlock(data, 0, data.Length);
            }
        }
    }

    // VULNERABLE: Plain Text Password Storage
    public class UserRepository
    {
        public void CreateUser(string username, string password, string email)
        {
            var user = new User
            {
                Username = username,
                Password = password,  // VULNERABLE: Plain text password storage
                Email = email
            };
            
            // Save to database
        }
        
        public bool ValidateLogin(string username, string password)
        {
            var user = GetUser(username);
            // VULNERABLE: Plain text password comparison
            return user?.Password == password;
        }
        
        private User GetUser(string username) => new User();
    }

    // VULNERABLE: Insecure Session Configuration
    public class SessionConfiguration
    {
        public void ConfigureSession(SessionOptions options)
        {
            // VULNERABLE: Insecure cookie settings
            options.Cookie.HttpOnly = false;      // Vulnerable to XSS
            options.Cookie.Secure = false;        // Can be sent over HTTP
            options.Cookie.SameSite = SameSiteMode.None;  // CSRF vulnerable
        }
        
        public void ConfigureCookies(CookiePolicyOptions options)
        {
            // VULNERABLE: Insecure cookie policy
            options.Secure = CookieSecurePolicy.Never;
        }
    }

    // VULNERABLE: Insecure API Key Management
    [ApiController]
    public class ApiController : ControllerBase
    {
        // VULNERABLE: Hardcoded API key comparison
        private readonly string validApiKey = "sk-1234567890abcdefghijklmnop";
        
        [HttpGet]
        public IActionResult GetData()
        {
            var apiKey = Request.Headers["X-API-Key"].FirstOrDefault();
            
            // VULNERABLE: Direct string comparison of API key
            if (apiKey == validApiKey)
            {
                return Ok("Sensitive data");
            }
            
            return Unauthorized();
        }
        
        [HttpPost]
        public IActionResult ValidateApiKey(string providedKey)
        {
            // VULNERABLE: Hardcoded API key in conditional
            if (providedKey == "my-secret-api-key-12345")
            {
                return Ok("Valid");
            }
            return Unauthorized();
        }
    }

    // VULNERABLE: Missing Multi-Factor Authentication
    [ApiController]
    public class AdminController : ControllerBase
    {
        // VULNERABLE: Sensitive operation without MFA
        [HttpDelete]
        [Authorize]  // Only basic auth, no MFA required
        public IActionResult DeleteAllUsers()
        {
            // Critical operation without MFA
            return Ok("All users deleted");
        }
        
        // VULNERABLE: Financial operation without MFA
        [HttpPost]
        [Authorize]
        public IActionResult TransferMoney(decimal amount, string toAccount)
        {
            // High-value operation without MFA
            return Ok($"Transferred ${amount} to {toAccount}");
        }
        
        // VULNERABLE: Admin operation without MFA
        [HttpPost]
        [Authorize]
        public IActionResult AdminOperation()
        {
            return Ok("Admin operation completed");
        }
    }

    // VULNERABLE: Information Disclosure in Authentication
    public class AuthenticationService
    {
        public string ValidateUser(string username, string password)
        {
            var user = GetUser(username);
            if (user == null)
            {
                // VULNERABLE: Specific error reveals if username exists
                throw new Exception("Invalid username - user not found in system");
            }
            
            if (user.IsLocked)
            {
                // VULNERABLE: Reveals account status
                throw new Exception("Account is locked due to multiple failed attempts");
            }
            
            if (user.PasswordExpired)
            {
                // VULNERABLE: Reveals password status
                throw new Exception("Password has expired, please reset");
            }
            
            if (!ValidatePassword(password, user.PasswordHash))
            {
                // VULNERABLE: Different timing and error for wrong password
                Thread.Sleep(100); // Artificial delay that reveals password was wrong
                throw new Exception("Invalid password provided");
            }
            
            return "Login successful";
        }
        
        private User GetUser(string username) => new User();
        private bool ValidatePassword(string password, string hash) => true;
    }

    // VULNERABLE: Timing Attack Vulnerabilities
    public class TimingAttackService
    {
        public bool ValidateApiKey(string providedKey)
        {
            string validKey = "sk-1234567890abcdefghijklmnop";
            
            // VULNERABLE: Early return allows timing attacks
            for (int i = 0; i < Math.Min(providedKey.Length, validKey.Length); i++)
            {
                if (providedKey[i] != validKey[i])
                {
                    return false; // Early return reveals position of difference
                }
            }
            
            return providedKey.Length == validKey.Length;
        }
    }

    // VULNERABLE: Race Condition in Authentication
    public class RaceConditionAuthService
    {
        private static int loginAttempts = 0;
        private static DateTime lastAttempt = DateTime.MinValue;
        
        public bool Login(string username, string password)
        {
            // VULNERABLE: Race condition in attempt counting
            loginAttempts++;
            lastAttempt = DateTime.UtcNow;
            
            if (loginAttempts > 3)
            {
                if (DateTime.UtcNow.Subtract(lastAttempt).TotalMinutes < 5)
                {
                    return false; // Rate limited
                }
                loginAttempts = 0; // Reset without proper synchronization
            }
            
            return ValidateCredentials(username, password);
        }
        
        private bool ValidateCredentials(string username, string password) => true;
    }

    // VULNERABLE: Insufficient Authentication for Password Change
    public class PasswordChangeController : ControllerBase
    {
        [HttpPost]
        public IActionResult ChangePassword(string username, string newPassword)
        {
            // VULNERABLE: No current password verification
            // VULNERABLE: No authentication check
            UpdateUserPassword(username, newPassword);
            return Ok("Password changed successfully");
        }
        
        [HttpPost]
        public IActionResult ResetPassword(string email, string newPassword)
        {
            // VULNERABLE: No token validation for password reset
            var user = GetUserByEmail(email);
            if (user != null)
            {
                UpdateUserPassword(user.Username, newPassword);
                return Ok("Password reset successfully");
            }
            return BadRequest("User not found");
        }
        
        private void UpdateUserPassword(string username, string password) { }
        private User GetUserByEmail(string email) => new User();
    }

    // VULNERABLE: Insecure Direct Object References
    [ApiController]
    [Authorize]
    public class UserDataController : ControllerBase
    {
        [HttpGet("{userId}")]
        public IActionResult GetUserProfile(int userId)
        {
            // VULNERABLE: No authorization check if user can access this specific user's data
            var userProfile = GetUserProfileById(userId);
            return Ok(userProfile);
        }
        
        [HttpPut("{userId}")]
        public IActionResult UpdateUserProfile(int userId, UserProfile profile)
        {
            // VULNERABLE: User can potentially update any user's profile
            UpdateUserProfileById(userId, profile);
            return Ok("Profile updated");
        }
        
        private UserProfile GetUserProfileById(int userId) => new UserProfile();
        private void UpdateUserProfileById(int userId, UserProfile profile) { }
    }

    // VULNERABLE: Weak Random Token Generation
    public class TokenService
    {
        private static Random random = new Random();
        
        public string GenerateResetToken()
        {
            // VULNERABLE: Using weak Random instead of cryptographically secure random
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(chars, 10)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
        
        public string GenerateSessionId()
        {
            // VULNERABLE: Predictable session ID
            return DateTime.Now.Ticks.ToString();
        }
    }

    // VULNERABLE: XML External Entity (XXE) in Authentication
    public class XmlAuthController : ControllerBase
    {
        [HttpPost]
        public IActionResult ProcessXmlAuth([FromBody] string xmlData)
        {
            // VULNERABLE: XML processing without disabling external entities
            var doc = new XmlDocument();
            doc.LoadXml(xmlData); // Vulnerable to XXE attacks
            
            var username = doc.SelectSingleNode("//username")?.InnerText;
            var password = doc.SelectSingleNode("//password")?.InnerText;
            
            if (ValidateUser(username, password))
            {
                return Ok("Authenticated");
            }
            return Unauthorized();
        }
        
        private bool ValidateUser(string username, string password) => true;
    }

    // VULNERABLE: SQL Injection in Authentication
    public class SqlAuthService
    {
        private readonly string connectionString;
        
        public bool AuthenticateUser(string username, string password)
        {
            // VULNERABLE: SQL injection in authentication query
            string query = $"SELECT COUNT(*) FROM Users WHERE Username = '{username}' AND Password = '{password}'";
            
            using (var connection = new SqlConnection(connectionString))
            {
                var command = new SqlCommand(query, connection);
                connection.Open();
                int count = (int)command.ExecuteScalar();
                return count > 0;
            }
        }
        
        public User GetUserByCredentials(string username, string password)
        {
            // VULNERABLE: Another SQL injection vector
            string query = "SELECT * FROM Users WHERE Username = '" + username + "' AND Password = '" + password + "'";
            
            // Execute query and return user
            return new User();
        }
    }

    // VULNERABLE: Insecure Deserialization in Authentication
    public class DeserializationAuthController : ControllerBase
    {
        [HttpPost]
        public IActionResult AuthenticateWithToken([FromBody] string serializedToken)
        {
            try
            {
                // VULNERABLE: Deserializing untrusted data
                var formatter = new BinaryFormatter();
                using (var stream = new MemoryStream(Convert.FromBase64String(serializedToken)))
                {
                    var authToken = (AuthToken)formatter.Deserialize(stream);
                    
                    if (authToken.IsValid())
                    {
                        return Ok("Authenticated");
                    }
                }
            }
            catch (Exception ex)
            {
                // VULNERABLE: Error message disclosure
                return BadRequest($"Deserialization failed: {ex.Message}");
            }
            
            return Unauthorized();
        }
    }

    // VULNERABLE: Missing Input Validation
    public class ValidationController : ControllerBase
    {
        [HttpPost]
        public IActionResult Register(RegistrationModel model)
        {
            // VULNERABLE: No input validation
            // VULNERABLE: No password strength checking
            // VULNERABLE: No email format validation
            
            CreateUser(model.Username, model.Password, model.Email);
            return Ok("User registered");
        }
        
        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            // VULNERABLE: No input sanitization
            // VULNERABLE: No length limits
            
            if (username.Length > 1000 || password.Length > 1000)
            {
                // Potential DoS through large inputs
            }
            
            return Ok("Processed");
        }
        
        private void CreateUser(string username, string password, string email) { }
    }

    // Supporting Models and Classes
    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }
    
    public class RegistrationModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
    }
    
    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string PasswordHash { get; set; }
        public string Email { get; set; }
        public bool IsLocked { get; set; }
        public bool PasswordExpired { get; set; }
    }
    
    public class UserProfile
    {
        public string Name { get; set; }
        public string Email { get; set; }
    }
    
    public class AuthToken
    {
        public string Token { get; set; }
        public DateTime Expiry { get; set; }
        
        public bool IsValid() => DateTime.UtcNow < Expiry;
    }
}

// VULNERABLE: Global Authentication Bypass in Development
#if DEBUG
public class DebugAuthenticationMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        // VULNERABLE: Bypass authentication in debug mode
        if (context.Request.Headers.ContainsKey("X-Debug-Auth"))
        {
            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, "debuguser"),
                new Claim(ClaimTypes.Role, "admin")
            }, "debug");
            
            context.User = new ClaimsPrincipal(identity);
        }
        
        await next(context);
    }
}
#endif
