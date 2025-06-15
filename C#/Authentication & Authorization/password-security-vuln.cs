using System;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;

namespace VulnerablePasswordSecurity
{
    public class PasswordVulnerabilities
    {
        private readonly ILogger<PasswordVulnerabilities> _logger;

        // Rule 1: Hardcoded Passwords in Source Code
        private string dbPassword = "MySecretPassword123!";
        private string adminPassword = "admin123";
        private string connectionString = "Server=localhost;Database=MyDB;User=admin;Password=hardcodedpass;";
        private const string DefaultPassword = "password123";

        // Rule 2: Plain Text Password Storage
        public void StorePasswordPlainText(string username, string password)
        {
            var sql = $"INSERT INTO Users (Username, Password) VALUES ('{username}', '{password}')";
            // Execute SQL - storing password in plain text
            
            var user = new User();
            user.Password = password; // Direct assignment of plain text password
        }

        // Rule 3: Weak Password Hashing Algorithms
        public string HashPasswordWeakly(string password)
        {
            using (var md5 = MD5.Create())
            {
                var hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
                return Convert.ToBase64String(hash);
            }
        }

        public string HashWithSHA1(string password)
        {
            using (var sha1 = SHA1.Create())
            {
                var passwordBytes = Encoding.UTF8.GetBytes(password);
                var hash = sha1.ComputeHash(passwordBytes);
                return BitConverter.ToString(hash);
            }
        }

        // Rule 4: Insufficient PBKDF2 Iteration Count
        public byte[] WeakPBKDF2(string password, byte[] salt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000); // Too low iteration count
            return pbkdf2.GetBytes(32);
        }

        public byte[] AnotherWeakPBKDF2(string password, byte[] salt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 50000); // Still too low for current standards
            return pbkdf2.GetBytes(16);
        }

        // Rule 5: Password Transmission in Plain Text
        public async Task SendPasswordOverHttp(string username, string password)
        {
            using (var client = new HttpClient())
            {
                var loginData = new { Username = username, Password = password };
                await client.PostAsJsonAsync("http://api.example.com/login", loginData); // HTTP, not HTTPS
            }
        }

        public async Task SendPasswordInQuery(string password)
        {
            using (var client = new HttpClient())
            {
                await client.GetAsync($"https://api.example.com/auth?password={password}");
            }
        }

        // Rule 6: Password in URL Parameters
        public void LoginWithPasswordInUrl(string username, string password)
        {
            var loginUrl = $"https://example.com/login?username={username}&password={password}";
            // Process URL with password in query string
        }

        public Uri BuildAuthUrl(string pwd)
        {
            return new Uri($"https://api.example.com/auth?pwd={pwd}&action=login");
        }

        // Rule 7: Password in Log Files
        public void LogPasswordUnsafely(string username, string password, Exception ex)
        {
            _logger.LogError($"Login failed for user {username} with password {password}");
            Console.WriteLine($"Authentication error: {ex.Message}, Password: {password}");
            
            var debugInfo = $"User credentials - Username: {username}, Password: {password}";
            _logger.LogDebug(debugInfo);
        }

        // Rule 8: Weak Password Validation
        public bool ValidatePasswordWeakly(string password)
        {
            return password.Length >= 6; // Too short minimum length
        }

        public bool IsValidPassword(string password)
        {
            if (password.Length < 4) // Very weak validation
                return false;
            return true;
        }

        // Rule 9: Password Comparison Without Timing Attack Protection
        public bool AuthenticateUser(string providedPassword, string storedPassword)
        {
            return providedPassword == storedPassword; // Vulnerable to timing attacks
        }

        public bool ValidateHash(string password, string hash)
        {
            var computedHash = HashPasswordWeakly(password);
            return computedHash.Equals(hash); // Timing attack vulnerability
        }

        // Rule 10: Default or Well-Known Passwords
        private string systemPassword = "password";
        private string testPassword = "123456";
        private string devPassword = "admin";
        private const string GuestPassword = "guest";

        public void SetDefaultCredentials()
        {
            var adminUser = new User { Username = "admin", Password = "admin" };
            var testUser = new User { Username = "test", Password = "test" };
        }

        // Rule 11: Password Reset Token Predictability
        public string GenerateResetToken()
        {
            var random = new Random();
            return random.Next(100000, 999999).ToString(); // Predictable token
        }

        public string CreatePasswordResetToken()
        {
            return DateTime.Now.ToString("yyyyMMddHHmmss"); // Predictable based on time
        }

        public string GenerateToken()
        {
            return Guid.NewGuid().ToString(); // Not cryptographically secure for sensitive operations
        }

        // Rule 12: Password Recovery Information Exposure
        public class PasswordRecovery
        {
            public string PasswordHint { get; set; } = "Your pet's name";
            public string SecurityQuestion { get; set; } = "What is your mother's maiden name?";
            public string SecurityAnswer { get; set; }
            
            public bool RecoverPassword(string hint, string answer)
            {
                // Exposing password recovery information
                return SecurityAnswer.ToLower() == answer.ToLower();
            }
        }

        // Rule 13: Insufficient Password Change Validation
        public async Task<bool> ChangePassword(int userId, string newPassword)
        {
            // No current password validation!
            var hashedPassword = HashPasswordWeakly(newPassword);
            return await UpdatePasswordInDatabase(userId, hashedPassword);
        }

        public void UpdatePassword(string newPassword)
        {
            // Missing current password verification
            var user = GetCurrentUser();
            user.Password = newPassword;
            SaveUser(user);
        }

        // Rule 14: Password Enumeration Vulnerability
        [HttpPost]
        public IActionResult Login(string username, string password)
        {
            var user = FindUser(username);
            if (user == null)
                return BadRequest("User not found"); // Reveals username validity
            
            if (!ValidatePassword(user, password))
                return BadRequest("Invalid password"); // Different message reveals user exists
            
            return Ok("Login successful");
        }

        // Rule 15: Missing Password Complexity Requirements
        public bool ValidatePassword(string password)
        {
            // Only checks length, missing complexity requirements
            return password.Length >= 8;
        }

        public bool IsPasswordValid(string pwd)
        {
            // No complexity validation at all
            return !string.IsNullOrEmpty(pwd);
        }

        // Rule 16: Password Brute Force Protection Missing
        [HttpPost]
        public async Task<IActionResult> Authenticate(string username, string password)
        {
            // No rate limiting or attempt tracking
            var user = await FindUserAsync(username);
            if (user != null && ValidatePassword(user, password))
            {
                return Ok("Authenticated");
            }
            return Unauthorized("Invalid credentials");
        }

        public bool Login(string username, string password)
        {
            // No brute force protection
            return ValidateCredentials(username, password);
        }

        // Rule 17: Session Fixation After Password Change
        public async Task<bool> ChangePasswordEndpoint(string newPassword)
        {
            var userId = GetCurrentUserId();
            await UpdatePasswordAsync(userId, newPassword);
            // Missing: session invalidation, force re-authentication
            return true;
        }

        // Rule 18: Insecure Password Recovery Flow
        public async Task<bool> ForgotPassword(string email)
        {
            var user = await FindUserByEmailAsync(email);
            if (user != null)
            {
                // Insecure: no token, no expiration
                await SendPasswordResetEmailAsync(email, user.Id.ToString());
            }
            return true;
        }

        public bool ResetPassword(string userId, string newPassword)
        {
            // No token validation, no expiration check
            return UpdateUserPassword(int.Parse(userId), newPassword);
        }

        // Rule 19: Password History Not Enforced
        public async Task<bool> UpdatePassword(int userId, string newPassword)
        {
            // No password history check
            var hashedPassword = HashPassword(newPassword);
            return await SaveNewPasswordAsync(userId, hashedPassword);
        }

        // Rule 20: Temporary Password Not Enforced for Change
        public IActionResult LoginWithT
