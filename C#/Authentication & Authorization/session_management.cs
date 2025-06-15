using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Threading.Tasks;
using System.Security.Claims;

namespace VulnerableSessionApp
{
    // VULNERABILITY 1: Insecure Session Configuration in Startup.cs
    public class VulnerableStartup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // Missing HttpOnly, Secure, and SameSite configuration
            services.AddSession();
            
            // Another vulnerable configuration
            services.Configure<SessionOptions>(options =>
            {
                options.IdleTimeout = TimeSpan.FromHours(24); // Too long timeout
                // Missing security settings
            });
        }
    }

    [Route("api/[controller]")]
    public class VulnerableSessionController : ControllerBase
    {
        // VULNERABILITY 2: Session Fixation - No session regeneration after login
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ValidateUser(model.Username, model.Password))
            {
                var claims = new[] { new Claim(ClaimTypes.Name, model.Username) };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                
                // Missing session regeneration - vulnerable to session fixation
                await HttpContext.SignInAsync(principal);
                
                return Ok("Login successful");
            }
            return Unauthorized();
        }

        // VULNERABILITY 3: Insecure Session Storage - Storing sensitive data
        [HttpPost("store-sensitive-data")]
        public IActionResult StoreSensitiveData()
        {
            // Storing sensitive data directly in session
            HttpContext.Session.SetString("password", "userPassword123");
            HttpContext.Session.SetString("ssn", "123-45-6789");
            HttpContext.Session.SetString("credit_card", "4111-1111-1111-1111");
            HttpContext.Session.SetString("api_token", "secret_api_token_123");
            
            return Ok("Sensitive data stored in session");
        }

        // VULNERABILITY 4: Session State Exposure
        [HttpGet("debug-session")]
        public IActionResult DebugSession()
        {
            // Exposing entire session state in response
            var sessionData = new
            {
                SessionId = HttpContext.Session.Id,
                SessionData = HttpContext.Session,
                AllKeys = HttpContext.Session.Keys
            };
            
            return Ok(sessionData);
        }

        // VULNERABILITY 5: Missing Session Validation
        [HttpGet("get-user-data")]
        public IActionResult GetUserData()
        {
            // No validation of session data
            var userId = HttpContext.Session.GetString("UserId");
            var userRole = HttpContext.Session.GetString("UserRole");
            
            // Direct use without null checking
            return Ok($"User {userId} has role {userRole}");
        }

        // VULNERABILITY 6: Session Data Tampering - Storing authorization data
        [HttpPost("set-admin")]
        public IActionResult SetAdmin()
        {
            // Storing role information in session (client-side)
            HttpContext.Session.SetString("role", "admin");
            HttpContext.Session.SetString("permission", "full_access");
            HttpContext.Session.SetString("admin_level", "super_admin");
            
            return Ok("Admin privileges set");
        }

        // VULNERABILITY 7: Incomplete Logout
        [HttpPost("logout")]
        public IActionResult Logout()
        {
            // Missing session cleanup
            return RedirectToAction("Login");
        }

        // VULNERABILITY 8: Session in URL
        [HttpGet("dashboard")]
        public IActionResult Dashboard(string sessionId)
        {
            // Session ID exposed in URL
            return RedirectToAction("Home", new { sessionId = HttpContext.Session.Id });
        }

        // VULNERABILITY 9: Weak Session Token Generation
        [HttpPost("generate-session-token")]
        public IActionResult GenerateSessionToken()
        {
            // Weak token generation
            var weakToken1 = Guid.NewGuid().ToString();
            var weakToken2 = DateTime.Now.Ticks.ToString();
            var weakToken3 = Environment.TickCount.ToString();
            
            var random = new Random();
            var weakToken4 = random.Next().ToString();
            
            HttpContext.Session.SetString("session_token", weakToken1);
            
            return Ok($"Session token: {weakToken1}");
        }

        // VULNERABILITY 10: Missing Session Regeneration on Privilege Change
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordModel model)
        {
            if (await ChangeUserPassword(model))
            {
                // Missing session regeneration after password change
                return Ok("Password changed successfully");
            }
            return BadRequest("Password change failed");
        }

        // VULNERABILITY 11: Concurrent Session Issues
        [HttpPost("force-login")]
        public async Task<IActionResult> ForceLogin(LoginModel model)
        {
            if (ValidateUser(model.Username, model.Password))
            {
                // No check for existing sessions
                var claims = new[] { new Claim(ClaimTypes.Name, model.Username) };
                var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);
                
                await HttpContext.SignInAsync(principal);
                
                return Ok("Login successful - multiple sessions allowed");
            }
            return Unauthorized();
        }

        // VULNERABILITY 12: Session Timeout Issues
        [HttpGet("extend-session")]
        public IActionResult ExtendSession()
        {
            // Arbitrary session extension without proper validation
            HttpContext.Session.SetString("last_activity", DateTime.Now.AddHours(10).ToString());
            
            return Ok("Session extended indefinitely");
        }

        // VULNERABILITY 13: Insecure Session Cookie Domain
        public void ConfigureInsecureCookies(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.Domain = "*.example.com"; // Wildcard domain
                options.Cookie.Path = "/"; // Too broad path
                // Missing security flags
            });
        }

        // VULNERABILITY 14: Session Data in Logs
        [HttpPost("log-user-activity")]
        public IActionResult LogUserActivity()
        {
            var userId = HttpContext.Session.GetString("UserId");
            var sessionData = HttpContext.Session.GetString("UserData");
            
            // Logging sensitive session data
            Console.WriteLine($"User activity: {userId}, Session: {sessionData}");
            
            return Ok("Activity logged");
        }

        // VULNERABILITY 15: Race Condition in Session Access
        [HttpPost("update-session-data")]
        public async Task<IActionResult> UpdateSessionData()
        {
            // No synchronization for concurrent session access
            var counter = HttpContext.Session.GetInt32("counter") ?? 0;
            
            // Simulate processing delay
            await Task.Delay(100);
            
            counter++;
            HttpContext.Session.SetInt32("counter", counter);
            
            return Ok($"Counter: {counter}");
        }

        // Helper methods
        private bool ValidateUser(string username, string password)
        {
            // Simplified validation
            return username == "admin" && password == "password";
        }

        private async Task<bool> ChangeUserPassword(ChangePasswordModel model)
        {
            // Simulate password change
            await Task.Delay(100);
            return true;
        }
    }

    // VULNERABILITY 16: Insecure Session State Configuration (web.config style)
    public class WebConfigVulnerabilities
    {
        // This would be in web.config for .NET Framework apps
        /*
        <sessionState 
            mode="StateServer" 
            stateConnectionString="tcpip=127.0.0.1:42424" 
            cookieTimeout="60" 
            regenerateExpiredSessionId="false" 
            cookieless="false" 
            httpOnlyCookies="false" 
            requireSSL="false" 
            sameSite="None" />
        */
    }

    // Models
    public class LoginModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class ChangePasswordModel
    {
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
    }

    // VULNERABILITY 17: Custom Session Manager with Security Issues
    public class VulnerableSessionManager
    {
        private static readonly Dictionary<string, SessionData> _sessions = new();

        public string CreateSession(string userId)
        {
            // Predictable session ID generation
            var sessionId = $"sess_{userId}_{DateTime.Now.Ticks}";
            
            _sessions[sessionId] = new SessionData
            {
                UserId = userId,
                CreatedAt = DateTime.Now,
                LastActivity = DateTime.Now
            };
            
            return sessionId;
        }

        public SessionData GetSession(string sessionId)
        {
            // No validation or expiration check
            return _sessions.ContainsKey(sessionId) ? _sessions[sessionId] : null;
        }

        public void UpdateSession(string sessionId, string key, object value)
        {
            // No synchronization for concurrent access
            if (_sessions.ContainsKey(sessionId))
            {
                _sessions[sessionId].Data[key] = value;
            }
        }
    }

    public class SessionData
    {
        public string UserId { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastActivity { get; set; }
        public Dictionary<string, object> Data { get; set; } = new();
    }
}
