using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace VulnerableAuthExamples
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

        [HttpPost]
        public IActionResult DeleteUser()  // No [Authorize] attribute
        {
            return Ok("User deleted");
        }
    }

    // VULNERABLE: Hardcoded Authentication Bypass
    public class AuthService
    {
        public bool ValidateUser(string username, string password)
        {
            // VULNERABLE: Hardcoded bypass
            if (username == "admin" && password == "bypass")
            {
                return true;
            }

            // VULNERABLE: Another bypass condition
            if (username.Equals("root"))
            {
                return true;
            }

            return ValidateCredentials(username, password);
        }

        private bool ValidateCredentials(string username, string password)
        {
            return false; // Simplified for example
        }
    }

    // VULNERABLE: Authentication Check Bypass
    public class BypassAuthService
    {
        public bool IsAuthenticated(string token)
        {
            return true; // TODO: bypass for testing - remove later
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            return Task.FromResult(true); // temporary bypass for debug
        }
    }

    // VULNERABLE: Weak JWT Validation
    public class JwtService
    {
        public void ConfigureJwtValidation()
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = false,  // VULNERABLE: Signature not validated
                RequireSignedTokens = false,       // VULNERABLE: Unsigned tokens allowed
                ValidateIssuer = true,
                ValidateAudience = true
            };
        }
    }

    // VULNERABLE: Role-Based Access Control Bypass
    [ApiController]
    public class AdminController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetAdminData()
        {
            // VULNERABLE: OR condition allows bypass
            if (User.IsInRole("Admin") || User.IsInRole("Guest"))
            {
                return Ok("Admin data");
            }
            return Forbid();
        }

        [HttpDelete]
        public IActionResult DeleteCriticalData()
        {
            // VULNERABLE: Always true condition
            if (User.IsInRole("SuperAdmin") || true)
            {
                return Ok("Data deleted");
            }
            return Forbid();
        }
    }

    // VULNERABLE: Session Validation Bypass
    public class SessionController : Controller
    {
        public IActionResult AccessProtectedResource()
        {
            // VULNERABLE: OR condition bypasses proper session check
            if (Session != null || Request.Headers.ContainsKey("X-Debug"))
            {
                return View("ProtectedContent");
            }
            return RedirectToAction("Login");
        }
    }

    // VULNERABLE: Debug Authentication Bypass
    public class ProductionAuthService
    {
        public bool AuthenticateUser(string username, string password)
        {
#if DEBUG
            return true;  // VULNERABLE: Debug bypass in production code
#endif
            return ValidateUserCredentials(username, password);
        }

        public bool IsUserAuthorized(string userId, string resource)
        {
#if DEVELOPMENT
            return true;  // VULNERABLE: Development bypass
#endif
            return CheckUserPermissions(userId, resource);
        }

        private bool ValidateUserCredentials(string username, string password)
        {
            // Proper validation logic here
            return false;
        }

        private bool CheckUserPermissions(string userId, string resource)
        {
            // Proper permission checking logic here
            return false;
        }
    }

    // VULNERABLE: Authorization Policy Bypass
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            // VULNERABLE: Empty authorization configuration
            services.AddAuthorization();

            // Should define policies properly
        }
    }

    // Additional vulnerable patterns
    public class WeakAuthController : ControllerBase
    {
        // VULNERABLE: Empty Authorize attribute
        [Authorize()]
        [HttpGet]
        public IActionResult WeakProtection()
        {
            return Ok();
        }
    }
}
