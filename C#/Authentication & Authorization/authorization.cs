using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace VulnerableApp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class VulnerableController : ControllerBase
    {
        // VULNERABILITY 1: Missing Authorization Attribute
        [HttpGet]
        public async Task<IActionResult> GetSensitiveData()
        {
            // This should require authorization but doesn't have [Authorize]
            return Ok("Sensitive data accessible to anyone");
        }

        // VULNERABILITY 2: Hardcoded Authorization Bypass
        [HttpGet("admin")]
        public IActionResult AdminPanel()
        {
            if (true) // Always grants access - hardcoded bypass
            {
                return Ok("Admin panel access granted");
            }
            return Unauthorized();
        }

        // VULNERABILITY 3: Hardcoded User Check
        [HttpPost("login")]
        public IActionResult Login(string username, string password)
        {
            if (username == "admin" && password == "password123") // Hardcoded credentials
            {
                return Ok("Login successful");
            }
            return Unauthorized();
        }

        // VULNERABILITY 4: Insecure Direct Object Reference
        [HttpGet("user/{id}")]
        public async Task<IActionResult> GetUserById(int id)
        {
            var user = await GetUserFromDatabase(id); // No authorization check
            return Ok(user);
        }

        // VULNERABILITY 5: Missing CSRF Protection
        [HttpPost("delete-user")]
        public async Task<IActionResult> DeleteUser(int userId)
        {
            // Missing [ValidateAntiForgeryToken] attribute
            await DeleteUserFromDatabase(userId);
            return Ok("User deleted");
        }

        // VULNERABILITY 6: Weak Role-Based Authorization
        [Authorize(Roles = "User")] // Too permissive
        [HttpDelete("delete-all-data")]
        public async Task<IActionResult> DeleteAllData()
        {
            // Critical operation with weak authorization
            return Ok("All data deleted");
        }

        // VULNERABILITY 7: Elevation of Privilege Risk
        [HttpPost("promote-user")]
        public async Task<IActionResult> PromoteUser(int userId, string role)
        {
            await AddToRole(userId, role); // No authorization check for privilege escalation
            return Ok($"User promoted to {role}");
        }

        // VULNERABILITY 8: Authorization Based on Client Data
        [HttpGet("protected-resource")]
        public IActionResult GetProtectedResource()
        {
            if (Request.Headers["IsAdmin"].ToString() == "true") // Client-controlled data
            {
                return Ok("Protected resource");
            }
            return Unauthorized();
        }

        // VULNERABILITY 9: Insecure AllowAnonymous Usage
        [AllowAnonymous]
        [HttpDelete("critical-operation")]
        public async Task<IActionResult> CriticalOperation()
        {
            // Critical operation should not be anonymous
            return Ok("Critical operation completed");
        }

        // VULNERABILITY 10: Missing Input Validation in Authorization
        [HttpGet("check-permission")]
        public IActionResult CheckPermission(string permission)
        {
            if (User.HasClaim("Permission", permission)) // No validation of permission parameter
            {
                return Ok("Permission granted");
            }
            return Unauthorized();
        }

        // VULNERABILITY 11: Authorization Decision Based on Query Parameters
        [HttpGet("admin-data")]
        public IActionResult GetAdminData(bool isAdmin)
        {
            if (isAdmin) // Authorization based on client parameter
            {
                return Ok("Admin data");
            }
            return Unauthorized();
        }

        // VULNERABILITY 12: Missing Authorization on API Controller
        public class UnprotectedApiController : ControllerBase
        {
            [HttpGet("sensitive-endpoint")]
            public IActionResult GetSensitiveEndpoint()
            {
                // No authorization attributes at all
                return Ok("Sensitive data");
            }
        }

        // Helper methods (normally would be in separate service)
        private async Task<object> GetUserFromDatabase(int id)
        {
            // Simulate database call
            return new { Id = id, Name = "User" + id };
        }

        private async Task DeleteUserFromDatabase(int userId)
        {
            // Simulate database deletion
        }

        private async Task AddToRole(int userId, string role)
        {
            // Simulate role assignment
        }
    }

    // VULNERABILITY 13: Controller without any authorization
    public class PublicController : ControllerBase
    {
        [HttpGet("public-data")]
        public IActionResult GetPublicData()
        {
            return Ok("This might be fine if truly public");
        }

        [HttpPost("update-settings")] // This should require authorization
        public IActionResult UpdateSettings(object settings)
        {
            return Ok("Settings updated");
        }
    }

    // VULNERABILITY 14: Mixed authorization patterns
    [Authorize]
    public class MixedController : ControllerBase
    {
        [HttpGet("protected")]
        public IActionResult ProtectedMethod()
        {
            return Ok("This is properly protected");
        }

        [AllowAnonymous]
        [HttpPut("update-critical-data")] // Overrides class-level authorization inappropriately
        public IActionResult UpdateCriticalData()
        {
            return Ok("Critical data updated without authorization");
        }
    }
}
