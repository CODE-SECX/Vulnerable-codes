// VULNERABLE CODE EXAMPLES FOR TESTING HTTP SECURITY HEADERS RULES

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace VulnerableApp
{
    public class Startup
    {
        // 1. VULNERABLE: Missing X-Frame-Options Header
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("Content-Type", "text/html");
                // Missing X-Frame-Options header - vulnerable to clickjacking
                await next();
            });
        }

        // 2. VULNERABLE: Missing X-Content-Type-Options Header
        public void ConfigureHeaders(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("Cache-Control", "no-cache");
                // Missing X-Content-Type-Options header - vulnerable to MIME sniffing
                await next();
            });
        }

        // 3. VULNERABLE: Missing Strict-Transport-Security Header
        public void ConfigureHTTPS(IApplicationBuilder app)
        {
            app.UseHttpsRedirection();
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("X-Frame-Options", "DENY");
                // Missing HSTS header - vulnerable to protocol downgrade attacks
                await next();
            });
        }

        // 4. VULNERABLE: Missing Content-Security-Policy Header
        public void ConfigureCSP(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                // Missing CSP header - vulnerable to XSS attacks
                await next();
            });
        }

        // 5. VULNERABLE: Weak Content-Security-Policy Configuration
        public void ConfigureWeakCSP(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Weak CSP with unsafe-inline and unsafe-eval
                context.Response.Headers.Add("Content-Security-Policy", 
                    "default-src 'self' 'unsafe-inline' 'unsafe-eval' *");
                await next();
            });
        }

        // 6. VULNERABLE: Missing Referrer-Policy Header
        public void ConfigureReferrer(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");
                // Missing Referrer-Policy header
                await next();
            });
        }

        // 7. VULNERABLE: Missing Permissions-Policy Header
        public void ConfigurePermissions(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
                // Missing Permissions-Policy header
                await next();
            });
        }

        // 8. VULNERABLE: Insecure X-XSS-Protection Header
        public void ConfigureXSS(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Vulnerable X-XSS-Protection configuration
                context.Response.Headers.Add("X-XSS-Protection", "1");
                await next();
            });
        }

        // 9. VULNERABLE: Server Information Disclosure
        public void ConfigureServerInfo(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Exposing server information
                context.Response.Headers.Add("Server", "Microsoft-IIS/10.0");
                context.Response.Headers.Add("X-Powered-By", "ASP.NET Core 6.0");
                await next();
            });
        }

        // 10. VULNERABLE: Missing Cache-Control for Sensitive Content
        [HttpGet("login")]
        public ActionResult Login()
        {
            // Missing cache control headers for sensitive login page
            return View();
        }

        [HttpGet("admin/dashboard")]
        public ActionResult AdminDashboard()
        {
            // Missing cache control headers for admin content
            return View();
        }

        [HttpPost("secure/token")]
        public ActionResult GenerateToken()
        {
            // Missing cache control headers for token endpoint
            return Json(new { token = "sensitive-token" });
        }

        // 11. VULNERABLE: Permissive CORS Configuration
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("AllowAll", builder =>
                {
                    // Dangerous CORS configuration allowing all origins
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });
        }

        public void ConfigureCORS2(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                {
                    // Another vulnerable CORS configuration
                    builder.WithOrigins("*")
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });
        }

        // 12. VULNERABLE: Missing Cross-Origin Headers
        public void ConfigureCrossOrigin(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
                // Missing Cross-Origin-Embedder-Policy
                // Missing Cross-Origin-Opener-Policy
                // Missing Cross-Origin-Resource-Policy
                // Missing X-Permitted-Cross-Domain-Policies
                await next();
            });
        }

        // 13. VULNERABLE: Weak HSTS Configuration
        public void ConfigureWeakHSTS(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // Weak HSTS configuration with short max-age
                context.Response.Headers.Add("Strict-Transport-Security", "max-age=3600");
                await next();
            });
        }

        public void ConfigureWeakHSTS2(IApplicationBuilder app)
        {
            app.Use(async (context, next) =>
            {
                // HSTS without includeSubDomains
                context.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000");
                await next();
            });
        }

        // 14. ADDITIONAL VULNERABLE PATTERNS
        public void ConfigureMultipleVulnerabilities(IApplicationBuilder app)
        {
            // Multiple vulnerabilities in one configuration
            app.Use(async (context, next) =>
            {
                // Only setting some headers, missing critical ones
                context.Response.Headers.Add("Cache-Control", "public, max-age=3600");
                context.Response.Headers.Add("Server", "Custom-Server/1.0");
                // Missing: X-Frame-Options, X-Content-Type-Options, CSP, HSTS, etc.
                await next();
            });
        }

        // 15. VULNERABLE: Middleware without security headers
        public void ConfigureBasicMiddleware(IApplicationBuilder app)
        {
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            // No security headers middleware configured
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }

    // VULNERABLE CONTROLLER EXAMPLES
    public class VulnerableController : Controller
    {
        // Missing cache control for password reset
        [HttpGet("password-reset")]
        public ActionResult PasswordReset()
        {
            return View();
        }

        // Missing security headers for API endpoint
        [HttpPost("api/sensitive-data")]
        public ActionResult GetSensitiveData()
        {
            return Json(new { data = "sensitive information" });
        }
    }

    // VULNERABLE CONFIGURATION CLASS
    public class InsecureHeaderConfiguration
    {
        public static void AddInsecureHeaders(HttpResponse response)
        {
            // Adding headers but missing security ones
            response.Headers.Add("Content-Type", "application/json");
            response.Headers.Add("Date", DateTime.Now.ToString());
            // Missing all security headers
        }
    }
}
