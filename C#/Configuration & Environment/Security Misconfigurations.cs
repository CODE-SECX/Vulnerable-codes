using System;
using System.Security.Cryptography;
using System.Net;
using System.IO;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Data.SqlClient;

namespace VulnerableMisconfigurationExamples
{
    // 1. Debug Mode Enabled in Production - VULNERABLE
    public class Startup
    {
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // VULNERABLE: Always using developer exception page
            app.UseDeveloperExceptionPage();
            
            // VULNERABLE: Debug-specific code without environment check
            if (true) // Should check env.IsDevelopment()
            {
                app.UseDeveloperExceptionPage();
            }
        }
    }

    // 2. Insecure SSL/TLS Configuration - VULNERABLE
    public class InsecureHttpClientConfig
    {
        public void ConfigureHttpClient()
        {
            // VULNERABLE: Disabling certificate validation
            ServicePointManager.ServerCertificateValidationCallback = 
                (sender, certificate, chain, sslPolicyErrors) => true;
            
            // VULNERABLE: Using weak TLS versions
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            
            // VULNERABLE: Disabling certificate revocation checking
            ServicePointManager.CheckCertificateRevocationList = false;
        }
    }

    // 3. Insecure HTTP Headers - VULNERABLE
    public class InsecureHeadersController : ControllerBase
    {
        [HttpGet]
        public IActionResult VulnerableEndpoint()
        {
            // VULNERABLE: Allowing all frames
            Response.Headers.Add("X-Frame-Options", "ALLOWALL");
            
            // VULNERABLE: Disabling XSS protection
            Response.Headers.Add("X-XSS-Protection", "0");
            
            // VULNERABLE: Weak HSTS configuration
            Response.Headers.Add("Strict-Transport-Security", "max-age=0");
            
            // VULNERABLE: Unsafe CSP
            Response.Headers.Add("Content-Security-Policy", "default-src 'unsafe-inline' 'unsafe-eval'");
            
            return Ok("Vulnerable response");
        }
    }

    // 4. Weak Authentication Configuration - VULNERABLE
    public class WeakAuthenticationStartup
    {
        public void ConfigureServices(IServiceCollectionservices)
        {
            services.Configure<IdentityOptions>(options =>
            {
                // VULNERABLE: Weak password policy
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 4; // Too short
                options.Password.RequireNonAlphanumeric = false;
                
                // VULNERABLE: No account lockout
                options.Lockout.MaxFailedAccessAttempts = 0;
                options.Lockout.LockoutTimeSpan = TimeSpan.FromSeconds(0);
            });
        }
    }

    // 5. Insecure Session Configuration - VULNERABLE
    public class InsecureSessionStartup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.ConfigureApplicationCookie(options =>
            {
                // VULNERABLE: Insecure cookie settings
                options.Cookie.HttpOnly = false;
                options.Cookie.Secure = CookieSecurePolicy.None;
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.None;
                
                // VULNERABLE: Long session timeout
                options.ExpireTimeSpan = TimeSpan.FromDays(365);
            });
            
            services.AddSession(options =>
            {
                // VULNERABLE: Insecure session cookie
                options.Cookie.HttpOnly = false;
                options.Cookie.Secure = CookieSecurePolicy.None;
            });
        }
    }

    // 6. Insecure CORS Configuration - VULNERABLE
    public class InsecureCorsStartup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddCors(options =>
            {
                options.AddPolicy("VulnerablePolicy", builder =>
                {
                    // VULNERABLE: Allow any origin
                    builder.AllowAnyOrigin()
                           .AllowAnyHeader()
                           .AllowAnyMethod()
                           .AllowCredentials(); // This combination is dangerous
                });
                
                options.AddPolicy("AnotherVulnerablePolicy", builder =>
                {
                    // VULNERABLE: Wildcard origin
                    builder.WithOrigins("*")
                           .AllowCredentials();
                });
            });
        }
        
        public void Configure(IApplicationBuilder app)
        {
            // VULNERABLE: Adding permissive CORS header manually
            app.Use(async (context, next) =>
            {
                context.Response.Headers.Add("Access-Control-Allow-Origin", "*");
                await next();
            });
        }
    }

    // 7. Insecure Database Connection - VULNERABLE
    public class InsecureDatabaseConfig
    {
        public void ConnectToDatabase()
        {
            // VULNERABLE: Unencrypted connection
            string connectionString1 = "Server=server;Database=db;User Id=user;Password=pass;Encrypt=false;";
            
            // VULNERABLE: Trusting server certificate without validation
            string connectionString2 = "Server=server;Database=db;Integrated Security=false;TrustServerCertificate=true;";
            
            // VULNERABLE: Persisting security info
            string connectionString3 = "Server=server;Database=db;User Id=user;Password=pass;Persist Security Info=true;";
            
            // VULNERABLE: No timeout (infinite wait)
            string connectionString4 = "Server=server;Database=db;Connection Timeout=0;";
            
            SqlConnection conn = new SqlConnection(connectionString1);
        }
    }

    // 8. Insecure Logging Configuration - VULNERABLE
    public class InsecureLoggingController : ControllerBase
    {
        private readonly ILogger<InsecureLoggingController> _logger;

        public InsecureLoggingController(ILogger<InsecureLoggingController> logger)
        {
            _logger = logger;
        }

        public void VulnerableLogging(string password, string token)
        {
            // VULNERABLE: Logging sensitive data at debug/trace level
            _logger.LogTrace($"User password: {password}");
            _logger.LogDebug($"Authentication token: {token}");
            _logger.LogInformation($"Processing credential: {password}");
        }
    }

    // 9. Insecure API Configuration - VULNERABLE
    [ApiController]
    [AllowAnonymous] // VULNERABLE: Entire controller allows anonymous access
    public class InsecureApiController : ControllerBase
    {
        // VULNERABLE: Sensitive endpoint without authentication
        [HttpGet("admin/users")]
        [AllowAnonymous]
        public IActionResult GetAllUsers()
        {
            return Ok("All user data");
        }
        
        // VULNERABLE: No authorization policy
        [HttpPost("transfer-money")]
        [Authorize(Policy = "")] // Empty policy
        public IActionResult TransferMoney()
        {
            return Ok("Money transferred");
        }
    }

    // 10. Insecure Cryptographic Configuration - VULNERABLE
    public class WeakCryptographyService
    {
        public void VulnerableCryptoMethods()
        {
            // VULNERABLE: Using MD5
            using (var md5 = MD5.Create())
            {
                // Weak hashing algorithm
            }
            
            // VULNERABLE: Using SHA1
            using (var sha1 = SHA1.Create())
            {
                // Weak hashing algorithm
            }
            
            // VULNERABLE: Using DES
            using (var des = DES.Create())
            {
                // Weak encryption algorithm
            }
            
            // VULNERABLE: Using TripleDES
            using (var tdes = TripleDES.Create())
            {
                // Weak encryption algorithm
            }
            
            // VULNERABLE: Weak AES configuration
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128; // Weak key size
                aes.Mode = CipherMode.ECB; // Insecure mode
                aes.Padding = PaddingMode.None; // No padding
            }
            
            // VULNERABLE: Using deprecated RijndaelManaged
            using (var rijndael = new RijndaelManaged())
            {
                // Deprecated class
            }
        }
    }

    // 11. Insecure File Upload Configuration - VULNERABLE
    [ApiController]
    public class VulnerableFileUploadController : ControllerBase
    {
        [HttpPost("upload")]
        public async Task<IActionResult> UploadFile(IFormFile file)
        {
            // VULNERABLE: No file type validation
            var fileName = file.FileName;
            
            // VULNERABLE: Direct path combination with user input
            var filePath = Path.Combine("uploads", fileName);
            
            // VULNERABLE: No size limit check (beyond global config)
            using (var stream = new FileStream(filePath, FileMode.Create))
            {
                await file.CopyToAsync(stream);
            }
            
            return Ok($"File uploaded: {fileName}");
        }
    }

    // Additional vulnerable configuration examples
    public class AdditionalVulnerableConfigs
    {
        public void MoreInsecureConfigurations()
        {
            // VULNERABLE: Weak SSL protocols
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;
            
            // VULNERABLE: Disabling certificate validation globally
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            
            // VULNERABLE: Insecure random number generation
            var random = new Random(); // Not cryptographically secure
            
            // VULNERABLE: Hard-coded crypto keys
            var key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }; // Weak key
        }
    }

    // Web.config equivalent vulnerabilities (for reference)
    /*
    VULNERABLE web.config sections:
    
    <!-- Debug enabled in production -->
    <compilation debug="true" />
    
    <!-- Cookieless sessions -->
    <sessionState cookieless="true" />
    
    <!-- Insecure HTTP cookies -->
    <httpCookies httpOnlyCookies="false" requireSSL="false" />
    
    <!-- ViewState without MAC -->
    <pages enableViewStateMac="false" viewStateEncryptionMode="Never" />
    
    <!-- Large file uploads without limits -->
    <httpRuntime maxRequestLength="2147483647" executionTimeout="3600" />
    
    <!-- Custom errors off -->
    <customErrors mode="Off" />
    */
}
