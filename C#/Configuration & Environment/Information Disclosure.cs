using System;
using System.Data.SqlClient;
using System.IO;
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;

namespace VulnerableExamples
{
    public class VulnerableController : ControllerBase
    {
        private readonly ILogger<VulnerableController> _logger;
        private readonly IConfiguration _configuration;

        public VulnerableController(ILogger<VulnerableController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        // 1. Hardcoded Credentials - VULNERABLE
        public void ConnectToDatabase()
        {
            string password = "MySecretPassword123!";
            string apiKey = "sk-1234567890abcdef1234567890abcdef";
            string connectionString = "Server=localhost;Database=MyDB;User Id=admin;Password=AdminPass123;";
            string secret = "MyApplicationSecretKey2023";
            
            // This should be detected by Rule 1
        }

        // 2. Detailed Exception Exposure - VULNERABLE
        [HttpGet]
        public IActionResult GetUserData(int userId)
        {
            try
            {
                // Some operation that might fail
                var userData = GetUserFromDatabase(userId);
                return Ok(userData);
            }
            catch (Exception ex)
            {
                // VULNERABLE: Exposing detailed exception information
                Response.Write($"Error occurred: {ex.Message} - {ex.StackTrace}");
                return BadRequest(ex.ToString());
                // This should be detected by Rules 2 and 7
            }
        }

        // 3. Debug Information with Sensitive Data - VULNERABLE
        public void ProcessUserLogin(string username, string password)
        {
            Debug.WriteLine($"User login attempt: {username} with password: {password}");
            Console.WriteLine($"Processing login for user: {username}, password: {password}");
            Trace.WriteLine($"Authentication token: {GenerateToken()}");
            System.Diagnostics.Debug.WriteLine($"Secret key used: {GetSecretKey()}");
            
            // This should be detected by Rule 3
        }

        // 4. SQL Connection String with Credentials - VULNERABLE
        public void DatabaseConnection()
        {
            string connectionString = "Data Source=server;Initial Catalog=DB;User ID=dbuser;Password=dbpass123;";
            string connString = "Server=myServer;Database=myDB;Uid=myUser;Pwd=myPassword123;";
            
            SqlConnection conn = new SqlConnection(connectionString);
            // This should be detected by Rule 4
        }

        // 5. Sensitive Data in Logs - VULNERABLE
        public void ProcessPayment(string creditCard, string cvv, string ssn)
        {
            _logger.LogInformation($"Processing payment for card: {creditCard}");
            _logger.LogDebug($"CVV provided: {cvv}");
            Console.WriteLine($"User SSN: {ssn}");
            Log.Info($"Credit card number: {creditCard}, PIN: 1234");
            
            // This should be detected by Rule 5
        }

        // 6. Configuration Secrets in Code - VULNERABLE
        public void LoadConfiguration()
        {
            Configuration["DatabasePassword"] = "MyDatabasePassword123";
            ConfigurationManager.AppSettings["ApiKey"] = "sk-abcdef1234567890abcdef1234567890";
            AppSettings["SecretToken"] = "MySecretToken2023!";
            
            // This should be detected by Rule 6
        }

        // 7. File System Path Exposure - VULNERABLE
        public IActionResult ListFiles(string directory)
        {
            try
            {
                var files = Directory.GetFiles(directory);
                var fileInfos = new List<string>();
                
                foreach (var file in files)
                {
                    var info = new FileInfo(file);
                    fileInfos.Add(info.FullName); // Exposing full path
                }
                
                var directories = Directory.GetDirectories(@"C:\Sensitive\Path");
                var dirInfo = new DirectoryInfo(@"C:\Internal\Config");
                
                return Ok(new { 
                    Files = fileInfos, 
                    Directories = directories,
                    ConfigPath = dirInfo.FullName
                });
                // This should be detected by Rule 8
            }
            catch (Exception ex)
            {
                return BadRequest($"Directory error: {ex.Message} - {ex.StackTrace}");
                // This should also be detected by Rule 7
            }
        }

        // Additional vulnerable patterns
        public void MoreVulnerablePatterns()
        {
            // Hardcoded tokens and keys
            string jwtSecret = "MyJWTSigningSecret2023!";
            string encryptionKey = "MyEncryptionKey123456789";
            
            // Debug statements with sensitive info
            Debug.WriteLine($"User credentials: admin/AdminPassword123");
            
            // Logging sensitive data
            _logger.LogError($"Failed login for user with password: {'userPassword'}");
            
            // Configuration exposure
            var dbPassword = Configuration["Database:Password"] = "ProductionDBPass123!";
        }

        private object GetUserFromDatabase(int userId)
        {
            // Mock implementation
            return new { Id = userId, Name = "John Doe" };
        }

        private string GenerateToken()
        {
            return "token123456789";
        }

        private string GetSecretKey()
        {
            return "secretkey123";
        }
    }

    // Additional vulnerable class examples
    public class DatabaseHelper
    {
        // VULNERABLE: Hardcoded connection string
        private readonly string _connectionString = "Server=prod-server;Database=ProdDB;User Id=sa;Password=ProductionPassword123!;";
        
        public void LogDatabaseError(Exception ex)
        {
            // VULNERABLE: Exposing detailed error information
            Console.WriteLine($"Database error: {ex.ToString()}");
            System.Diagnostics.Debug.WriteLine($"Connection string used: {_connectionString}");
        }
    }

    public class ConfigurationService
    {
        public void InitializeConfig()
        {
            // VULNERABLE: Hardcoded sensitive configuration
            var apiKey = "AKIAIOSFODNN7EXAMPLE"; // AWS access key format
            var secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
            var password = "MyApplicationPassword2023!";
            
            // VULNERABLE: Logging sensitive configuration
            Console.WriteLine($"Initializing with API key: {apiKey}");
        }
    }
}
