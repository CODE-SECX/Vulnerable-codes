using System;
using System.Data.SqlClient;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json;
using System.IO;

namespace VulnerableLoggingExamples
{
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;
        
        public UserController(ILogger<UserController> logger)
        {
            _logger = logger;
        }

        // VULNERABLE: Sensitive Data in Log Messages
        public IActionResult Login(string username, string password)
        {
            _logger.LogInformation($"User login attempt: {username} with password: {password}");
            _logger.LogDebug($"Authentication token: {GenerateJWTToken(username)}");
            _logger.LogError($"Failed login for SSN: 123-45-6789 and credit card: 4532-1234-5678-9012");
            
            return Ok();
        }

        // VULNERABLE: Exception Stack Trace Logging
        public IActionResult ProcessUser(int userId)
        {
            try
            {
                // Some operation that might fail
                var user = GetUserById(userId);
                return Ok(user);
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error processing user: {ex.ToString()}");
                _logger.LogWarning($"Exception details: {ex.StackTrace}");
                _logger.LogDebug($"Inner exception: {ex.InnerException?.Message}");
                return StatusCode(500);
            }
        }

        // VULNERABLE: SQL Query Logging
        public IActionResult GetUserData(string userId, string password)
        {
            string query = $"SELECT * FROM Users WHERE UserId = '{userId}' AND Password = '{password}'";
            _logger.LogDebug($"Executing SQL query: {query}");
            
            string insertQuery = $"INSERT INTO LoginAttempts VALUES ('{userId}', '{DateTime.Now}', '{password}')";
            _logger.LogInformation($"Logging attempt with query: {insertQuery}");
            
            return Ok();
        }

        // VULNERABLE: Request/Response Body Logging
        [HttpPost]
        public async Task<IActionResult> CreateUser()
        {
            var requestBody = await new StreamReader(Request.Body).ReadToEndAsync();
            _logger.LogInformation($"Received request body: {requestBody}");
            
            var response = "User created successfully";
            _logger.LogDebug($"Response content: {response}");
            _logger.LogTrace($"Request headers: {Request.Headers}");
            
            return Ok(response);
        }

        // VULNERABLE: File Path Disclosure in Logs
        public IActionResult ProcessFile(string fileName)
        {
            string fullPath = @"C:\SecretConfigs\Database\ConnectionStrings.config";
            _logger.LogError($"Failed to read file at path: {fullPath}");
            _logger.LogWarning($"File not found: {fileName} in directory \\\\server\\share\\sensitive\\");
            _logger.LogDebug($"Processing file:// {fullPath}");
            
            return Ok();
        }

        // VULNERABLE: Connection String Logging
        public void InitializeDatabase()
        {
            string connectionString = "Server=localhost;Database=UserDB;User Id=admin;Password=secretpass123;";
            _logger.LogDebug($"Using connection string: {connectionString}");
            _logger.LogInformation($"Database configuration: Server=prod-server;Integrated Security=false;Password=dbpass;");
            
            using (var connection = new SqlConnection(connectionString))
            {
                _logger.LogTrace($"Connection details: {connection.ConnectionString}");
            }
        }

        // VULNERABLE: Debug Information in Production Logs
        public IActionResult ProcessUserData(User user)
        {
            _logger.LogDebug($"User object state: {JsonConvert.SerializeObject(user)}");
            _logger.LogDebug($"Processing user variable: {user.ToString()}");
            _logger.LogTrace($"User parameters: Name={user.Name}, Email={user.Email}, Password={user.Password}");
            
            return Ok();
        }

        // VULNERABLE: Authentication Token Logging
        public IActionResult AuthenticateUser()
        {
            string bearerToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
            _logger.LogInformation($"Received bearer token: {bearerToken}");
            
            string apiKey = "sk-1234567890abcdef";
            _logger.LogDebug($"Using API key: {apiKey}");
            
            string jwtToken = GenerateJWTToken("user123");
            _logger.LogTrace($"Generated JWT: {jwtToken}");
            
            _logger.LogError($"Authorization header: {Request.Headers["Authorization"]}");
            
            return Ok();
        }

        // VULNERABLE: Session Data Logging
        public IActionResult ManageSession()
        {
            _logger.LogDebug($"Current session: {JsonConvert.SerializeObject(HttpContext.Session)}");
            _logger.LogInformation($"Session ID: {HttpContext.Session.Id}");
            _logger.LogTrace($"Session state: {HttpContext.Session.GetString("UserData")}");
            
            return Ok();
        }

        // VULNERABLE: Unstructured Sensitive Data Logging
        public IActionResult ProcessSensitiveData(string userToken, string personalInfo)
        {
            string sensitiveData = "SSN: 123-45-6789";
            _logger.LogWarning($"Processing data for token " + userToken + " with info " + personalInfo);
            _logger.LogError(string.Format("Error with token {0} and sensitive data {1}", userToken, sensitiveData));
            _logger.LogDebug(string.Concat("User: ", personalInfo, " Token: ", userToken, " Data: ", sensitiveData));
            
            return Ok();
        }

        // Helper methods
        private User GetUserById(int id) => new User { Id = id, Name = "TestUser", Email = "test@example.com", Password = "secret123" };
        private string GenerateJWTToken(string username) => "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sample.token";
    }

    public class User
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        
        public override string ToString()
        {
            return $"User: {Name}, Email: {Email}, Password: {Password}";
        }
    }

    // Additional vulnerable logging examples
    public class DatabaseService
    {
        private readonly ILogger<DatabaseService> _logger;
        
        public DatabaseService(ILogger<DatabaseService> logger)
        {
            _logger = logger;
        }

        // VULNERABLE: Multiple issues in one method
        public void ExecuteUserQuery(string username, string password, string personalData)
        {
            try
            {
                string query = $"SELECT * FROM Users WHERE Username='{username}' AND Password='{password}'";
                _logger.LogDebug($"Executing query: {query}");
                
                string connectionString = "Data Source=server;Initial Catalog=DB;User ID=sa;Password=admin123";
                Console.WriteLine($"Connection: {connectionString}"); // This would also be caught
                
                _logger.LogInformation($"User data contains: SSN={personalData}, Token=bearer_abc123");
            }
            catch (Exception ex)
            {
                _logger.LogError($"Database error: {ex.ToString()}");
                System.Diagnostics.Debug.WriteLine($"Full exception: {ex.StackTrace}");
            }
        }
    }

    // VULNERABLE: File operations with path disclosure
    public class FileService
    {
        private readonly ILogger<FileService> _logger;
        
        public FileService(ILogger<FileService> logger)
        {
            _logger = logger;
        }
        
        public void ProcessConfigFile()
        {
            string configPath = @"D:\Applications\MyApp\Configs\secrets.json";
            _logger.LogError($"Cannot access file at: {configPath}");
            
            string networkPath = @"\\prod-server\secrets\api-keys.txt";
            _logger.LogWarning($"Network file issue: {networkPath}");
            
            Log.Debug($"Processing filepath: {configPath}"); // Different logger instance
        }
    }
}