using System;
using System.Security.Cryptography;
using System.IO;
using System.Net.Http;
using System.Net;
using System.Security;
using System.Text;

namespace VulnerableKeyManagement
{
    public class KeyManagementVulnerabilities
    {
        // Rule 1: Hardcoded Private Keys in Code
        private static string hardcodedPrivateKey = @"
-----BEGIN RSA PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB
UJBW9LjZeCKZZgb7BUTdgQjuKLh2Z5u8BaEH2g7QRJXmjGcj2VNFc8JNw2L/5RK
-----END RSA PRIVATE KEY-----";

        // Rule 2: Hardcoded API Keys and Secrets
        private string apiKey = "sk-1234567890abcdef1234567890abcdef12345678";
        private string accessToken = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        private string secretKey = "super_secret_key_123456789";

        // Rule 3: Insecure Key Storage in Memory
        private string encryptionKey = "MySecretEncryptionKey123!";
        private byte[] cryptoKey = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

        // Rule 4: Key Derivation Without Salt
        public byte[] DeriveKeyWithoutSalt(string password)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, null, 10000);
            return pbkdf2.GetBytes(32);
        }

        public byte[] WeakKeyDerivation(string password)
        {
            var derive = new Rfc2898DeriveBytes(password);
            return derive.GetBytes(16);
        }

        // Rule 5: Insecure Key Exchange Implementation
        public void WeakKeyExchange()
        {
            var dh = DiffieHellman.Create(512); // Weak key size
            var ecdh = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("P-256")); // Not explicitly weak but pattern detected
        }

        // Rule 6: Missing Key Rotation Implementation
        private static readonly string StaticEncryptionKey = "MyStaticKey123456789";
        private const string ConstantSecret = "ConstantSecretValue";
        private static byte[] StaticKeyBytes = { 1, 2, 3, 4, 5, 6, 7, 8 };

        // Rule 7: Insecure Key Transmission
        public async void SendKeyOverHttp()
        {
            using (var client = new HttpClient())
            {
                var keyData = new { secretKey = "my-secret-key-123", token = "auth-token-456" };
                await client.PostAsJsonAsync("http://api.example.com/keys", keyData);
            }
        }

        // Rule 8: Weak Key Generation Entropy
        public byte[] GenerateWeakKey()
        {
            var random = new Random(12345);
            var keyBytes = new byte[16];
            random.NextBytes(keyBytes);
            return keyBytes;
        }

        public string GenerateWeakApiKey()
        {
            var rand = new System.Random();
            return "key_" + rand.Next(100000, 999999).ToString();
        }

        // Rule 9: Insecure Key Backup and Recovery
        public void BackupKeyInsecurely(byte[] privateKey)
        {
            File.WriteAllBytes("backup_private_key.bak", privateKey);
            File.WriteAllText("secret_backup.txt", Convert.ToBase64String(privateKey));
            
            using (var writer = new StreamWriter("key_backup.log"))
            {
                writer.WriteLine("Private Key: " + Convert.ToBase64String(privateKey));
            }
        }

        // Rule 10: Missing Key Validation
        public void UseKeyWithoutValidation(RSA rsa, byte[] data)
        {
            // No key size or validity checks
            var encrypted = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            var signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        // Rule 11: Insecure Key Derivation Function Usage
        public byte[] WeakKeyDerivationFunction(string password, byte[] salt)
        {
            var derive = new PasswordDeriveBytes(password, salt); // Deprecated
            return derive.GetBytes(16);
        }

        public byte[] MD5KeyDerivation(string input)
        {
            using (var md5 = MD5.Create())
            {
                return md5.ComputeHash(Encoding.UTF8.GetBytes(input));
            }
        }

        // Rule 12: Improper Key Lifecycle Management
        public void ImproperKeyLifecycle()
        {
            var aes = Aes.Create(); // Not using 'using' statement
            aes.GenerateKey();
            
            var rsa = RSA.Create(); // Memory leak potential
            var key = rsa.ExportRSAPrivateKey();
            
            // Keys not properly disposed
        }

        // Rule 13: Certificate Validation Bypass
        public void BypassCertificateValidation()
        {
            ServicePointManager.ServerCertificateValidationCallback = 
                (sender, certificate, chain, sslPolicyErrors) => true; // Always return true
        }

        // Rule 14: Key Material in Exception Messages
        public void ExposeKeyInException(string secretKey)
        {
            try
            {
                // Some crypto operation
                throw new InvalidOperationException("Failed with key: " + secretKey);
            }
            catch (Exception ex)
            {
                var errorMsg = $"Crypto error occurred with secret: {secretKey}";
                Console.WriteLine(errorMsg);
                throw new Exception("Key operation failed: " + secretKey, ex);
            }
        }

        // Rule 15: Insecure Key Agreement Protocol
        public void InsecureKeyAgreement()
        {
            using (var ecdh = ECDiffieHellman.Create()) // No authentication
            {
                var publicKey = ecdh.PublicKey;
                // Unauthenticated key agreement
                var sharedSecret = ecdh.DeriveKeyFromHash(publicKey.ExportSubjectPublicKeyInfo(), 
                    HashAlgorithmName.SHA256);
            }
        }

        // Additional vulnerable patterns
        public class WeakCertificateHandler
        {
            public WeakCertificateHandler()
            {
                // Disable certificate validation globally
                ServicePointManager.ServerCertificateValidationCallback += 
                    (sender, cert, chain, errors) => { return true; };
            }
        }

        // Hardcoded certificate
        private string hardcodedCert = @"
-----BEGIN CERTIFICATE-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB
-----END CERTIFICATE-----";
    }

    // Static keys at class level
    public static class GlobalKeys
    {
        public static string MasterKey = "GlobalMasterKey123456789";
        public static readonly byte[] SystemKey = { 0x01, 0x02, 0x03, 0x04 };
    }
}

// Test cases for regex patterns
namespace TestPatterns
{
    public class RegexTestCases
    {
        // Should trigger Rule 1
        string key1 = "-----BEGIN RSA PRIVATE KEY-----";
        string key2 = "-----BEGIN CERTIFICATE-----";
        string key3 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC";

        // Should trigger Rule 2
        string api1 = "apikey = \"sk-1234567890abcdefghijklmnopqrstuvwxyz\"";
        string api2 = "API_KEY: \"live_pk_1234567890abcdefghijklmnop\"";
        string token1 = "access_token = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"";

        // Should trigger Rule 3
        string keyString = "MyEncryptionKey123";
        byte[] keyBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        // Should trigger Rule 6
        static string StaticKey = "StaticValue";
        const string ConstKey = "ConstantValue";
        readonly string ReadonlyKey = "ReadonlyValue";
    }
}
