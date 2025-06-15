using System;
using System.Security.Cryptography;
using System.Text;
using System.Net;

namespace VulnerableCryptoExamples
{
    public class WeakCryptographyExamples
    {
        // VULNERABLE: MD5 Usage
        public string HashWithMD5(string input)
        {
            using (var md5 = MD5.Create()) // Rule: Weak Hash Algorithm - MD5
            {
                byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hash);
            }
        }

        // VULNERABLE: SHA1 Usage
        public string HashWithSHA1(string input)
        {
            using (var sha1 = SHA1.Create()) // Rule: Weak Hash Algorithm - SHA1
            {
                byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hash);
            }
        }

        // VULNERABLE: Alternative MD5 Usage
        public string AlternateMD5(string input)
        {
            var md5Provider = new MD5CryptoServiceProvider(); // Rule: Weak Hash Algorithm - MD5
            byte[] hash = md5Provider.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Convert.ToBase64String(hash);
        }

        // VULNERABLE: DES Encryption
        public byte[] EncryptWithDES(byte[] data, byte[] key)
        {
            using (var des = DES.Create()) // Rule: Weak Symmetric Encryption - DES
            {
                des.Key = key;
                des.Mode = CipherMode.ECB; // Rule: ECB Mode Usage
                using (var encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // VULNERABLE: 3DES/TripleDES Usage
        public byte[] EncryptWithTripleDES(byte[] data)
        {
            using (var tripleDes = TripleDES.Create()) // Rule: Weak Symmetric Encryption - 3DES/TripleDES
            {
                // VULNERABLE: Hardcoded key
                tripleDes.Key = Convert.FromBase64String("AAAAAAAAAAAAAAAAAAAAAA=="); // Rule: Hardcoded Cryptographic Keys
                tripleDes.Mode = CipherMode.ECB; // Rule: ECB Mode Usage
                using (var encryptor = tripleDes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // VULNERABLE: RC2 Encryption
        public byte[] EncryptWithRC2(byte[] data)
        {
            using (var rc2 = RC2.Create()) // Rule: Weak Symmetric Encryption - RC2
            {
                rc2.Key = Encoding.UTF8.GetBytes("weakkey123456789");
                using (var encryptor = rc2.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        // VULNERABLE: Weak RSA Key Size
        public RSA CreateWeakRSAKey()
        {
            var rsa = RSA.Create();
            rsa.KeySize = 1024; // Rule: Weak Key Size - RSA
            return rsa;
        }

        // VULNERABLE: Alternative weak RSA
        public RSACryptoServiceProvider CreateWeakRSAProvider()
        {
            return new RSACryptoServiceProvider(512); // Rule: Weak Key Size - RSA
        }

        // VULNERABLE: Insecure Random Number Generation
        public byte[] GenerateRandomBytes(int length)
        {
            var random = new Random(); // Rule: Insecure Random Number Generation
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++)
            {
                bytes[i] = (byte)random.Next(256);
            }
            return bytes;
        }

        // VULNERABLE: Weak AES Key Size
        public Aes CreateWeakAES()
        {
            var aes = Aes.Create();
            aes.KeySize = 128; // Rule: Weak AES Key Size
            aes.Mode = CipherMode.ECB; // Rule: ECB Mode Usage
            return aes;
        }

        // VULNERABLE: Hardcoded encryption with weak settings
        public string EncryptPassword(string password)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 192; // Rule: Weak AES Key Size
                aes.Key = Convert.FromBase64String("MTIzNDU2NzgxMjM0NTY3ODEyMzQ1Njc4MTIzNDU2Nzg="); // Rule: Hardcoded Cryptographic Keys
                aes.IV = Convert.FromBase64String("MTIzNDU2NzgxMjM0NTY3OA=="); // Rule: Hardcoded Cryptographic Keys
                aes.Mode = CipherMode.ECB; // Rule: ECB Mode Usage

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                    byte[] encrypted = encryptor.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);
                    return Convert.ToBase64String(encrypted);
                }
            }
        }

        // VULNERABLE: Weak PBKDF2 Iterations
        public byte[] DeriveKeyFromPassword(string password, byte[] salt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 1000); // Rule: Weak PBKDF2 Iterations
            return pbkdf2.GetBytes(32);
        }

        // VULNERABLE: Multiple weak crypto issues
        public string WeakPasswordHashing(string password)
        {
            // VULNERABLE: Insecure random for salt
            var random = new Random(); // Rule: Insecure Random Number Generation
            byte[] salt = new byte[8];
            for (int i = 0; i < salt.Length; i++)
            {
                salt[i] = (byte)random.Next(256);
            }

            // VULNERABLE: Weak iterations
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100); // Rule: Weak PBKDF2 Iterations
            byte[] hash = pbkdf2.GetBytes(20);

            // VULNERABLE: Additional MD5 hash
            using (var md5 = new MD5CryptoServiceProvider()) // Rule: Weak Hash Algorithm - MD5
            {
                byte[] finalHash = md5.ComputeHash(hash);
                return Convert.ToBase64String(finalHash);
            }
        }

        // VULNERABLE: Insecure SSL/TLS Configuration
        public void ConfigureInsecureSSL()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3; // Rule: Insecure SSL/TLS Protocols
            // Alternative vulnerable configurations:
            // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls; // Rule: Insecure SSL/TLS Protocols
            // ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11; // Rule: Insecure SSL/TLS Protocols
        }

        // VULNERABLE: Hash algorithm created by string
        public string HashWithStringAlgorithm(string input)
        {
            using (var hash = HashAlgorithm.Create("MD5")) // Rule: Weak Hash Algorithm - MD5
            {
                byte[] hashBytes = hash.ComputeHash(Encoding.UTF8.GetBytes(input));
                return Convert.ToBase64String(hashBytes);
            }
        }

        // VULNERABLE: Symmetric algorithm created by string
        public byte[] EncryptWithStringAlgorithm(byte[] data)
        {
            using (var des = SymmetricAlgorithm.Create("DES")) // Rule: Weak Symmetric Encryption - DES
            {
                des.Key = Encoding.UTF8.GetBytes("12345678");
                using (var encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }
    }

    // Additional vulnerable class with different patterns
    public class MoreVulnerableExamples
    {
        // VULNERABLE: Direct instantiation patterns
        private readonly MD5 _md5Hash = new MD5CryptoServiceProvider(); // Rule: Weak Hash Algorithm - MD5
        private readonly SHA1 _sha1Hash = new SHA1CryptoServiceProvider(); // Rule: Weak Hash Algorithm - SHA1
        private readonly DES _desAlgorithm = new DESCryptoServiceProvider(); // Rule: Weak Symmetric Encryption - DES

        // VULNERABLE: Method with hardcoded values
        public void ProcessSensitiveData()
        {
            string secretKey = "MyHardcodedSecretKey123!"; // Rule: Hardcoded Cryptographic Keys
            string iv = "1234567890123456"; // Rule: Hardcoded Cryptographic Keys
            
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128; // Rule: Weak AES Key Size
                aes.Key = Encoding.UTF8.GetBytes(secretKey);
                aes.IV = Encoding.UTF8.GetBytes(iv);
                aes.Mode = CipherMode.ECB; // Rule: ECB Mode Usage
            }
        }
    }
}
