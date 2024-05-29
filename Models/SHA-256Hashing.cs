using System;
using System.Security.Cryptography;
using System.Text;

namespace EmployeeManagementWebsite.Models
{
    public class SHA256Hashing
    {
        // Generate a random salt
        public static byte[] GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[16]; // 128-bit salt
                rng.GetBytes(salt);
                return salt;
            }
        }

        // Hash the password with the provided salt
        public static byte[] HashPassword(string password, byte[] salt)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] passwordWithSaltBytes = new byte[passwordBytes.Length + salt.Length];

                Buffer.BlockCopy(salt, 0, passwordWithSaltBytes, 0, salt.Length);
                Buffer.BlockCopy(passwordBytes, 0, passwordWithSaltBytes, salt.Length, passwordBytes.Length);

                return sha256.ComputeHash(passwordWithSaltBytes);
            }
        }

        // Combine salt and hashed password for storage
        public static byte[] CombineSaltAndHash(byte[] salt, byte[] hash)
        {
            byte[] combinedBytes = new byte[salt.Length + hash.Length];
            Buffer.BlockCopy(salt, 0, combinedBytes, 0, salt.Length);
            Buffer.BlockCopy(hash, 0, combinedBytes, salt.Length, hash.Length);
            return combinedBytes;
        }

        // Extract salt from the stored combined salt and hash
        public static byte[] ExtractSalt(byte[] storedHash)
        {
            byte[] salt = new byte[16];
            Buffer.BlockCopy(storedHash, 0, salt, 0, salt.Length);
            return salt;
        }

        // Extract hash from the stored combined salt and hash
        public static byte[] ExtractHash(byte[] storedHash)
        {
            byte[] hash = new byte[storedHash.Length - 16];
            Buffer.BlockCopy(storedHash, 16, hash, 0, hash.Length);
            return hash;
        }
    }
}
