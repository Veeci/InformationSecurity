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
    }
}