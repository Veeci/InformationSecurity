using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

public static class SHA256Hashing
{
    public static byte[] Hash(string input)
    {
        using (var sha256 = SHA256.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            return sha256.ComputeHash(inputBytes);
        }
    }

    /*
    public static bool VerifyHash(string input, byte[] storedHash)
    {
        byte[] inputHash = Hash(input);
        return inputHash.SequenceEqual(storedHash);
    }
    */
}