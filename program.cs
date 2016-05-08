using System;
using Microsoft.AspNet.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;

namespace ConsoleApp1
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("*******************************");
            Console.WriteLine("        Password Hasher        ");
            Console.WriteLine("*******************************");
            
            Console.Write(Environment.NewLine);
            Console.WriteLine($"Random Salt: {GenerateSalt()}");
            Console.Write(Environment.NewLine);
            
            Console.Write("Password: ");
            var password = Console.ReadLine();
            Console.Write("Salt: ");
            var salt = Console.ReadLine();
            
            var hashedPassword = HashPassword(password, salt);
            Console.Write(Environment.NewLine);
            Console.WriteLine($"Hashed Password: {hashedPassword}");
        }
        
        public static string GenerateSalt()
        {
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return Convert.ToBase64String(salt);
        }

        public static string HashPassword(string password, string salt)
        {
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: password,
                salt: Encoding.Unicode.GetBytes(salt),
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return hashed;
        }
    }
}