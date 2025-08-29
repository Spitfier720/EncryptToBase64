using System.Security.Cryptography;

public class Program
{
    public static void Main(string[] args)
    {
        try
        {
            string inputFile = args[0];
            string password = args[1];
            string encryptOrDecrpyt = args[2].Trim().ToLower() == "decrypt" ? "decrypt" : "encrypt";

            byte[] keyBytes;
            byte[] IV;

            using (var pbkdf2 = new Rfc2898DeriveBytes(password, System.Text.Encoding.UTF8.GetBytes(password), 10000, HashAlgorithmName.SHA256))
            {
                keyBytes = pbkdf2.GetBytes(32);
                IV = pbkdf2.GetBytes(16);
            }

            if (encryptOrDecrpyt == "encrypt")
            {
                byte[] input = System.IO.File.ReadAllBytes(inputFile);
                byte[] encrypted = EncryptStringToBytes_Aes(System.Text.Encoding.UTF8.GetString(input), keyBytes, IV);

                string base64String = Convert.ToBase64String(encrypted);
                System.IO.File.WriteAllText(inputFile + ".enc.txt", base64String);
                System.Console.WriteLine("Encrypted file written to " + inputFile + ".enc.txt");
            }
            else
            {
                string base64 = System.IO.File.ReadAllText(inputFile);
                byte[] input = Convert.FromBase64String(base64);

                string decrypted = DecryptStringFromBytes_Aes(input, keyBytes, IV);

                string base64String = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(decrypted));
                System.IO.File.WriteAllText(inputFile + ".dec.txt", decrypted);
                System.Console.WriteLine("Decrypted text.");
            }
        }
        catch (System.IndexOutOfRangeException)
        {
            System.Console.WriteLine("Usage: EncryptToBase64 <inputFile> <key> <\"encrypt\"/\"decrypt\">");
            return;
        }
    }

    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
    {
        byte[] encrypted;

        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            aesAlg.Mode = CipherMode.CBC;

            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption. 
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    encrypted = msEncrypt.ToArray();
                }
            }
        }

        return encrypted;

    }

    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
    {

        // Declare the string used to hold 
        // the decrypted text. 
        string plaintext = null;

        // Create an Aes object 
        // with the specified key and IV. 
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Key;
            aesAlg.IV = IV;

            aesAlg.Mode = CipherMode.CBC;

            // Create a decrytor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption. 
            using (var msDecrypt = new MemoryStream(cipherText))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }

        }

        return plaintext;

    }
}