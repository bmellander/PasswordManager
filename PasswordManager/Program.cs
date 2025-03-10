using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace PasswordManager
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                // Check if any arguments are provided
                if (args.Length == 0)
                {
                    Console.WriteLine("Usage: PasswordManager <command> [<args>]");
                    return;
                }

                string command = args[0].ToLower();

                // Handle different commands
                switch (command)
                {
                    case "init":
                        if (args.Length != 3)
                        {
                            Console.WriteLine("Usage: init <client> <server>");
                            return;
                        }
                        InitCommand(args[1], args[2]);
                        break;

                    case "get":
                        if (args.Length < 3)
                        {
                            Console.WriteLine("Usage: get <client> <server> [<prop>]");
                            return;
                        }
                        string prop = args.Length > 3 ? args[3] : null;
                        GetCommand(args[1], args[2], prop);
                        break;

                    case "set":
                        if (args.Length < 4)
                        {
                            Console.WriteLine("Usage: set <client> <server> <prop> [-g]");
                            return;
                        }
                        bool generate = args.Length > 4 && args[4] == "-g";
                        SetCommand(args[1], args[2], args[3], generate);
                        break;

                    case "delete":
                        if (args.Length < 4)
                        {
                            Console.WriteLine("Usage: delete <client> <server> <prop>");
                            return;
                        }
                        DeleteCommand(args[1], args[2], args[3]);
                        break;

                    case "secret":
                        if (args.Length != 2)
                        {
                            Console.WriteLine("Usage: secret <client>");
                            return;
                        }
                        SecretCommand(args[1]);
                        break;

                    case "change":
                        if (args.Length != 3)
                        {
                            Console.WriteLine("Usage: change <client> <server>");
                            return;
                        }
                        ChangeCommand(args[1], args[2]);
                        break;

                    default:
                        Console.WriteLine("Unknown command.");
                        break;
                }
            }
            catch (CryptographicException)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Incorrect password. Please try again.");
                Console.ResetColor();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Error: {ex.Message}");
                Console.ResetColor();
            }
        }

        // Initializes the password manager by creating client and server data files
        static void InitCommand(string clientPath, string serverPath)
        {
            Console.Write("Enter master password: ");
            string masterPassword = Console.ReadLine();

            // Generate secret key and IV
            byte[] secretKey = GenerateSecretKey();
            byte[] iv = GenerateIV();
            // Derive vault key from master password and secret key
            byte[] vaultKey = DeriveVaultKey(masterPassword, secretKey);

            // Create client and server data
            var clientData = new { Secret = Convert.ToBase64String(secretKey) };
            var serverData = new { IV = Convert.ToBase64String(iv), Vault = EncryptVault("{}", vaultKey, iv) };

            // Write client and server data to files
            File.WriteAllText(clientPath, JsonSerializer.Serialize(clientData));
            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));

            // Output success message and secret key
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Vault initialized successfully.");
            Console.ResetColor();
            Console.WriteLine("Secret Key: " + Convert.ToBase64String(secretKey));
        }

        // Retrieves a property from the vault
        static void GetCommand(string clientPath, string serverPath, string prop)
        {
            Console.Write("Enter master password: ");
            string masterPassword = Console.ReadLine();

            // Read and deserialize client and server data
            var clientData = JsonSerializer.Deserialize<ClientData>(File.ReadAllText(clientPath));
            var serverData = JsonSerializer.Deserialize<ServerData>(File.ReadAllText(serverPath));

            // Derive vault key and decrypt vault
            byte[] vaultKey = DeriveVaultKey(masterPassword, Convert.FromBase64String(clientData.Secret));
            string vaultJson = DecryptVault(serverData.Vault, vaultKey, Convert.FromBase64String(serverData.IV));
            var vault = JsonSerializer.Deserialize<Vault>(vaultJson);

            // Output success message
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Login successful.");
            Console.ResetColor();

            // Output the requested property or list all properties
            if (prop == null)
            {
                foreach (var key in vault.Data.Keys)
                {
                    Console.WriteLine(key);
                }
            }
            else if (vault.Data.ContainsKey(prop))
            {
                Console.WriteLine(vault.Data[prop]);
            }
            else
            {
                Console.WriteLine("Property not found.");
            }
        }

        // Sets a property in the vault
        static void SetCommand(string clientPath, string serverPath, string prop, bool generate)
        {
            Console.Write("Enter master password: ");
            string masterPassword = Console.ReadLine();

            // Read and deserialize client and server data
            var clientData = JsonSerializer.Deserialize<ClientData>(File.ReadAllText(clientPath));
            var serverData = JsonSerializer.Deserialize<ServerData>(File.ReadAllText(serverPath));

            // Derive vault key and decrypt vault
            byte[] vaultKey = DeriveVaultKey(masterPassword, Convert.FromBase64String(clientData.Secret));
            string vaultJson = DecryptVault(serverData.Vault, vaultKey, Convert.FromBase64String(serverData.IV));
            var vault = JsonSerializer.Deserialize<Vault>(vaultJson);

            // Output success message
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Login successful.");
            Console.ResetColor();

            // Generate or prompt for password
            string password;
            if (generate)
            {
                password = GenerateRandomPassword();
                Console.WriteLine("Generated Password: " + password);
            }
            else
            {
                Console.Write("Enter password: ");
                password = Console.ReadLine();
            }

            // Set the property in the vault
            vault.Data[prop] = password;

            // Encrypt and save the updated vault
            serverData.Vault = EncryptVault(JsonSerializer.Serialize(vault), vaultKey, Convert.FromBase64String(serverData.IV));
            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));

            // Output success message
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Password set successfully.");
            Console.ResetColor();
        }

        // Deletes a property from the vault
        static void DeleteCommand(string clientPath, string serverPath, string prop)
        {
            Console.Write("Enter master password: ");
            string masterPassword = Console.ReadLine();

            // Read and deserialize client and server data
            var clientData = JsonSerializer.Deserialize<ClientData>(File.ReadAllText(clientPath));
            var serverData = JsonSerializer.Deserialize<ServerData>(File.ReadAllText(serverPath));

            // Derive vault key and decrypt vault
            byte[] vaultKey = DeriveVaultKey(masterPassword, Convert.FromBase64String(clientData.Secret));
            string vaultJson = DecryptVault(serverData.Vault, vaultKey, Convert.FromBase64String(serverData.IV));
            var vault = JsonSerializer.Deserialize<Vault>(vaultJson);

            // Output success message
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Login successful.");
            Console.ResetColor();

            // Delete the property if it exists
            if (vault.Data.ContainsKey(prop))
            {
                vault.Data.Remove(prop);
                // Encrypt and save the updated vault
                serverData.Vault = EncryptVault(JsonSerializer.Serialize(vault), vaultKey, Convert.FromBase64String(serverData.IV));
                File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Property deleted successfully.");
                Console.ResetColor();
            }
            else
            {
                Console.WriteLine("Property not found.");
            }
        }

        // Displays the secret key from the client data
        static void SecretCommand(string clientPath)
        {
            var clientData = JsonSerializer.Deserialize<ClientData>(File.ReadAllText(clientPath));
            Console.WriteLine("Secret Key: " + clientData.Secret);
        }

        // Changes the master password
        static void ChangeCommand(string clientPath, string serverPath)
        {
            Console.Write("Enter current master password: ");
            string currentPassword = Console.ReadLine();

            // Read and deserialize client and server data
            var clientData = JsonSerializer.Deserialize<ClientData>(File.ReadAllText(clientPath));
            var serverData = JsonSerializer.Deserialize<ServerData>(File.ReadAllText(serverPath));

            // Derive vault key and decrypt vault
            byte[] vaultKey = DeriveVaultKey(currentPassword, Convert.FromBase64String(clientData.Secret));
            string vaultJson = DecryptVault(serverData.Vault, vaultKey, Convert.FromBase64String(serverData.IV));
            var vault = JsonSerializer.Deserialize<Vault>(vaultJson);

            // Output success message
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Login successful.");
            Console.ResetColor();

            // Prompt for new master password
            Console.Write("Enter new master password: ");
            string newPassword = Console.ReadLine();

            // Derive new vault key and encrypt the vault with the new key
            byte[] newVaultKey = DeriveVaultKey(newPassword, Convert.FromBase64String(clientData.Secret));
            serverData.Vault = EncryptVault(JsonSerializer.Serialize(vault), newVaultKey, Convert.FromBase64String(serverData.IV));
            File.WriteAllText(serverPath, JsonSerializer.Serialize(serverData));

            // Output success message
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Master password changed successfully.");
            Console.ResetColor();
        }

        // Generates a random secret key
        static byte[] GenerateSecretKey()
        {
            using var rng = RandomNumberGenerator.Create();
            byte[] secretKey = new byte[32];
            rng.GetBytes(secretKey);
            return secretKey;
        }

        // Generates a random initialization vector (IV)
        static byte[] GenerateIV()
        {
            using var aes = Aes.Create();
            aes.GenerateIV();
            return aes.IV;
        }

        // Derives the vault key from the master password and secret key
        static byte[] DeriveVaultKey(string masterPassword, byte[] secretKey)
        {
            using var deriveBytes = new Rfc2898DeriveBytes(masterPassword, secretKey, 10000, HashAlgorithmName.SHA256);
            return deriveBytes.GetBytes(32);
        }

        // Encrypts the vault data
        static string EncryptVault(string plainText, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
            using var sw = new StreamWriter(cs);
            sw.Write(plainText);
            sw.Close();
            return Convert.ToBase64String(ms.ToArray());
        }

        // Decrypts the vault data
        static string DecryptVault(string cipherText, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor();
            using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }

        // Generates a random password
        static string GenerateRandomPassword()
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, 20).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        // Class to represent client data
        class ClientData
        {
            public string Secret { get; set; }
        }

        // Class to represent server data
        class ServerData
        {
            public string IV { get; set; }
            public string Vault { get; set; }
        }

        // Class to represent the vault
        class Vault
        {
            public Dictionary<string, string> Data { get; set; } = new Dictionary<string, string>();
        }
    }
}
