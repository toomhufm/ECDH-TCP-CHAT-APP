using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Data;
using System.Text;
using System.Security.Cryptography;

namespace Client
{
    class Program
    {
        private static byte[] PublicKey;
        static ECDiffieHellmanCng ecc = new ECDiffieHellmanCng(ECCurve.NamedCurves.nistP256);

        static readonly Dictionary<byte[], string> friend_pk = new Dictionary<byte[], string>();

        static void Help()
        {
            Console.WriteLine("========================== HELP MENU ===============================");
            Console.WriteLine("Use /share to broadcast your Public Key");
            Console.WriteLine("Use /p <friend-name> | <message> to chat in private with your friend");
            Console.WriteLine("Use /o to see who is online");
            Console.WriteLine("====================================================================");
        }

        static void Banner()
        {
            string banner = @"Use /h for available command";
            Console.WriteLine(banner);
        }
        static void Main(string[] args)
        {
            Banner();
            KeyGen();
            Console.WriteLine($"Your Public Key : {Convert.ToHexString(PublicKey)}");
            IPAddress ip = IPAddress.Parse("127.0.0.1");
            int port = 5000;
            TcpClient client = new TcpClient();
            client.Connect(ip, port);
            Console.Write("Enter your name : ");
            string username = Console.ReadLine();
            NetworkStream ns = client.GetStream();
            ns.Write(Encoding.UTF8.GetBytes($"@username|{username}"));
            ns.Flush();
            Console.WriteLine("You connected!!");
            Thread thread = new Thread(o => ReceiveData((TcpClient)o));
            thread.Start(client);
            string s;
            while (!string.IsNullOrEmpty((s = Console.ReadLine())))
            {

                if (s.StartsWith("/p"))
                {
                    try
                    {
                        string[] msg = s.Split('|');
                        string friend_name = msg[0].Split(' ')[1].TrimEnd();
                        byte[] enc = null;
                        EncryptMessage(msg[1], friend_name, out enc);
                        string hex_enc = Convert.ToHexString(enc);
                        string private_msg = $"@private-{friend_name}|{hex_enc}|{friend_name}";
                        //Console.WriteLine(private_msg);
                        byte[] buffer = Encoding.ASCII.GetBytes(private_msg);
                        ns.Write(buffer, 0, buffer.Length);

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                    }

                }
                else if (s.StartsWith("/h"))
                {
                    Help();
                }

                else if (s.StartsWith("/share"))
                {
                    BroadCastPublicKey(PublicKey,client);
                    Console.WriteLine("[NOTI] Shared your public key");
                }
                else if (s.StartsWith("/o"))
                {
                    ShowFriend();
                }

                else
                {
                    byte[] buffer = Encoding.ASCII.GetBytes($"#{username}|{s}");
                    ns.Write(buffer, 0, buffer.Length);
                }
            }

            client.Client.Shutdown(SocketShutdown.Send);
            thread.Join();
            ns.Close();
            client.Close();
            Console.WriteLine("disconnect from server!!");
            Console.ReadKey();
        }

        static void ReceiveData(TcpClient client)
        {
            NetworkStream ns = client.GetStream();
            byte[] receivedBytes = new byte[2048];
            int byte_count;
            while ((byte_count = ns.Read(receivedBytes, 0, receivedBytes.Length)) > 0)
            {
                string msg = (Encoding.ASCII.GetString(receivedBytes, 0, byte_count));
                if (msg.Contains("connected"))
                {
                    Console.WriteLine($"[New Comer] : {msg}");
                }
                else if (msg.StartsWith("@publickey"))
                {
                    string[] split = msg.Split('|');
                    byte[] fpk = ToByteArray(split[1]);
                    string friend_name = split[2];
                    friend_pk.Add(fpk, friend_name.TrimEnd());
                }
                else if (msg.StartsWith("@private"))
                {
                    try
                    {
                        string[] split = msg.Split('|');
                        string friend_name = split[2].Trim();
                        string message = split[1].Trim();
                        byte[] cipher = ToByteArray(message);
                        DecryptMessage(cipher, friend_name);

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);  
                    }
                }
                else
                {
                    string[] msg_split = msg.Split('|');
                    Console.WriteLine($"[GLOBAL][FROM {msg_split[0]} ] : {msg_split[1]}");
                }
            }
        }


        static void EncryptMessage(string msg, string receiver, out byte[] encrypted_msg)
        {

            using (Aes aes = new AesCryptoServiceProvider())
            {
                byte[] _keyBlob = GetFriendKey(receiver);
                CngKey receiver_pk = CngKey.Import(_keyBlob, CngKeyBlobFormat.EccPublicBlob);
                byte[] shared_secret = ecc.DeriveKeyMaterial(receiver_pk);

                aes.Key = shared_secret;
                aes.IV = Encoding.ASCII.GetBytes("bQeThWmZq4t6w9z$");

                // Encrypt the message
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(msg);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encrypted_msg = ciphertext.ToArray();
                }
            }
        }

        static void DecryptMessage(byte[] ciphertext, string sender)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                byte[] _keyBlob = GetFriendKey(sender);
                CngKey sender_pk = CngKey.Import(_keyBlob, CngKeyBlobFormat.EccPublicBlob);
                byte[] shared_secret = ecc.DeriveKeyMaterial(sender_pk);
                aes.Key = shared_secret;
                aes.IV = Encoding.ASCII.GetBytes("bQeThWmZq4t6w9z$");
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(ciphertext, 0, ciphertext.Length);
                        cs.Close();
                        string message = Encoding.UTF8.GetString(plaintext.ToArray());
                        Console.WriteLine($"[PRIVATE][FROM {sender}] : {message}");
                    }
                }
            }
        }

        static void KeyGen()
        {
            ecc.HashAlgorithm = CngAlgorithm.Sha256;
            ecc.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
            PublicKey = ecc.PublicKey.ToByteArray();
        }

        static void BroadCastPublicKey(byte[] PublicKey, TcpClient self)
        {
            NetworkStream ns = self.GetStream();
            string msg = $"@publickey|{Convert.ToHexString(PublicKey)}";
            byte[] buffer = Encoding.ASCII.GetBytes(msg);
            ns.Write(buffer, 0, buffer.Length);
        }
        static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }

        static void ShowFriend()
        {
            Console.WriteLine("Online list : ");
            foreach(byte[] pk in friend_pk.Keys)
            {
                Console.WriteLine(friend_pk[pk]);
                Console.WriteLine(Convert.ToHexString(GetFriendKey(friend_pk[pk])));
            }
        }

        static byte[] GetFriendKey(string name)
        {
            name.TrimEnd();
            foreach (byte[] pk in friend_pk.Keys)
            {
                if (friend_pk[pk].Contains(name))
                {
                    //Console.WriteLine($"Found {name} Public Key ");
                    return pk;
                }
            }
            Console.WriteLine("Public Key Not Found");
            return null;
        }
    }
}