using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Data;
using System.Text;
using System.Security.Cryptography;

namespace Server
{

    class Program
    {
        private static void Banner()
        {
            string banner = @"
            =========================================================================
            =                            ECDH DEMOSTRATION                          =
            =========================================================================
            ";
            Console.WriteLine(banner);
        }

        static readonly object _lock = new object();
        static readonly Dictionary<int, TcpClient> list_clients = new Dictionary<int, TcpClient>();
        static readonly Dictionary<TcpClient,string> clients_name = new Dictionary<TcpClient,string>();
        static readonly Dictionary<TcpClient,byte[]> clients_pk = new Dictionary<TcpClient,byte[]>();
        static void Main(string[] args)
        {
            int count = 1;
            Banner();
            TcpListener ServerSocket = new TcpListener(IPAddress.Any, 5000);
            ServerSocket.Start();

            while (true)
            {
                TcpClient client = ServerSocket.AcceptTcpClient();
                lock (_lock) list_clients.Add(count, client);

                Thread t = new Thread(handle_clients);
                t.Start(count);
                count++;
            }
        }

        public static void handle_clients(object o)
        {
            int id = (int)o;
            TcpClient client;

            lock (_lock) client = list_clients[id];
            System.Net.ServicePointManager.Expect100Continue = false;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            while (true)
            {
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[1024];
                int byte_count = stream.Read(buffer, 0, buffer.Length);

                if (byte_count == 0)
                {
                    break;
                }

                string data = Encoding.ASCII.GetString(buffer, 0, byte_count);
                if (data.StartsWith("@username"))
                {
                    string username = data.Split('|')[1];
                    clients_name.Add(client, username);
                    broadcast($"{username} connected", client);
                    Console.WriteLine($"{username} connected");
                }

                else if (data.StartsWith("@private"))
                {
                    string[] split = data.Split('|');
                    string name = split[2];
                    string msg = split[1];
                    privateChat(msg,name,client);
                }

                else if (data.StartsWith("@publickey"))
                {
                    string pk = data.Split('|')[1];
                    byte[] PublicKey = ToByteArray(pk);
                    clients_pk.Add(client, PublicKey);
                    broadcast(data + $"|{clients_name[client]}", client);
                }
                else
                {
                    broadcast(data,client);
                    Console.WriteLine(data);

                }
            }

            lock (_lock) list_clients.Remove(id);
            client.Client.Shutdown(SocketShutdown.Both);
            client.Close();
        }

        public static void broadcast(string data, Object client)
        {
            byte[] buffer = Encoding.ASCII.GetBytes(data + Environment.NewLine);

            lock (_lock)
            {
                foreach (TcpClient c in list_clients.Values)
                {
                    if(c != client)
                    {
                        NetworkStream stream = c.GetStream();

                        stream.Write(buffer, 0, buffer.Length);
                    }
                }
            }
        }

        public static void privateChat(string msg, string receiver_name, TcpClient sender)
        {
            string sender_name = clients_name[sender];
            msg = $"@private|{msg}|{sender_name}";
            foreach(TcpClient c in clients_name.Keys)
            {
                if(clients_name[c] == receiver_name)
                {
                    byte[] buffer = Encoding.ASCII.GetBytes(msg);
                    NetworkStream stream = c.GetStream();
                    stream.Write(buffer, 0, buffer.Length);
                    Console.WriteLine(msg);
                }
            }
        }
        public static byte[] ToByteArray(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }
    }
}