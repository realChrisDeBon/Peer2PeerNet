using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using UnverifiedConnection = (System.Net.IPAddress address, string message); // Alias for unverified connections that must be passed from HandshakeProtocol to validation pipeline
using System.Text;
using Peer2Peer;
using System.Collections.Concurrent;
using Newtonsoft.Json;
using Microsoft.VisualBasic;
using System.Text.Json.Serialization;

namespace Peer2Peer
{

    public class Peer2PeerNet
    {
        HandshakeHandler HandshakeHandler_;
        EncryptionHandler EncryptionHandler_;
        ConnectionHandler ConnectionHandler_;

        public List<IPAddress> current_connections = new List<IPAddress>();
        public Queue<UnverifiedConnection> unverified_connections = new Queue<UnverifiedConnection>();

        public bool print_activity = true;


        public void Start(int handshake_port = 80, string handshake_msg = "P2P_HANDSHAKE", string handshake_reply = "P2P_HANDSHAKE_OK", bool begin_handshake = true, string key_path = null, List<IPAddress> starting_connection = null, string alias = "John Doe")
        {
            HandshakeHandler_ = new HandshakeHandler(this, 80, handshake_msg, handshake_reply); // Initialize HandshakeHandler
            ConnectionHandler_ = new ConnectionHandler(this);
            if (starting_connection != null)
            {
                foreach(IPAddress address in starting_connection)
                {
                    try
                    {
                        ConnectionHandler_.AddConnection(address);

                    }
                    catch
                    {
                        MsgOut($"Could not add default connection: {address.ToString()}");
                    }
                }
            }
            EncryptionHandler_ = new EncryptionHandler(this, key_path); // Default key is null and results in new key being generated
            if (begin_handshake == true)
            {
                Thread unverifiedConnectionsThread = new Thread(HandleUnverifiedConnections);
                unverifiedConnectionsThread.Start();
            }

        }

        private void HandleUnverifiedConnections()

        {
            while (true)
            {
                if (unverified_connections.Count > 0)
                {
                    UnverifiedConnection connection = unverified_connections.Dequeue();
                    string decryptedMessage = DecryptStr(connection.message);

                    if (HandshakeHandler_.valid_reply(decryptedMessage) == true)
                    {
                        IPAddress address = connection.address;
                        TcpClient client = new TcpClient();
                        client.Connect(address, 8888); // Or whatever port you need

                        // Add the connected IP to current_connections
                        current_connections.Add(address);

                        // Further logic for handling the trusted connection (NetworkStream, etc.)
                        // ...
                    }
                }
                else
                {
                    Thread.Sleep(100); // Sleep briefly if no connections to process
                }
            }
        }

        public string DecryptStr(string encryptedmsg_)
        {
            return EncryptionHandler_.Decrypt(encryptedmsg_);
        }

        public string EncryptStr(string unencryptedmsg_)
        {
            return EncryptionHandler_.Encrypt(unencryptedmsg_);
        }

        public void MsgOut(string msg_)
        {
            if (print_activity == true)
            {
                Console.WriteLine(msg_);
            }
        }

    }


    public class ConnectionHandler
    {
        public Peer2PeerNet p2pnet; // reference to top-level Peer2Peer class
        public ServerSide _localServer; // Local server for handling incoming connections


        // Constructor (to pass the Peer2PeerNet instance)
        public ConnectionHandler(Peer2PeerNet p2pnet)
        {
            this.p2pnet = p2pnet;
            _localServer = new ServerSide();
        }

        public async Task StartLocalServer()
        {
            await _localServer.Start();
        }

        public void AddConnection(IPAddress ipAddress)
        {
            TcpClient tcpClient = new TcpClient();
            tcpClient.Connect(ipAddress, 8888);

            ClientHandler clientHandler = new ClientHandler(tcpClient, _localServer);
            _localServer.clients.Add(clientHandler);

            Thread clientThread = new Thread(clientHandler.HandleClient);
            clientThread.Start();

            // TODO: Handle the new connection as needed
        }

        public void RemoveConnection(IPAddress ipAddress)
        {
           
        }

        public async Task BroadcastMsg(string message)
        {
            _localServer.BroadcastMessageAsync(message);
        }


        private string GetLocalIPAddress()
        {
            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "IP Address Not Found";
        }
    }


    public class EncryptionHandler
    {
        public Peer2PeerNet p2pnet; // reference to top-level Peer2Peer class
        private byte[] sharedKey;

        public EncryptionHandler(Peer2PeerNet top, string keypath = null, byte[] sharedKey = null)
        {
            if (keypath != null)
            {
                try
                {
                    if (File.Exists(keypath))
                    {
                        sharedKey = LoadKeyFromFile(keypath);
                    } else
                    {
                        p2pnet.MsgOut($"{keypath} not a valid filepath.\nGenerating new key.");
                    }
                } catch
                {

                }
            }

            if (sharedKey != null)
            {
                this.sharedKey = sharedKey;
                this.p2pnet = top;
            }
            else
            {
                // generate a new random AES key
                using (var rng = RandomNumberGenerator.Create())
                {
                    this.sharedKey = new byte[32];
                    rng.GetBytes(this.sharedKey);
                }
            }
        }

        public string Encrypt(string textToEncrypt)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = sharedKey;
                aes.GenerateIV(); // generate a new random IV for each encryption

                ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] plainText = Encoding.UTF8.GetBytes(textToEncrypt);
                byte[] cipherText = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);

                // Combine IV and ciphertext for easier transmission
                byte[] combined = aes.IV.Concat(cipherText).ToArray();
                return Convert.ToBase64String(combined);
            }
        }

        public string Decrypt(string base64EncryptedText)
        {
            byte[] combined = Convert.FromBase64String(base64EncryptedText);
            using (var aes = Aes.Create())
            {
                aes.Key = sharedKey;

                // Extract IV and ciphertext
                byte[] iv = combined.Take(aes.BlockSize / 8).ToArray();
                byte[] cipherText = combined.Skip(aes.BlockSize / 8).ToArray();

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, iv);
                byte[] plainText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                return Encoding.UTF8.GetString(plainText);
            }
        }

        public void SaveKeyToFile(string filePath)
        {

            string fileExtension = ".key"; // Suitable file extension for storing cryptographic keys

            string fullFilePath = Path.Combine(filePath, Path.GetRandomFileName() + fileExtension);

            try
            {
                using (var fileStream = new FileStream(fullFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fileStream.Write(this.sharedKey, 0, this.sharedKey.Length);
                }

                try
                {
                    File.Encrypt(fullFilePath);
                }
                catch (Exception ex)
                {
                    p2pnet.MsgOut("Warning: Failed to apply DPAPI encryption."); // DPAPI error
                }

            }
            catch (Exception ex)
            {
                p2pnet.MsgOut("Error saving key to file.");
            }
        }
        public byte[] LoadKeyFromFile(string filePath)
        {
            try
            {
                try
                {
                    File.Decrypt(filePath); // Attempt to decrypt
                }
                catch (Exception ex)
                {
                    p2pnet.MsgOut("Warning: Failed to remove DPAPI encryption."); // DPAPI error
                }

                // Read the key from the file 
                byte[] key;

                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    key = new byte[fileStream.Length];
                    fileStream.Read(key, 0, key.Length);
                }

                return key;
            }
            catch (Exception ex)
            {
                // Handle file access or key loading exceptions
                p2pnet.MsgOut("Error loading key from file.");
                return null; 
            }
        }

    }


    public class HandshakeHandler
    {
        public enum HandshakeProtocolSpread
        {
            Chronological,
            Multithread
        }

        public Peer2PeerNet p2pnet; // reference to top-level Peer2Peer class

        private string HANDSHAKE_MESSAGE { get; set; }
        private string HANDSHAKE_REPLY { get; set; }
        private int HANDSHAKE_PORT { get; set; }

        private UdpClient _udpSender;
        private UdpClient _udpListener;

        public HandshakeHandler(Peer2PeerNet p2pnetref_, int HandshakeProtocolPort = 80, string HandshakeMessage = "P2P_HANDSHAKE", string HandshakeReply = "P2P_HANDSHAKE_OK")
        {

            _udpSender = new UdpClient();
            _udpSender.EnableBroadcast = true; // Enable broadcast if needed

            _udpListener = new UdpClient(HANDSHAKE_PORT);
            this.p2pnet = p2pnetref_;

        }

        public void StartHandshake()
        {
            new Thread(SendHandshakeMessages).Start();
            new Thread(ListenForReplies).Start();
        }

        // PROTOTYPE METHOD - Flinging spaghetti, seeing what sticks as we seek peers
        // SUBJECT TO CHANGE OR REFACTOR
        private void SendHandshakeMessages()
        {
            for (int a = 1; a < 256; a++)
            {
                for (int b = 1; b < 256; b++)
                {
                    for (int c = 1; c < 256; c++)
                    {
                        for (int d = 1; d < 256; d++)
                        {
                            IPAddress targetIP = IPAddress.Parse($"{a}.{b}.{c}.{d}"); // Example local IP range
                            try
                            {
                                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(HANDSHAKE_MESSAGE);
                                _udpSender.Send(messageBytes, messageBytes.Length, new IPEndPoint(targetIP, HANDSHAKE_PORT));
                            }
                            catch
                            {
                                p2pnet.MsgOut($"Bad send: {a}.{b}.{c}.{d}\t");
                            }
#if DEBUG
                            Thread.Sleep(10); // small delay between messages
                            Console.Write($"{a}.{b}.{c}.{d}\t"); 
#endif
                        }
                    }
                }
            }
        }

        private void ListenForReplies()
        {
            while (true)
            {
                IPEndPoint remoteEP = null;
                byte[] receivedBytes = _udpListener.Receive(ref remoteEP);
                string receivedMessage = System.Text.Encoding.UTF8.GetString(receivedBytes);

                
                if (p2pnet.current_connections.Contains(remoteEP.Address)) // If connection already exists, do nothing
                {
                    p2pnet.MsgOut("Peer already verified: " + remoteEP.Address);
                }
                else
                {
                    UnverifiedConnection new_connection = new UnverifiedConnection(remoteEP.Address, receivedMessage); // New unverified connection
                    p2pnet.unverified_connections.Enqueue(new_connection); // IPAddress and received message passed to network queue
                    p2pnet.MsgOut("Potential peer: " + remoteEP.Address);
                }
            }
        }

        public bool valid_reply(string decrypted_string)
        {
            if (decrypted_string == HANDSHAKE_REPLY)
            {
                return true; // decrypted string matches - trusted
            }
            else
            {
                return false; // decrypted string matches - untrusted
            }
        }
    }


    // TCP Client and Listener (Server) classes for ConnectionHandler
    // These  classes handle the TCP network stream between verified
    // peer connections.
    #region TCP Net Code

    [Serializable]
    public class ChatMessage
    {
        public string Alias { get; set; }
        public string Content { get; set; }
    }

    public class ServerSide
    {
        private TcpListener server;
        public List<ClientHandler> clients;

        public ServerSide()
        {
            server = new TcpListener(IPAddress.Any, 8888);
            clients = new List<ClientHandler>();
        }

        public async Task Start()
        {
            server.Start(); // Start TCPListener
            while(true)
            {
                TcpClient newClient = await server.AcceptTcpClientAsync();
                ClientHandler newClientHandler = new ClientHandler(newClient, this); 
                clients.Add(newClientHandler);

                Thread clientThread = new Thread(newClientHandler.HandleClient);
                clientThread.Start();
            }
        }

        public async Task BroadcastMessageAsync(string message)
        {
            Console.WriteLine("Broadcasting message: " + message);

            foreach (var client in clients)
            {
                client.SendMessage(message);
            }
        }

    }
    public class ClientHandler
    {
        private TcpClient client;
        private ServerSide server;
        private NetworkStream stream;

        public ClientHandler(TcpClient client, ServerSide server)
        {
            this.client = client;
            this.server = server;
            stream = client.GetStream();
        }

        private async Task<string> ReadMessageAsync()
        {
            byte[] buffer = new byte[4096];
            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
            return Encoding.UTF8.GetString(buffer, 0, bytesRead);
        }

        public async void HandleClient()
        {
            while (true)
            {
                try
                {
                    string message = await ReadMessageAsync();
                    Console.WriteLine("Received message: " + message);
                    ChatMessage newmsg = JsonConvert.DeserializeObject<ChatMessage>(message);
                    // Process the received message
                    string MessageToSend = ($"{newmsg.Alias}: {newmsg.Content}");
                    await server.BroadcastMessageAsync(MessageToSend);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error reading message from client: " + ex.Message);
                    break;
                }
            }
        }

        public async void SendMessage(string message)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(message);
            await stream.WriteAsync(buffer, 0, buffer.Length);
        }
    }
    public class ClientSide
    {
        private TcpClient client;
        public void Start(string ipaddress)
        {

            client = new TcpClient();
            client.Connect(ipaddress, 8888);
            NetworkStream stream = client.GetStream();

            // Start a new thread to handle incoming messages from the server
            Thread receiveThread = new Thread(ReceiveMessages);
            receiveThread.Start();

        }

        private void SendMessage(string alias_, string content_)
        {
            ChatMessage chatMessage = new ChatMessage
            {
                Alias = alias_,
                Content = content_
            };

            // Serialize the ChatMessage to JSON
            string jsonMessage = JsonConvert.SerializeObject(chatMessage);

            // Send the JSON message to the server
            byte[] buffer = Encoding.UTF8.GetBytes(jsonMessage);
            NetworkStream stream = client.GetStream();
            stream.Write(buffer, 0, buffer.Length);
            stream.Flush();
        }

        private void ReceiveMessages()
        {
            NetworkStream stream = client.GetStream();

            while (true)
            {
                byte[] buffer = new byte[client.ReceiveBufferSize];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                try
                {
                   // Process the regular chat message
                   Console.WriteLine(message);
                    
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Error deserializing JSON: " + ex.Message);
                }
            }
        }

    }

    #endregion
}