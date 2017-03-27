using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Net;
using System.Net.Sockets;

using System.Threading;

using System.Diagnostics;

using System.IO;
using DotNETWork.Globals;
using DotNETWork.Security;
using System.Windows.Forms;

namespace DotNETWork.Tcp
{
    public class DotTcpClient
    {
        public string ServerName { get; private set; }

        public IPEndPoint LocalEndpoint { get; private set; }
        public IPEndPoint RemoteEndPoint { get; set; }

        public delegate void OnConnectedDelegate();
        public event OnConnectedDelegate OnConnected;

        public string Keyset { get; private set; }
        public string ID { get; private set; }

        public bool IsConnected { get; private set; }

        public bool DirectConnectionAllowed { get; private set; }
        public Dictionary<string, string> UserKeyPair { get; private set; }

        public bool OperationRunning { get; private set; }

        private Socket specialClient;
        private Socket socketClient;

        private BinaryReader specialReader;
        private Thread dequeueThread;

        private BinaryReader binReader;
        private BinaryWriter binWriter;

        private DotRijndaelEncryption rjindaelEncryption;
        private DotRijndaelDecryption rijndaelDecryption;

        private string verificationHash = "";

        private static object SYNC = new object();

        public DotTcpClient(string remoteIp, int remotePort, string encryptionString, string username)
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse(remoteIp), remotePort);
            Keyset = encryptionString;
            ID = username;

            UserKeyPair = new Dictionary<string, string>();
        }


        /// <summary>
        /// Chaning parameter verify to false increases the security lack!
        /// </summary>
        /// <param name="ms"></param>
        /// <param name="verify"></param>
        /// <returns></returns>
        public Exception StartSession(int ms, string pass, bool verify = true)
        {
            if (string.IsNullOrWhiteSpace(verificationHash))
                return new Exception("An verification hash must be set!");

            specialClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            socketClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IAsyncResult asyncResult = socketClient.BeginConnect(RemoteEndPoint.Address.MapToIPv4(), RemoteEndPoint.Port, null, null);
            bool connectionStatus = asyncResult.AsyncWaitHandle.WaitOne(ms);
            if (!connectionStatus)
                return new DotTcpException("NO CONNECTION");

            socketClient.EndConnect(asyncResult);

            LocalEndpoint = (IPEndPoint)socketClient.LocalEndPoint;

            binReader = new BinaryReader(new NetworkStream(socketClient));
            binWriter = new BinaryWriter(new NetworkStream(socketClient));


            // INFORM CONNECTION MODE

            // TRY TO GET PUBLIC KEY
            // AND INSTANCIATE RIJNADELENCRYPTION

            byte[] receivedDataDecrypted = new byte[0];
            int dataLength = binReader.ReadInt32();
            receivedDataDecrypted = binReader.ReadBytes(dataLength);

            string inputXML = receivedDataDecrypted.DeserializeToDynamicType();
            // VERIFY PUBLIC KEY HTML

            if (verify && !verificationHash.Equals(Utilities.GetMD5Hash(inputXML)))
            {
                MessageBox.Show("Attention: The hash of the received Public-Key-XML is not equivalent to the verification hash:" + Environment.NewLine +
                    "Verification hash: " + verificationHash + Environment.NewLine +
                    "Received hash: " + Utilities.GetMD5Hash(inputXML) + Environment.NewLine +
                    "The XML is probably corrupt which is common in MITM-Attacks." + Environment.NewLine +
                    "The connection will be closed immadiatly!", "Warning!", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly, false);

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[*]CONNECTION LOST DUE CORRUPT KEY EXCEPTION!");
                socketClient.Close();
                binReader.Close();
                binWriter.Close();
                return new DotTcpException("CORRUPT KEY EXCEPTION");
            }

            rjindaelEncryption = new DotRijndaelEncryption(inputXML);

            // SEND OWN CREATED PUBLIC KEY
            // TO SERVER.
            rijndaelDecryption = new DotRijndaelDecryption(Keyset);
            rijndaelDecryption.SendPublicKeyXML(binWriter);


            ServerName = binReader.ReadString();


            bool passwordRequired = binReader.ReadBoolean();
            if (passwordRequired)
            {
                binWriter.Write(pass);
                string responsePass = binReader.ReadString();
                if (responsePass.Equals("INVALID_PASSWORD"))
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("INVALID PASSWORD");
                    Console.ForegroundColor = ConsoleColor.Gray;
                    return new DotUserException("INVALID PASSWORD");
                }
            }


            binWriter.Write(ID);
            string response = binReader.ReadString();
            if (response.Equals("INVALID_USERNAME"))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("USERNAME ALREADY EXISTS");
                Console.ForegroundColor = ConsoleColor.Gray;
                return new DotUserException("USERNAME ALREADY EXISTS");
            }

            bool requestState = binReader.ReadBoolean();

            DirectConnectionAllowed = requestState;
            if (DirectConnectionAllowed)
            {
                int activeUsers = binReader.ReadInt32();

                // RECEIVE PUBLIC KEYS OF USERS

                for (int i = 0; i < activeUsers; i++)
                {
                    // READ USER_ID
                    string userId = binReader.ReadString();

                    // READ PUBLIC KEY
                    string publicKeyXML = binReader.ReadString();

                    // FINALLY ADD TO DICTIONARY

                    UserKeyPair.Add(userId, publicKeyXML);

                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("ADDED " + UserKeyPair.Count + " KEY(S)");
                Console.ForegroundColor = ConsoleColor.Gray;
            }

            specialClient.Connect(new IPEndPoint(RemoteEndPoint.Address.MapToIPv4(), RemoteEndPoint.Port + 1));
            specialReader = new BinaryReader(new NetworkStream(specialClient));

            OnConnected?.Invoke();
            IsConnected = true;

            Task.Run(() =>
            {
                while (IsConnected)
                {
                    string s = specialReader.ReadString();
                    OperationRunning = !s.Equals("READY");
                }
            });


            return null;
        }


        public void SetVerificationHash(string hash)
        {
            verificationHash = hash;
        }

        public void Send(object inputData)
        {
            Task.Run(() =>
            {
                lock (SYNC)
                {
                    while (OperationRunning) { }

                    OperationRunning = true;
                    var byteBuffer = inputData.SerializeToByteArray();
                    var encryptedBuffer = rjindaelEncryption.EncryptStream(byteBuffer);
                    binWriter.Write(encryptedBuffer.Length);
                    binWriter.Write(encryptedBuffer);
                }

            });

        }

        public Exception SendDirect(object inputData, string toUser)
        {
            if (!DirectConnectionAllowed)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("NO PRIVILIGES TO DO THIS!");
                Console.ForegroundColor = ConsoleColor.Gray;
                return new DotTcpException("NO PRIVILIGES");
            }
            if (!UserKeyPair.ContainsKey(toUser))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("USER " + toUser + " DOES NOT EXIST (YET) !");
                Console.ForegroundColor = ConsoleColor.Gray;
                return new DotUserException("USER DOES NOT EXIST");
            }
            try
            {
                var encryptedBuffer = rjindaelEncryption.EncryptStream("DIRECT_USER".SerializeToByteArray());
                binWriter.Write(encryptedBuffer.Length);
                binWriter.Write(encryptedBuffer);

                encryptedBuffer = rjindaelEncryption.EncryptStream(toUser.SerializeToByteArray());
                binWriter.Write(encryptedBuffer.Length);
                binWriter.Write(encryptedBuffer);

                var message = inputData.SerializeToByteArray();
                DotRijndaelEncryption rijndaelEncryptionAnon = new DotRijndaelEncryption(UserKeyPair[toUser]);
                encryptedBuffer = rijndaelEncryptionAnon.EncryptStream(message);
                var encrypted = rjindaelEncryption.EncryptStream(encryptedBuffer);
                binWriter.Write(encrypted.Length);
                binWriter.Write(encrypted);
                return null;
            }
            catch
            {
                return new DotTcpException("NO CONNECTION");
            }
        }
        // Blue

        public async Task<bool> SendAsync(object inputData)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var byteBuffer = inputData.SerializeToByteArray();
                    //binWriter.Write(byteBuffer.Length);
                    //binWriter.Write(byteBuffer);
                    var decryptedBuffer = rjindaelEncryption.EncryptStream(byteBuffer);
                    binWriter.Write(decryptedBuffer.Length);
                    binWriter.Write(decryptedBuffer);
                    return true;
                }
                catch
                {
                    return false;
                }
            });
        }

        public dynamic Receive()
        {
            try
            {
                byte[] receivedDataEncrypted = new byte[0];
                int dataLength = binReader.ReadInt32();
                receivedDataEncrypted = binReader.ReadBytes(dataLength);
                byte[] receivedDataDecrypted = rijndaelDecryption.DecryptStream(receivedDataEncrypted);
                var data = receivedDataDecrypted.DeserializeToDynamicType();

                if (DirectConnectionAllowed && data is string)
                {
                    string s = (string)data;
                    if (s.Equals("DIRECT_CONFIG"))
                    {
                        string userID = Receive();
                        string xml = Receive();

                        UserKeyPair.Add(userID, xml);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("ADDED 1 KEY(S)");
                        Console.ForegroundColor = ConsoleColor.Gray;
                        return new DotUserException("JOINED=" + userID);
                    }
                    else if (s.Equals("REMOVE_USER"))
                    {
                        string userID = Receive();
                        UserKeyPair.Remove(userID);
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("REMOVED 1 KEY(S)");
                        Console.ForegroundColor = ConsoleColor.Gray;
                        return new DotUserException("LEFT=" + userID);
                    }
                }

                if(data is string)
                {
                    string s = (string)data;
                    if(s.Equals("CONNECTION_CLOSED"))
                    {
                        IsConnected = false;
                        return null;
                    }
                }

                return data;
            }
            catch
            {
                return false;
            }
        }


        public async Task<dynamic> ReceiveAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    byte[] receivedDataEncrypted = new byte[0];
                    int dataLength = binReader.ReadInt32();
                    receivedDataEncrypted = binReader.ReadBytes(dataLength);
                    byte[] receivedDataDecrypted = rijndaelDecryption.DecryptStream(receivedDataEncrypted);
                    return receivedDataDecrypted.DeserializeToDynamicType();
                }
                catch
                {
                    return false;
                }
            });
        }

        public void Close()
        {
            socketClient.Close();
        }



    }
}
