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
    public class DotTcpServer<T> where T : IClient, new()
    {
        public object Owner { get; set; }

        public string ServerName { get; set; }
        public string Password { get; set; }

 
        public IPEndPoint LocalIPEndPoint { get; private set; }
        public List<T> ClientList { get; private set; }

        public int MaximumClients { get; set; }
        public bool IsActive;

        public string Signature { get; private set; }

        public bool AllowDirectConnect { get; set; }

        public string Keyset { get; private set; }

        private Socket socketListener;
        private Socket serverCommunication;

        private Thread listenerThread;

        public DotRijndaelDecryption RijndaelDecryption;

        public DotTcpServer(string name, int portNumber, string encryptionString)
        {
            ServerName = name;

            LocalIPEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), portNumber);

            socketListener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socketListener.Bind(LocalIPEndPoint);

            serverCommunication = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverCommunication.Bind(new IPEndPoint(LocalIPEndPoint.Address.MapToIPv4(), portNumber + 1));

            ClientList = new List<T>();

            Keyset = encryptionString;

            RijndaelDecryption = new DotRijndaelDecryption(Keyset);
            RijndaelDecryption.ExportCertificate(name, "Certificate_" + name);
            MessageBox.Show(
@"Certificate saved in application directory.
Send it to an certificate-server administrator to verify Your identiy!", "Information", MessageBoxButtons.OK, MessageBoxIcon.Information);

            Signature = Utilities.GetMD5Hash(RijndaelDecryption.GetPublicKeyXML());

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("#################################################");
            Console.WriteLine("       IMPORTANT: SIGNATURE FOR PUBLIC KEY");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(" " + Signature);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("          (To copy , run server in cmd)");
            Console.WriteLine("#################################################");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Gray;

            Clipboard.SetText(Signature);
        }

        public void StartSession(string path_to_certificate, string pass)
        {
            IsActive = true;
            Password = pass;

            listenerThread = new Thread(() =>
            {
                socketListener.Listen(2147483647);
                serverCommunication.Listen(2147483647);

                while (IsActive)
                {
                    bool isInvalid = false;
                    var acceptedSocket = socketListener.Accept();
                    if (ClientList.Count != MaximumClients)
                    {

                        #region "Initializing T"
                        T inClient = new T()
                        {
                            Socket = acceptedSocket,
                            BinReader = new BinaryReader(new NetworkStream(acceptedSocket)),
                            BinWriter = new BinaryWriter(new NetworkStream(acceptedSocket)),
                            ClientEndPoint = new IPEndPoint(IPAddress.Parse(acceptedSocket.RemoteEndPoint.ToString().Split(':')[0]), int.Parse(acceptedSocket.RemoteEndPoint.ToString().Split(':')[1]))
                        };

                        #region "Send verification"
                        RijndaelDecryption.SendCertificate(path_to_certificate, inClient.BinWriter);
                        try
                        {
                            int publicKeyLength = inClient.BinReader.ReadInt32();
                            inClient.PublicKeyXML = inClient.BinReader.ReadBytes(publicKeyLength).DeserializeToDynamicType();
                            inClient.DotRijndaelEncryption = new DotRijndaelEncryption(inClient.PublicKeyXML);
                        }
                        catch (Exception ex)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("[*] INVALID CERTIFICAE!");
                            Console.ForegroundColor = ConsoleColor.Gray;
                            isInvalid = true;
                        }
                        #endregion
                        if (isInvalid)
                            continue;
                        #region "Direct client"

                        inClient.BinWriter.Write(ServerName);

                        inClient.BinWriter.Write(!String.IsNullOrEmpty(Password));
                        if (!String.IsNullOrEmpty(Password))
                        {
                            string userPass = inClient.BinReader.ReadString();

                            if (!userPass.Equals(Password))
                            {
                                inClient.BinWriter.Write("INVALID_PASSWORD");
                                continue;
                            }
                            else inClient.BinWriter.Write("SUCEED");
                        }

                        string userId = inClient.BinReader.ReadString();
                        if (ClientList.Exists(p => p.UserID.Equals(userId)))
                        {

                            inClient.BinWriter.Write("INVALID_USERNAME");
                            continue;
                        }

                        inClient.BinWriter.Write("SUCCEED");


                        inClient.UserID = userId;
                        inClient.BinWriter.Write(AllowDirectConnect);
                        if (AllowDirectConnect)
                        {
                            inClient.BinWriter.Write(ClientList.Count(p => p.UserID != inClient.UserID));

                            for (int i = 0; i < ClientList.Count; i++)
                            {
                                inClient.BinWriter.Write(ClientList[i].UserID);
                                inClient.BinWriter.Write(ClientList[i].PublicKeyXML);
                            }

                            for (int i = 0; i < ClientList.Count; i++)
                            {
                                var client = ClientList[i];

                                DotRijndaelEncryption rEncryptor = new DotRijndaelEncryption(client.PublicKeyXML);

                                var encBytes = rEncryptor.EncryptStream("DIRECT_CONFIG".SerializeToByteArray());

                                client.BinWriter.Write(encBytes.Length);
                                client.BinWriter.Write(encBytes);

                                encBytes = rEncryptor.EncryptStream(inClient.UserID.SerializeToByteArray());

                                client.BinWriter.Write(encBytes.Length);
                                client.BinWriter.Write(encBytes);

                                encBytes = rEncryptor.EncryptStream(inClient.PublicKeyXML.SerializeToByteArray());

                                client.BinWriter.Write(encBytes.Length);
                                client.BinWriter.Write(encBytes);

                            }
                        }

                        inClient.ServerCommunicationSocket = serverCommunication.Accept();

                        #endregion

                        ClientList.Add(inClient);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[*] USER " + inClient.UserID + " ADDED!");
                        Console.ForegroundColor = ConsoleColor.Gray;

                        #endregion
                        new Thread(new ParameterizedThreadStart((object @object) =>
                        {
                            T threadClient = (T)@object;

                            BinaryWriter specialWriter = new BinaryWriter(new NetworkStream(threadClient.ServerCommunicationSocket));

                            while (threadClient.Socket.Connected)
                            {
                                byte[] decrypted = Receive(threadClient.BinReader);
                                if (decrypted == null)
                                    continue;
                                var temp = decrypted.DeserializeToDynamicType();
                                if (AllowDirectConnect && temp is string)
                                {
                                    string s = (string)temp;
                                    if (s.Equals("DIRECT_USER"))
                                    {
                                        string toUser = Receive(threadClient.BinReader).DeserializeToDynamicType();
                                        var toClient = ClientList.Find(p => p.UserID.Equals(toUser));

                                        byte[] message = Receive(threadClient.BinReader);

                                        toClient.BinWriter.Write(message.Length);
                                        toClient.BinWriter.Write(message);
                                    }
                                    else
                                    {
                                        threadClient.Triggered = true;
                                        threadClient.Call<T>(this, decrypted);
                                        threadClient.Triggered = false;
                                    }
                                }
                                else
                                {
                                    threadClient.Triggered = true;
                                    threadClient.Call<T>(this, decrypted);
                                    threadClient.Triggered = false;

                                    specialWriter.Write("READY");


                                }
                                new ManualResetEvent(false).WaitOne(1);
                            }

                        })).Start((object)ClientList[ClientList.Count - 1]);

                    }
                }
            });
            listenerThread.Start();


            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[*] LISTENING ON " + LocalIPEndPoint);
            Console.ForegroundColor = ConsoleColor.Gray;
        }

        public byte[] Receive(BinaryReader binReader)
        {
            try
            {
                int length = binReader.ReadInt32();
                byte[] decryptedBuffer = RijndaelDecryption.DecryptStream(binReader.ReadBytes(length));
                return decryptedBuffer;
            }
            catch (Exception ex)
            {
                //System.Windows.Forms.MessageBox.Show("[DotNETWork ~Receive] Fatal server error.." + Environment.NewLine + "Message: " + ex.Message, "Message", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error, System.Windows.Forms.MessageBoxDefaultButton.Button2, System.Windows.Forms.MessageBoxOptions.ServiceNotification, false);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[*] USER " + ClientList.Find(p => p.BinReader.Equals(binReader)).UserID + " REMOVED!");
                Console.ForegroundColor = ConsoleColor.Gray;

                if (AllowDirectConnect)
                    for (int i = 0; i < ClientList.Count; i++)
                    {
                        var client = ClientList[i];
                        if (!client.UserID.Equals(ClientList.Find(p => p.BinReader.Equals(binReader)).UserID))
                        {
                            DotRijndaelEncryption rEncryptor = new DotRijndaelEncryption(client.PublicKeyXML);

                            var encBytes = rEncryptor.EncryptStream("REMOVE_USER".SerializeToByteArray());

                            client.BinWriter.Write(encBytes.Length);
                            client.BinWriter.Write(encBytes);

                            encBytes = rEncryptor.EncryptStream(ClientList.Find(p => p.BinReader.Equals(binReader)).UserID.SerializeToByteArray());

                            client.BinWriter.Write(encBytes.Length);
                            client.BinWriter.Write(encBytes);
                        }
                    }

                ClientList.Remove(ClientList.Find(p => p.BinReader.Equals(binReader)));

                return null;
            }
        }

        public void SendToAllClients(IClient host, byte[] decrypted)
        {
            if (!host.Triggered)
                return;
            foreach (var client in ClientList)
            {
                if (!client.PublicKeyXML.Equals(host.PublicKeyXML))
                    client.Call<T>(this, decrypted);

            }
        }

        public void Remove(string id)
        {
            ClientList[ClientList.FindIndex(p => p.UserID.Equals(id))].BinWriter.WriteEncrypted("CONNECTION_CLOSED", ClientList[ClientList.FindIndex(p => p.UserID.Equals(id))]);
            ClientList[ClientList.FindIndex(p => p.UserID.Equals(id))].Socket.Close();   
        }

    }
}
