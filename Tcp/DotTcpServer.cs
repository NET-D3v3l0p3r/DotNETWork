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
        public IPEndPoint LocalIPEndPoint { get; private set; }
        public List<T> ClientList { get; private set; }

        public int MaximumClients { get; set; }
        public bool IsActive;

        public bool AllowDirectConnect { get; set; }

        public string Keyset { get; private set; }

        private TcpListener tcpListener;
        private Thread listenerThread;

        public DotRijndaelDecryption RijndaelDecryption;

        public DotTcpServer(int portNumber, string encryptionString)
        {
            LocalIPEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), portNumber);
            tcpListener = new TcpListener(LocalIPEndPoint);

            ClientList = new List<T>();

            Keyset = encryptionString;

            RijndaelDecryption = new DotRijndaelDecryption(Keyset);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("#################################################");
            Console.WriteLine("       IMPORTANT: SIGNATURE FOR PUBLIC KEY");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(" " + Utilities.GetMD5Hash(RijndaelDecryption.GetPublicKeyXML()));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("          (To copy , run server in cmd)");
            Console.WriteLine("#################################################");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Gray;
        }

        public void StartSession()
        {
            IsActive = true;
            listenerThread = new Thread(() =>
            {
                tcpListener.Start();
                while (IsActive)
                {
                    bool isInvalid = false;
                    var acceptedClient = tcpListener.AcceptTcpClient();
                    if (ClientList.Count != MaximumClients)
                    {

                        #region "Initializing T"
                        T inClient = new T()
                        {
                            TcpClient = acceptedClient,
                            BinReader = new BinaryReader(acceptedClient.GetStream()),
                            BinWriter = new BinaryWriter(acceptedClient.GetStream()),
                            ClientEndPoint = new IPEndPoint(IPAddress.Parse(acceptedClient.Client.RemoteEndPoint.ToString().Split(':')[0]), int.Parse(acceptedClient.Client.RemoteEndPoint.ToString().Split(':')[1]))
                        };

                        #region "Send verification"
                        RijndaelDecryption.SendPublicKeyXML(inClient.BinWriter);
                        try
                        {
                            int publicKeyLength = inClient.BinReader.ReadInt32();
                            inClient.PublicKeyXML = inClient.BinReader.ReadBytes(publicKeyLength).DeserializeToDynamicType();
                        }
                        catch (Exception ex)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("[*] INVALID HASH!");
                            Console.ForegroundColor = ConsoleColor.Gray;
                            isInvalid = true;
                        }
                        #endregion
                        if (isInvalid)
                            continue;
                        #region "Direct client"

                        string userId = inClient.BinReader.ReadString();
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

                        #endregion

                        ClientList.Add(inClient);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("[*] USER " + inClient.UserID + " ADDED!");
                        Console.ForegroundColor = ConsoleColor.Gray;

                        #endregion
                        new Thread(new ParameterizedThreadStart((object @object) =>
                        {
                            T threadClient = (T)@object;
                            while (threadClient.TcpClient.Connected)
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
                                        threadClient.Call((object)this, decrypted);
                                }
                                else
                                    threadClient.Call((object)this, decrypted);
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

    }
}
