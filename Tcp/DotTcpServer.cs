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
        private int clientCounter;

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
            Console.WriteLine("          (To copy , run server in cmd)"  );
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
                    var acceptedClient = tcpListener.AcceptTcpClient();
                    if (clientCounter != MaximumClients)
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
                            System.Windows.Forms.MessageBox.Show("[DotNETWork ~StartSession] Fatal server error.." + Environment.NewLine + "Message: " + ex.Message, "Message", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error, System.Windows.Forms.MessageBoxDefaultButton.Button2, System.Windows.Forms.MessageBoxOptions.ServiceNotification, false);
                            break;
                        }
                        #endregion

                        #region "Direct client"
                        string connectionMode = inClient.BinReader.ReadString();
                        if (connectionMode.Split('=')[1].Equals("DIRECT"))
                        {
                            string userId = inClient.BinReader.ReadString();
                            inClient.UserID = userId;
                            inClient.BinWriter.Write(AllowDirectConnect);
                            inClient.BinWriter.Write(ClientList.Count(p => p.UserID != null));

                            for (int i = 0; i < ClientList.Count; i++)
                            {
                                inClient.BinWriter.Write(ClientList[i].UserID);
                                inClient.BinWriter.Write(ClientList[i].PublicKeyXML);
                            }

                        }
                        #endregion


                        ClientList.Add(inClient);
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("---USER_ADDED---");
                        Console.ForegroundColor = ConsoleColor.Gray;

                        #endregion
                        new Thread(new ParameterizedThreadStart((object @object) =>
                        {
                            T threadClient = (T)@object;
                            clientCounter++;

                            while (threadClient.TcpClient.Connected)
                            {
                                if (threadClient.UserID != null)
                                {
                                    // ...
                                    Console.WriteLine(Receive(threadClient.BinReader).DeserializeToDynamicType());
                                }
                                else
                                    threadClient.Call((object)this);
                                new ManualResetEvent(false).WaitOne(1);
                            }

                        })).Start((object)ClientList[ClientList.Count - 1]);

                    }
                }
            });

            listenerThread.Start();
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
                System.Windows.Forms.MessageBox.Show("[DotNETWork ~Receive] Fatal server error.." + Environment.NewLine + "Message: " + ex.Message, "Message", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error, System.Windows.Forms.MessageBoxDefaultButton.Button2, System.Windows.Forms.MessageBoxOptions.ServiceNotification, false);
                return null;
            }
        }

    }
}
