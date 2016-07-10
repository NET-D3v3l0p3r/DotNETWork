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
namespace DotNETWork.Tcp
{
    public class DotTcpServer<T> where T : IClient, new()
    {
        public IPEndPoint LocalIPEndPoint { get; private set; }
        public List<T> ClientList { get; private set; }

        public int MaximumClients { get; set; }
        public bool IsActive;

        private TcpListener tcpListener;
        private Thread listenerThread;
        private int clientCounter;

        public DotRijndaelDecryption RijndaelDecryption;

        public DotTcpServer(int portNumber)
        {
            LocalIPEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), portNumber);
            tcpListener = new TcpListener(LocalIPEndPoint);

            ClientList = new List<T>();

            RijndaelDecryption = new DotRijndaelDecryption();
        }

        public void Run()
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
                        T inClient = new T()
                        {
                            TcpClient = acceptedClient,
                            BinReader = new BinaryReader(acceptedClient.GetStream()),
                            BinWriter = new BinaryWriter(acceptedClient.GetStream()),
                            ClientEndPoint = new IPEndPoint(IPAddress.Parse(acceptedClient.Client.RemoteEndPoint.ToString().Split(':')[0]), int.Parse(acceptedClient.Client.RemoteEndPoint.ToString().Split(':')[1]))
                        };

                        RijndaelDecryption.SendPublicKeyXML(inClient.BinWriter);

                        int publicKeyLength = inClient.BinReader.ReadInt32();
                        inClient.PublicKeyXML = inClient.BinReader.ReadBytes(publicKeyLength).DeserializeToDynamicType();

                        Console.WriteLine("[SERVER] Received public key!");

                        ClientList.Add(inClient);

                        new Thread(new ParameterizedThreadStart((object @object) =>
                        {
                            T threadClient = (T)@object;

                            ClientParameters<T> clientParams = new ClientParameters<T>();
                            clientParams.ServerHandler = this;

                            DotRijndaelEncryption rEncryptor = new DotRijndaelEncryption(threadClient.PublicKeyXML);

                            clientCounter++;

                            while (threadClient.TcpClient.Connected)
                            {

                                clientParams.DecryptedBytes = ForceReading(threadClient.BinReader);

                                threadClient.Call((object)clientParams);
                                new ManualResetEvent(false).WaitOne(1);
                            }

                        })).Start((object)ClientList[ClientList.Count - 1]);

                    }
                }
            });

            listenerThread.Start();
        }


        public byte[] ForceReading(BinaryReader binReader)
        {
            int length = binReader.ReadInt32();
            byte[] decryptedBuffer = RijndaelDecryption.DecryptStream(binReader.ReadBytes(length));
            return decryptedBuffer;
        }

    }
}
