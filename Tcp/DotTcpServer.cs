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
namespace DotNETWork.Tcp
{
    public class DotTcpServer<T> where T : IClient, new()
    {
        public IPEndPoint LocalIPEndPoint { get; private set; }
        public List<T> ClientList { get; private set; }

        public bool IsActive;

        private TcpListener tcpListener;
        private Thread listenerThread;

        public DotTcpServer(int portNumber)
        {
            LocalIPEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), portNumber);
            tcpListener = new TcpListener(LocalIPEndPoint);

            ClientList = new List<T>();
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

                    ClientList.Add(new T()
                    {
                        TcpClient = acceptedClient,
                        BinReader = new BinaryReader(acceptedClient.GetStream()),
                        BinWriter = new BinaryWriter(acceptedClient.GetStream()),
                        ClientEndPoint = new IPEndPoint(IPAddress.Parse(acceptedClient.Client.RemoteEndPoint.ToString().Split(':')[0]), int.Parse(acceptedClient.Client.RemoteEndPoint.ToString().Split(':')[1]))
                    });

                    new Thread(new ParameterizedThreadStart((object @object) =>
                    {
                        T threadClient = (T)@object;

                        while (threadClient.TcpClient.Connected)
                        {
                            threadClient.Call((object)this);
                        }

                    })).Start((object)ClientList[ClientList.Count - 1]);

                }

            });

            listenerThread.Start();
        }



    }
}
