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

namespace DotNETWork.Tcp.P2P
{
    public class Mediator
    {
        public IPEndPoint LocalEndPoint { get; private set; }
        public int MaxClients { get; set; }

        public List<Client> ConnectedPeers { get; private set; }
        public bool KeepAlive { get; set; }

        public DotRijndaelDecryption RijndaelDecryption { get; private set; }

        public string Signature { get; private set; }
        public string Keyset { get; private set; }

        private Socket serverSocket;

        public Mediator(int port, string encryptionString)
        {
            LocalEndPoint = new IPEndPoint(IPAddress.Any, port);

            serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            serverSocket.Bind(LocalEndPoint);

            ConnectedPeers = new List<Client>();

            Keyset = encryptionString;
            RijndaelDecryption = new DotRijndaelDecryption(Keyset);
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

        }

        public void Run()
        {
            KeepAlive = true;
            new Thread(new ThreadStart(() =>
            {

                serverSocket.Listen(1);
                while (KeepAlive)
                {
                    var incomingClient = serverSocket.Accept();

                    Client client = new Client(incomingClient);

                    client.BinWriter.Write("OK");
                    client.BinWriter.Write(RijndaelDecryption.GetPublicKeyXML());

                    new Thread(new ParameterizedThreadStart((inClient) =>
                    {
                        Client newClient = (Client)inClient;
                        while (newClient.Socket.Connected)
                        {
                            string command = newClient.BinReader.ReadString();

                            if (command.ToUpper().Contains("REQUEST_PEER"))
                            {
                                string id = command.Split('=')[1];
                                for (int i = 0; i < ConnectedPeers.Count; i++)
                                {
                                    Client peer = ConnectedPeers[i];

                                    if (peer.Id.Equals(id.ToUpper()))
                                    {
                                        peer.SendEndPointToPeer(newClient);
                                        newClient.SendEndPointToPeer(peer);
                                        break;
                                    }
                                }
                            }else if (command.ToUpper().Contains("REQUEST_LIST"))
                            {
                                StringBuilder sb = new StringBuilder();

                                for (int i = 0; i < ConnectedPeers.Count; i++)
                                {
                                    if (!ConnectedPeers[i].Id.Equals(newClient.Id))
                                        sb.Append(ConnectedPeers[i].Id + Environment.NewLine);
                                }

                                newClient.BinWriter.Write(sb.ToString());
                            }
                        }
                    })).Start(client);

                    
                    ConnectedPeers.Add(client);

                }

            })).Start();
        }

    }
}
