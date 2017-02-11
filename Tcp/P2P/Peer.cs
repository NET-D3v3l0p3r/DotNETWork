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

namespace DotNETWork.Tcp.P2P
{
    public class Peer
    {
        public IPEndPoint MediatorIPEndPoint { get; set; }
        public string MediatorSignature { get; set; }

        public bool IsConnected { get; private set; }

        public string Id { get; set; }

        public Client AcceptedPeer{ get; private set; }

        public bool OperationIsRunning { get; private set; }


        private Socket puncherSocket, connectorSocket, acceptorSocket;
        private IPEndPoint localEndPoint, remoteEndPoint;

        private BinaryReader inReader;
        private BinaryWriter inWriter;

        private int openedPort;
        private bool isReady;

        public Peer(IPEndPoint mediator)
        {
            MediatorIPEndPoint = mediator;

            puncherSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            connectorSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            acceptorSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            connectorSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            acceptorSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            try
            {
                connectorSocket.Connect(mediator);
                localEndPoint = (IPEndPoint)connectorSocket.LocalEndPoint;

                // VERIFIY

                inWriter = new BinaryWriter(new NetworkStream(connectorSocket));
                inReader = new BinaryReader(new NetworkStream(connectorSocket));

                if (!inReader.ReadString().ToUpper().Equals("OK"))
                    throw new Exception("INVALID MEDIATOR!" + Environment.NewLine + "REQUESTED OK");

                string verificationXML = inReader.ReadString();

                if (!MediatorSignature.Equals(Utilities.GetMD5Hash(verificationXML)))
                {
                    MessageBox.Show("Attention: The hash of the received Public-Key-XML is not equivalent to the verification hash:" + Environment.NewLine +
                        "Verification hash: " + MediatorSignature + Environment.NewLine +
                        "Received hash: " + Utilities.GetMD5Hash(verificationXML) + Environment.NewLine +
                        "The XML is probably corrupt which is common in MITM-Attacks." + Environment.NewLine +
                        "The connection will be closed immadiatly!", "Warning!", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly, false);

                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[*]CONNECTION LOST DUE CORRUPT KEY EXCEPTION!");
                    connectorSocket.Close();
                    inWriter.Close();
                    inReader.Close();
                    throw new DotTcpException("CORRUPT KEY EXCEPTION");
                }

                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("READY.");
                Console.ForegroundColor = ConsoleColor.Gray;

                isReady = true;
            }
            catch
            {
                throw new Exception("MEDIATOR DOES NOT RESPOND!");
            }
        }


        public void StartP2P(string id)
        {

            inWriter.Write("REQUEST_PEER=" + id);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("WAITING FOR REQUEST.");
            Console.ForegroundColor = ConsoleColor.Gray;

            while (connectorSocket.Connected)
            {
                string signal = inReader.ReadString();
                if (signal.ToUpper().Contains("RUN=TCPHP"))
                {
                    string incoming = inReader.ReadString();
                    remoteEndPoint = new IPEndPoint(IPAddress.Parse(incoming.Split(':')[0]), int.Parse(incoming.Split(':')[1]));
                }
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("INITIALIZING.");
            Console.ForegroundColor = ConsoleColor.Gray;

            connectorSocket.Close();
            connectorSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            connectorSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OPENING NAT.");
            Console.ForegroundColor = ConsoleColor.Gray;

            openedPort = puncherSocket.SendSYN(new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port)).Port;

            Thread punchingThread = new Thread(new ThreadStart(() =>
            {
                for (int i = -10; i < 10; i++)
                {
                    if (remoteEndPoint.Port + i == openedPort)
                        continue;
                    try
                    {
                        Console.ForegroundColor = ConsoleColor.Blue;
                        Console.WriteLine("ATTEMPTING!");
                        Console.ForegroundColor = ConsoleColor.Gray;

                        connectorSocket.Connect(new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port + i));

                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("CLIENT CONNECTED!");
                        Console.ForegroundColor = ConsoleColor.Gray;

                        AcceptedPeer = new Client(connectorSocket);

                        break;
                    }
                    catch
                    {

                    }
                }
            }));

            punchingThread.Start();

            acceptorSocket.Bind(new IPEndPoint(localEndPoint.Address, openedPort));
            acceptorSocket.Listen(1);

            while (true)
            {
                var acceptedClient = acceptorSocket.Accept();
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("CLIENT RECEIVED!");
                Console.ForegroundColor = ConsoleColor.Gray;

                AcceptedPeer = new Client(acceptedClient);

                break;
            }

        }


        public IEnumerator<string> GetActivePeers()
        {
            inWriter.Write("REQUEST_LIST");

            string rawList = inReader.ReadString();
            string[] users = rawList.Split(new string[] { Environment.NewLine }, StringSplitOptions.None);

            for (int i = 0; i < users.Length; i++)
            {
                yield return users[i];
            }
        }

        public void SetSignature(string hash)
        {
            MediatorSignature = hash;
        }
    }
}
