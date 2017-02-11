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
    public class Client
    {
        public string Id { get; set; }
        
        public BinaryReader BinReader { get; set; }
        public BinaryWriter BinWriter { get; set; }

        public Socket Socket { get; set; }

        public Client(Socket socket)
        {
            Socket = socket;

            BinReader = new BinaryReader(new NetworkStream(Socket));
            BinWriter = new BinaryWriter(new NetworkStream(Socket));

            Id = BinReader.ReadString().ToUpper();
        }

        public void SendEndPointToPeer(Client otherPeer)
        {
            otherPeer.BinWriter.Write("RUN=TCPHP");
            otherPeer.BinWriter.Write(Socket.RemoteEndPoint + "");
        }

    }
}
