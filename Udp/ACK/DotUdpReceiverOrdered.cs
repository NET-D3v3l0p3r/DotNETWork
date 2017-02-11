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

namespace DotNETWork.Udp.ACK
{
    //ATTENTION: IN DEVELOPMENT
    public class DotUdpReceiverOrdered
    {
        public IPEndPoint LocalEndPoint;

        public bool KeepAlive;
        /// <summary>
        /// A boolean which determines whether and packet is avaible.
        /// </summary>
        public bool PacketAvaible { get; set; }
        /// <summary>
        /// Holds the thread until it receives an UDP-packet.
        /// </summary>
        public dynamic Packet
        {
            get
            {
                ThreadPool.QueueUserWorkItem(new WaitCallback(pullData), waitHandles[0]);
                WaitHandle.WaitAll(waitHandles);

                List<byte> dataGram = new List<byte>();

                foreach (var _dgram in byteCollector)
                {
                    for (int i = 0; i < _dgram.Value.Length; i++)
                    {
                        dataGram.Add(_dgram.Value[i]);
                    }
                }
                byteCollector = new SortedDictionary<int, byte[]>();

                return dataGram.ToArray().DeserializeToDynamicType();
            }
        }

        private UdpClient udpClient;
        private SortedDictionary<int, byte[]> byteCollector = new SortedDictionary<int, byte[]>();
        private int portNumber;

        private WaitHandle[] waitHandles = new WaitHandle[]
        {
            new AutoResetEvent(false)
        };

        public DotUdpReceiverOrdered(int _port)
        {
            portNumber = _port;
            LocalEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), portNumber);
            PacketAvaible = false;
            udpClient = new UdpClient(LocalEndPoint);
        }

        private void pullData(object resetState)
        {
            AutoResetEvent aReset = (AutoResetEvent)resetState;
            //WAIT FOR INCOMING (GET IP:PORT)
            IPEndPoint remoteEndPoint = udpClient.Receive(ref LocalEndPoint).DeserializeToDynamicType();
            //RECEIVE AMOUNT OF PACKETS
            int packCount = udpClient.Receive(ref LocalEndPoint).DeserializeToDynamicType();

            for (int i = 0; i < packCount; i++)
            {
                //get index
                int packetIndex = BitConverter.ToInt32(udpClient.Receive(ref LocalEndPoint), 0);
                //get dgram[]
                byte[] _dgram = udpClient.Receive(ref LocalEndPoint);
                //add to byte-collector
                byteCollector.Add(packetIndex, _dgram);
            }
            PacketAvaible = true;
            aReset.Set();

        }
    }
}