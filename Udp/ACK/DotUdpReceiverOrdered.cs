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
        public dynamic Packet { get; private set; }


        private UdpClient udpClient;
        private SortedDictionary<int, byte[]> byteCollector = new SortedDictionary<int, byte[]>();
        private int portNumber;

        public DotUdpReceiverOrdered(int _port)
        {
            portNumber = _port;
            LocalEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), portNumber);
            KeepAlive = true;
            udpClient = new UdpClient(LocalEndPoint);

            pullData();
        }

        private void pullData()
        {
            Task.Run(() =>
            {
                while (KeepAlive)
                {
                    try
                    {
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

                        List<byte> dataGram = new List<byte>();


                        for (int j = 0; j < byteCollector.Count; j++)
                        {
                            var bytes = byteCollector.Values.ElementAt(j);
                            for (int i = 0; i < bytes.Length; i++)
                            {
                                dataGram.Add(bytes[i]);
                            }
                        }


                        byteCollector = new SortedDictionary<int, byte[]>();

                        Packet = dataGram.ToArray().DeserializeToDynamicType();
                    }
                    catch
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("DROP PACKAGE!");
                        Console.ForegroundColor = ConsoleColor.Gray;
                    }
                }
            });
        }
        public void ClearCache()
        {
            byteCollector.Clear();
            Packet = null;
        }
    }
}