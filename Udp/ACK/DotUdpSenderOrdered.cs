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
    public class DotUdpSenderOrdered
    {
        public IPEndPoint LocalEndPoint;
        /// <summary>
        /// Maximal datagram[] size.
        /// <para>&#160;</para>
        /// Default value = 64 kb (64000 bytes) 
        /// </summary>
        public int MaximalDatagramSize { get; set; } // 32000 bytes default value

        private UdpClient udpClient;
        public DotUdpSenderOrdered()
        {
            LocalEndPoint = new IPEndPoint(Utilities.GetLocalIPv4(), Utilities.Random.Next(2000, 10000));
            MaximalDatagramSize = 64000;
            udpClient = new UdpClient(LocalEndPoint);

        }

        /// <summary>
        ///  Sends an object to an other udp-client bind on a specified socket.
        ///  <para>&#160;</para>
        ///  Important: Configure sendInterval -value (default: 20)
        /// </summary>
        /// <param name="_datagram"></param>
        public void SendDatagram(object inputData, IPEndPoint remoteIp, int sendInterval)
        {
            udpClient.Send(LocalEndPoint.SerializeToByteArray(), LocalEndPoint.SerializeToByteArray().Length, remoteIp);
            List<byte[]> bytePackets = inputData.SerializeToByteArray().StackByteArray(64000);
            udpClient.Send(bytePackets.Count.SerializeToByteArray(), bytePackets.Count.SerializeToByteArray().Length, remoteIp);

            for (int i = 0; i < bytePackets.Count; i++)
            {
                udpClient.Send(BitConverter.GetBytes(i), BitConverter.GetBytes(i).Length, remoteIp);
                udpClient.Send(bytePackets[i], bytePackets[i].Length, remoteIp);
                new System.Threading.ManualResetEvent(false).WaitOne(sendInterval);
            }
        }
    }
}
