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
    public class DotTcpClient
    {
        public IPEndPoint LocalEndpoint { get; private set; }
        public IPEndPoint RemoteEndPoint { get; set; }

        private TcpClient tcpClient;

        private BinaryReader binReader;
        private BinaryWriter binWriter;

        private DotRijndaelEncryption rjindaelEncryption;

        public DotTcpClient(string remoteIp, int remotePort)
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse(remoteIp), remotePort);
        }

        private void initLocalEndPoint()
        {
            LocalEndpoint = new IPEndPoint(Utilities.GetLocalIPv4(), Utilities.Random.Next(2000, 10000));
            tcpClient = new TcpClient(LocalEndpoint);
        }

        public bool Connect(int ms)
        {
            initLocalEndPoint();
            IAsyncResult asyncResult = tcpClient.BeginConnect(RemoteEndPoint.Address.MapToIPv4(), RemoteEndPoint.Port, null, null);
            bool connectionStatus = asyncResult.AsyncWaitHandle.WaitOne(ms);
            if (!connectionStatus)
                return false;

            tcpClient.EndConnect(asyncResult);

            binReader = new BinaryReader(tcpClient.GetStream());
            binWriter = new BinaryWriter(tcpClient.GetStream());

            // TRY TO GET PUBLIC KEY
            // AND INSTANCIATE RIJNADELENCRYPTION
            string inputXML = Receive();
            rjindaelEncryption = new DotRijndaelEncryption(inputXML, binWriter);


            return true;
        }
        public bool Send(object inputData) 
        {
            try
            {
                var byteBuffer = inputData.SerializeToByteArray();
                //binWriter.Write(byteBuffer.Length);
                //binWriter.Write(byteBuffer);
                rjindaelEncryption.EncryptStream(byteBuffer);
                return true;
            }
            catch (Exception ex)
            {
                System.Windows.Forms.MessageBox.Show("[DotNETWork ~Send] The host (" + RemoteEndPoint + ") closed the connection." + Environment.NewLine + "Message: " + ex.Message, "Message", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error, System.Windows.Forms.MessageBoxDefaultButton.Button2, System.Windows.Forms.MessageBoxOptions.ServiceNotification, false);
                return false;
            }
        }
        public dynamic Receive()
        {
            try
            {
                byte[] receivedData = new byte[0];
                int dataLength = binReader.ReadInt32();
                receivedData = new byte[dataLength];
                receivedData = binReader.ReadBytes(dataLength);
                return receivedData.DeserializeToDynamicType();
            }
            catch(Exception ex)
            {
                System.Windows.Forms.MessageBox.Show("[DotNETWork ~Receive] The host (" + RemoteEndPoint + ") closed the connection." + Environment.NewLine + "Message: " + ex.Message, "Message", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error, System.Windows.Forms.MessageBoxDefaultButton.Button2, System.Windows.Forms.MessageBoxOptions.ServiceNotification, false);
                return null;
            }
        }


    }
}
