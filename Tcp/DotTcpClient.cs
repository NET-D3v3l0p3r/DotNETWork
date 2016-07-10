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
        private DotRijndaelDecryption rijndaelDecryption;

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

            byte[] receivedDataEncrypted = new byte[0];
            int dataLength = binReader.ReadInt32();
            receivedDataEncrypted = binReader.ReadBytes(dataLength);

            string inputXML = receivedDataEncrypted.DeserializeToDynamicType();
            rjindaelEncryption = new DotRijndaelEncryption(inputXML);

            // SEND OWN CREATED PUBLIC KEY
            // TO SERVER.
            rijndaelDecryption = new DotRijndaelDecryption();
            rijndaelDecryption.SendPublicKeyXML(binWriter);
            
            Console.WriteLine("[CLIENT] Sent public key!");

            return true;
        }
        public bool Send(object inputData) 
        {
            try
            {
                var byteBuffer = inputData.SerializeToByteArray();
                //binWriter.Write(byteBuffer.Length);
                //binWriter.Write(byteBuffer);
                var decryptedBuffer = rjindaelEncryption.EncryptStream(byteBuffer);
                binWriter.Write(decryptedBuffer.Length);
                binWriter.Write(decryptedBuffer);
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
                byte[] receivedDataEncrypted = new byte[0];
                int dataLength = binReader.ReadInt32();
                receivedDataEncrypted = binReader.ReadBytes(dataLength);
                byte[] receivedDataDecrypted = rijndaelDecryption.DecryptStream(receivedDataEncrypted);
                return receivedDataDecrypted.DeserializeToDynamicType();
            }
            catch(Exception ex)
            {
                System.Windows.Forms.MessageBox.Show("[DotNETWork ~Receive] The host (" + RemoteEndPoint + ") closed the connection." + Environment.NewLine + "Message: " + ex.Message, "Message", System.Windows.Forms.MessageBoxButtons.OK, System.Windows.Forms.MessageBoxIcon.Error, System.Windows.Forms.MessageBoxDefaultButton.Button2, System.Windows.Forms.MessageBoxOptions.ServiceNotification, false);
                return null;
            }
        }


    }
}
