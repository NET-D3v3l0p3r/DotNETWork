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

namespace DotNETWork.Tcp
{
    public class DotTcpClient
    {
        public IPEndPoint LocalEndpoint { get; private set; }
        public IPEndPoint RemoteEndPoint { get; set; }

        public delegate void OnConnectedDelegate( );
        public event OnConnectedDelegate OnConnected;

        public string EncryptionString { get; private set; }

        private TcpClient tcpClient;

        private BinaryReader binReader;
        private BinaryWriter binWriter;

        private DotRijndaelEncryption rjindaelEncryption;
        private DotRijndaelDecryption rijndaelDecryption;

        private string verificationHash = "";

        public DotTcpClient(string remoteIp, int remotePort, string encryptionString)
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse(remoteIp), remotePort);
            EncryptionString = encryptionString;
        }

        private void initLocalEndPoint()
        {
            LocalEndpoint = new IPEndPoint(Utilities.GetLocalIPv4(), Utilities.Random.Next(IPEndPoint.MinPort, IPEndPoint.MaxPort));
            tcpClient = new TcpClient(LocalEndpoint);
        }

        public bool StartSession(int ms)
        {
            if (string.IsNullOrWhiteSpace(verificationHash))
                throw new Exception("An verification hash must be set!");

            initLocalEndPoint();
            IAsyncResult asyncResult = tcpClient.BeginConnect(RemoteEndPoint.Address.MapToIPv4(), RemoteEndPoint.Port, null, null);
            bool connectionStatus = asyncResult.AsyncWaitHandle.WaitOne(ms);
            if (!connectionStatus)
                return false;

            tcpClient.EndConnect(asyncResult);

            binReader = new BinaryReader(tcpClient.GetStream());
            binWriter = new BinaryWriter(tcpClient.GetStream());

            // INFORM CONNECTION MODE
            binWriter.Write("CONNECTION=DEFAULT");

            // TRY TO GET PUBLIC KEY
            // AND INSTANCIATE RIJNADELENCRYPTION

            byte[] receivedDataDecrypted = new byte[0];
            int dataLength = binReader.ReadInt32();
            receivedDataDecrypted = binReader.ReadBytes(dataLength);

            string inputXML = receivedDataDecrypted.DeserializeToDynamicType();
            // VERIFY PUBLIC KEY HTML
            if (!verificationHash.Equals(Utilities.GetMD5Hash(inputXML)))
            {
                MessageBox.Show("Attention: The hash of the received Public-Key-XML is not equivalent to the verification hash:" + Environment.NewLine  +
                    "Verification hash: " + verificationHash  + Environment.NewLine +
                    "Received hash: " + Utilities.GetMD5Hash(inputXML) + Environment.NewLine + 
                    "The XML is probably corrupt which is common in MITM-Attacks." + Environment.NewLine + 
                    "The connection will be closed immadiatly!", "Warning!", MessageBoxButtons.OK, MessageBoxIcon.Error, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly, false);

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[*]CONNECTION LOST DUE CORRUPT KEY EXCEPTION!");
                tcpClient.Close();
                binReader.Close();
                binWriter.Close();
                return false;
            }
            rjindaelEncryption = new DotRijndaelEncryption(inputXML);

            // SEND OWN CREATED PUBLIC KEY
            // TO SERVER.
            rijndaelDecryption = new DotRijndaelDecryption(EncryptionString);
            rijndaelDecryption.SendPublicKeyXML(binWriter);

            OnConnected();
            return true;
        }

        public void SetVerificationHash(string vHash)
        {
            verificationHash = vHash;
        }

        public bool Send(object inputData)
        {
            try
            {
                var byteBuffer = inputData.SerializeToByteArray();
                //binWriter.Write(byteBuffer.Length);
                //binWriter.Write(byteBuffer);
                var encryptedBuffer = rjindaelEncryption.EncryptStream(byteBuffer);
                binWriter.Write(encryptedBuffer.Length);
                binWriter.Write(encryptedBuffer);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<bool> SendAsync(object inputData)
        {
            return await Task.Run(() =>
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
                catch
                {
                    return false;
                }
            });
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
            catch
            {
                return false;
            }
        }


        public async Task<dynamic> ReceiveAsync()
        {
            return await Task.Run(() =>
            {
                try
                {
                    byte[] receivedDataEncrypted = new byte[0];
                    int dataLength = binReader.ReadInt32();
                    receivedDataEncrypted = binReader.ReadBytes(dataLength);
                    byte[] receivedDataDecrypted = rijndaelDecryption.DecryptStream(receivedDataEncrypted);
                    return receivedDataDecrypted.DeserializeToDynamicType();
                }
                catch
                {
                    return false;
                }
            });
        }
    


    }
}
