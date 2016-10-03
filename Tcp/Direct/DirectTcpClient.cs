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
using System.Net.Security;
namespace DotNETWork.Tcp.Direct
{
    public class DirectTcpClient
    {
        public IPEndPoint LocalEndpoint { get; private set; }
        public IPEndPoint RemoteEndPoint { get; set; }

        public delegate void OnConnectedDelegate();
        public event OnConnectedDelegate OnConnected;

        public string EncryptionString { get; private set; }

        private TcpClient tcpClient; 

        private BinaryReader binReader;
        private BinaryWriter binWriter;

        private DotRijndaelEncryption rjindaelEncryption;
        private DotRijndaelDecryption rijndaelDecryption;

        private Dictionary<string, string> UserKeyPair = new Dictionary<string, string>();

        public DirectTcpClient(string remoteIp, int remotePort, string encryptionString)
        {
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse(remoteIp), remotePort);
            EncryptionString = encryptionString;

            //throw new Exception("NOT IMPLEMENTED YET!");
        }

        private void initLocalEndPoint()
        {
            LocalEndpoint = new IPEndPoint(Utilities.GetLocalIPv4(), Utilities.Random.Next(IPEndPoint.MinPort, IPEndPoint.MaxPort));
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

            byte[] receivedDataDecrypted = new byte[0];
            int dataLength = binReader.ReadInt32();
            receivedDataDecrypted = binReader.ReadBytes(dataLength);

            string inputXML = receivedDataDecrypted.DeserializeToDynamicType();
            rjindaelEncryption = new DotRijndaelEncryption(inputXML);

            // SEND OWN CREATED PUBLIC KEY
            // TO SERVER.
            rijndaelDecryption = new DotRijndaelDecryption(EncryptionString);
            rijndaelDecryption.SendPublicKeyXML(binWriter);

            // REQUEST DIRECT CONNECTION PRIVILEGES

            binWriter.Write("CONNECTION=DIRECT");
            binWriter.Write(("USER=" + "ID_" + Utilities.Random.Next(0, 1000000)));

            // RECEIVE RESULSTS 
            bool requestState = binReader.ReadBoolean();

            if (!requestState)
            {
                Console.WriteLine("DENIED");
                return false;
            }

            // RECEIVE LOGGED IN USER

            int activeUsers = binReader.ReadInt32();

            // RECEIVE PUBLIC KEYS OF USERS

            for (int i = 0; i < activeUsers; i++)
            {
                // READ USER_ID
                string userId = binReader.ReadString();

                // READ PUBLIC KEY
                string publicKeyXML = binReader.ReadString();

                // FINALLY ADD TO DICTIONARY

                UserKeyPair.Add(userId, publicKeyXML);

            }

            Console.WriteLine("ADDED " + UserKeyPair.Count + " KEYS");

            OnConnected();

            return true;
        }

        /// <summary>
        /// SYNTAX: ::TYPE=[TYPE]::CLIENTS=[*,USER,USER0|USER1|USER...]::TAG=[IMPLEMENT-BASED]
        /// </summary>
        /// <param name="objectMessage"></param>
        /// <param name="dotCommand"></param>
        public void Send(object objectMessage, string dotCommand)
        {
            var byteData = objectMessage.SerializeToByteArray();

            // EXTRACT COMMAND

            string[] commandSegments = dotCommand.Split(new string[] { "::" }, StringSplitOptions.None);

            string messageType = "";
            string receiverClient = "";
            string miscString = "";

            string serverCommandMessage = "";

            for (int i = 0; i < commandSegments.Length; i++)
            {
                string selectedCommand = commandSegments[i];
                string[] keyValuePair = selectedCommand.Split('=');

                if (keyValuePair[0].ToUpper().Equals("TYPE"))
                    messageType = keyValuePair[1].ToUpper();

                if (keyValuePair[0].ToUpper().Equals("CLIENTS"))
                    receiverClient = keyValuePair[1];

                if (keyValuePair[0].ToUpper().Equals("TAG"))
                    miscString = keyValuePair[1];
            }

            switch (messageType)
            {
                case "MESSAGE":

                    //if (receiverClient.Equals("*"))
                    //    serverCommandMessage = "::REQUEST_TYPE=ALL::USERS=" + receiverClient;
                    //else if (receiverClient.Contains(","))
                    //    serverCommandMessage = "::REQUEST_TYPE=SEVERAL::USERS=" + receiverClient;
                    //else
                    //    serverCommandMessage = "::REQUEST_TYPE=SPECIFIED::USERS=" + receiverClient;


                    //rjindaelEncryption = new DotRijndaelEncryption(UserKeyPair[receiverClient]);
                    //var encryptedBytes = rjindaelEncryption.EncryptStream(byteData);

                    //binWriter.Write(encryptedBytes.Length);
                    //binWriter.Write(encryptedBytes);

                    break;

                case "INFORMATION":

                    break;
            }
        }


    }
}
