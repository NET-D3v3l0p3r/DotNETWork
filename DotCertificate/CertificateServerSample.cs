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
using DotNETWork.Tcp;
using System.Windows.Forms;

namespace DotNETWork.DotCertificate
{
    public class CertificateServerSample
    {
        public string CertificateFolder { get; private set; }
        public List<Certificate> Certificates { get; private set; }

        public IPEndPoint IPEndPoint { get; private set; }

        public CertificateServerSample(string path, int port)
        {
            if (!Directory.Exists(path))
                throw new Exception("Folder does not exist!");
            CertificateFolder = path;
            Certificates = new List<Certificate>();


            foreach (var file in Directory.GetFiles(CertificateFolder))
                Certificates.Add(File.ReadAllBytes(file).DeserializeToDynamicType());

            Console.WriteLine("Loaded " + Certificates.Count + " certificates.");
            IPEndPoint = new IPEndPoint(IPAddress.Any, port);

            Socket listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            listener.Bind(IPEndPoint);

            new Thread(new ThreadStart(() =>
            {
                listener.Listen(int.MaxValue);

                DotRijndaelDecryption _xmlDecryptor = new DotRijndaelDecryption("");
                string xml = _xmlDecryptor.GetPublicKeyXML();
                Clipboard.SetText(Utilities.GetMD5Hash(xml));

                Console.WriteLine("Certificate-Server listening!");
                while (true)
                {
                    Socket client = listener.Accept();

                    BinaryWriter binWriter = new BinaryWriter(new NetworkStream(client));
                    BinaryReader xmlReader = new BinaryReader(new NetworkStream(client));

                    binWriter.WriteFull(xml);
                    try
                    {
                        int lenght = xmlReader.ReadInt32();
                        byte[] data = _xmlDecryptor.DecryptStream(xmlReader.ReadBytes(lenght));
                        string clientXml = data.DeserializeToDynamicType();

                        DotRijndaelEncryption _keyEncryptor = new DotRijndaelEncryption(clientXml);


                        binWriter.WriteFull(_keyEncryptor.EncryptStream(Certificates.SerializeToByteArray()));
                        binWriter.WriteFull(_keyEncryptor.EncryptStream("OK".SerializeToByteArray()));

                        Console.WriteLine("Done.");
                    }
                    catch { Console.WriteLine("Invalid."); }
                }


            }))
            { ApartmentState = ApartmentState.STA }.Start();
            
        }
    }

}
