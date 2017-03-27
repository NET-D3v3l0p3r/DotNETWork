using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DotNETWork.Tcp;

namespace DotNETWork.Globals
{
    public static class Extension
    {

        public static IPEndPoint SendSYN(this Socket socket, EndPoint ipep)
        {
            SocketAsyncEventArgs e = new SocketAsyncEventArgs();
            e.RemoteEndPoint = ipep;
            try
            {
                socket.ConnectAsync(e);
                IPEndPoint ipEndP = (IPEndPoint)socket.LocalEndPoint;
                return ipEndP;
            }
            catch { return null; }
        }
        public static bool GetAvaiblity(this Socket socket, EndPoint ipep, int timeout)
        {
            var result = socket.BeginConnect(ipep, null, null);
            var status = result.AsyncWaitHandle.WaitOne(TimeSpan.FromMilliseconds(timeout));
            return status;
        }

        public static byte[] SerializeToByteArray(this object objectData)
        {
            byte[] bytes;
            using (var _MemoryStream = new MemoryStream())
            {
                IFormatter _BinaryFormatter = new BinaryFormatter();
                _BinaryFormatter.Serialize(_MemoryStream, objectData);
                bytes = _MemoryStream.ToArray();
            }
            return bytes;
        }
        public static dynamic DeserializeToDynamicType(this byte[] byteArray)
        {
            using (var _MemoryStream = new MemoryStream(byteArray))
            {
                IFormatter _BinaryFormatter = new BinaryFormatter();
                var ReturnValue = _BinaryFormatter.Deserialize(_MemoryStream);
                return ReturnValue;
            }
        }

        public static List<byte[]> StackByteArray(this byte[] inputArray, int stackSize)
        {
            List<byte[]> _packets = new List<byte[]>();
            byte[] _byteCollection = null;

            int _amountPacket = 0;
            if ((double)inputArray.Length / (double)stackSize >= 1)
                _amountPacket = inputArray.Length / stackSize;

            for (int i = 0; i <= _amountPacket; i++)
            {
                int _amount = (i * stackSize) + stackSize;

                if (inputArray.Length - i * stackSize < stackSize)
                    _byteCollection = new byte[inputArray.Length - i * stackSize];
                else _byteCollection = new byte[stackSize];

                Array.Copy(inputArray, i * stackSize, _byteCollection, 0, _byteCollection.Length);
                _packets.Add(_byteCollection);
            }
            return _packets;
        }

        public static string ToMD5(this string stringData)
        {
            //Prüfen ob Daten übergeben wurden.
            if ((stringData == null) || (stringData.Length == 0))
            {
                return string.Empty;
            }

            //MD5 Hash aus dem String berechnen. Dazu muss der string in ein Byte[]
            //zerlegt werden. Danach muss das Resultat wieder zurück in ein string.
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] textToHash = Encoding.Default.GetBytes(stringData);
            byte[] result = md5.ComputeHash(textToHash);

            return System.BitConverter.ToString(result);
        }
        public static string ToHex(this byte[] bytes, bool upperCase)
        {
            StringBuilder result = new StringBuilder(bytes.Length * 2);

            for (int i = 0; i < bytes.Length; i++)
                result.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));

            return result.ToString();
        }

        public static Bitmap CompressImage(this Image sourceImage, int imageQuality)
        {
            try
            {
                //Create an ImageCodecInfo-object for the codec information
                ImageCodecInfo jpegCodec = null;

                //Set quality factor for compression
                EncoderParameter imageQualitysParameter = new EncoderParameter(
                            System.Drawing.Imaging.Encoder.Quality, imageQuality);

                //List all avaible codecs (system wide)
                ImageCodecInfo[] alleCodecs = ImageCodecInfo.GetImageEncoders();

                EncoderParameters codecParameter = new EncoderParameters(1);
                codecParameter.Param[0] = imageQualitysParameter;

                //Find and choose JPEG codec
                for (int i = 0; i < alleCodecs.Length; i++)
                {
                    if (alleCodecs[i].MimeType == "image/jpeg")
                    {
                        jpegCodec = alleCodecs[i];
                        break;
                    }
                }

                //Save compressed image
                MemoryStream ms = new MemoryStream();
                sourceImage.Save(ms, jpegCodec, codecParameter);

                return new Bitmap(ms);
            }
            catch (Exception e)
            {
                throw e;
            }
        }

        public static void WriteEncrypted(this BinaryWriter binWriter, object data, IClient client)
        {
            var encrypted = client.DotRijndaelEncryption.EncryptStream(data.SerializeToByteArray());

            binWriter.Write(encrypted.Length);
            binWriter.Write(encrypted);
        }
    }
}
