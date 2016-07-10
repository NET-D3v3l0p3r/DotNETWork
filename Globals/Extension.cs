using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DotNETWork.Globals
{
    public static class Extension
    {
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
    }
}
