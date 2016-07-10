using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Security.Cryptography;

namespace DotNETWork.Security
{
    public class DotRijndaelEncryption
    {
        private CspParameters cspParameters = new CspParameters();
        private RSACryptoServiceProvider rsacProvider;
        private const string keyName = "rijndaelKey01";

        public string PublicKeyXML { get; private set; }

        public DotRijndaelEncryption(string xmlKey)
        {
            PublicKeyXML = xmlKey;

            cspParameters.KeyContainerName = keyName;

            rsacProvider = new RSACryptoServiceProvider(cspParameters);
            rsacProvider.FromXmlString(PublicKeyXML);
            rsacProvider.PersistKeyInCsp = true;
        }

        public byte[] EncryptStream(byte[] inputArray)
        {
            RijndaelManaged rjndManaged = new RijndaelManaged();
            rjndManaged.KeySize = rjndManaged.BlockSize = 256;
            rjndManaged.Mode = CipherMode.CBC;
            ICryptoTransform cryptoTransform = rjndManaged.CreateEncryptor();


            byte[] keyEncrypted = rsacProvider.Encrypt(rjndManaged.Key, false);

            byte[] lenKey = new byte[4];
            byte[] lenIV = new byte[4];

            int lKey = keyEncrypted.Length;
            lenKey = BitConverter.GetBytes(lKey);
            int lIV = rjndManaged.IV.Length;
            lenIV = BitConverter.GetBytes(lIV);


            using (MemoryStream mStreamOut = new MemoryStream())
            {
                mStreamOut.Write(lenKey, 0, 4);
                mStreamOut.Write(lenIV, 0, 4);

                mStreamOut.Write(keyEncrypted, 0, lKey);
                mStreamOut.Write(rjndManaged.IV, 0, lIV);
                using (CryptoStream cryptoStream = new CryptoStream(mStreamOut, cryptoTransform, CryptoStreamMode.Write))
                {
                    int count = 0;
                    int offSet = 0;

                    int blockSizeBytes = rjndManaged.BlockSize / (4 * 2);
                    byte[] arrayData = new byte[blockSizeBytes];
                    int bytesRead = 0;
                    using (MemoryStream mStreamIn = new MemoryStream(inputArray))
                    {
                        do
                        {
                            count = mStreamIn.Read(arrayData, 0, blockSizeBytes);
                            offSet += count;
                            cryptoStream.Write(arrayData, 0, count);
                            bytesRead += blockSizeBytes;
                        } while (count > 0);
                        mStreamIn.Close();
                    }
                    cryptoStream.FlushFinalBlock();
                    cryptoStream.Close();
                }
                mStreamOut.Close();
                return mStreamOut.ToArray();
            }
        }
    }
}
