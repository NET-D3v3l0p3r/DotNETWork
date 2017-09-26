﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Security.Cryptography;

using DotNETWork.Globals;
using DotNETWork.DotCertificate;

namespace DotNETWork.Security
{
    public class DotRijndaelDecryption
    {
        private CspParameters cspParameters = new CspParameters();
        private RSACryptoServiceProvider rsacProvider;

        public DotRijndaelDecryption(string keyString)
        {
            // Generate private key

            cspParameters.KeyContainerName = keyString;

            rsacProvider = new RSACryptoServiceProvider(cspParameters);
            rsacProvider.PersistKeyInCsp = true;

        }

        public void SendCertificate(string path, BinaryWriter binWriter)
        {
            byte[] buffer = File.ReadAllBytes(path);
            binWriter.Write(buffer.Length);
            binWriter.Write(buffer);
             
        }

        public void SendPublicKeyXML(BinaryWriter binWriter)
        {
            byte[] xmlBuffer = GetPublicKeyXML().SerializeToByteArray();

            binWriter.Write(xmlBuffer.Length);
            binWriter.Write(xmlBuffer);
        }

        public string GetPublicKeyXML()
        {
            return rsacProvider.ToXmlString(false);
        }

        public Certificate ToCertificate(string owner)
        {
            string xml = GetPublicKeyXML();
            return new Certificate()
            {
                Owner = owner,
                PublicKey = xml,
                Id = Utilities.GetMD5Hash(xml)
            };
        }

        public void ExportCertificate(string owner, string path)
        {
            File.WriteAllBytes(path, ToCertificate(owner).SerializeToByteArray());
        }

        public byte[] DecryptStream(byte[] inputArray)
        {
            RijndaelManaged rjndManaged = new RijndaelManaged();
            rjndManaged.KeySize = rjndManaged.BlockSize = 256;
            rjndManaged.Mode = CipherMode.CBC;

            byte[] lenKey = new byte[4];
            byte[] lenIV = new byte[4];

            using (MemoryStream mStreamIn = new MemoryStream(inputArray))
            {
                mStreamIn.Seek(0, SeekOrigin.Begin);
                mStreamIn.Seek(0, SeekOrigin.Begin);
                mStreamIn.Read(lenKey, 0, 3);
                mStreamIn.Seek(4, SeekOrigin.Begin);
                mStreamIn.Read(lenIV, 0, 3);

                int lKey = BitConverter.ToInt32(lenKey, 0);
                int lIV = BitConverter.ToInt32(lenIV, 0);

                int startC = lKey + lIV + (4 * 2);
                int lenC = (int)mStreamIn.Length - startC;

                byte[] keyEncrypted = new byte[lKey];
                byte[] IV = new byte[lIV];

                mStreamIn.Seek((4 * 2), SeekOrigin.Begin);
                mStreamIn.Read(keyEncrypted, 0, lKey);
                mStreamIn.Seek((4 * 2) + lKey, SeekOrigin.Begin);
                mStreamIn.Read(IV, 0, lIV);

                byte[] KeyDecrypted = rsacProvider.Decrypt(keyEncrypted, false);

                ICryptoTransform cryptoTransform = rjndManaged.CreateDecryptor(KeyDecrypted, IV);

                using (MemoryStream mStreamOut = new MemoryStream())
                {
                    int count = 0;
                    int offSet = 0;

                    int blockSizeBytes = rjndManaged.BlockSize / (4 * 2);
                    byte[] arrayData = new byte[blockSizeBytes];

                    mStreamIn.Seek(startC, SeekOrigin.Begin);

                    using (CryptoStream cryptoStream = new CryptoStream(mStreamOut, cryptoTransform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = mStreamIn.Read(arrayData, 0, blockSizeBytes);
                            offSet += count;
                            cryptoStream.Write(arrayData, 0, count);

                        } while (count > 0);

                        cryptoStream.FlushFinalBlock();
                        cryptoStream.Close();

                    }
                    mStreamOut.Close();
                    mStreamIn.Close();
                    return mStreamOut.ToArray();
                }

            }
        }
    }
}
