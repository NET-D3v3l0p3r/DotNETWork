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
using System.Drawing;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;


namespace DotNETWork.Globals
{
    public static class Utilities
    {
        public static Random Random = new Random();
        public static IPAddress GetLocalIPv4()
        {
            if (!System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable())
            {
                return null;
            }

            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());

            return host
                .AddressList
                .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork);
        }

        public static string GetMD5Hash(string TextToHash)
        {
            //Prüfen ob Daten übergeben wurden.
            if ((TextToHash == null) || (TextToHash.Length == 0))
            {
                return string.Empty;
            }

            //MD5 Hash aus dem String berechnen. Dazu muss der string in ein Byte[]
            //zerlegt werden. Danach muss das Resultat wieder zurück in ein string.
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] textToHash = Encoding.Default.GetBytes(TextToHash);
            byte[] result = md5.ComputeHash(textToHash);

            return System.BitConverter.ToString(result);
        }

        public static string GenerateRandomKeyContainerName(int nameLength)
        {
            if (nameLength % 2 != 0)
                throw new Exception("Parameter nameLength must be devisible by 2!");

            string resultText = "";

            string keyCharacters = @"abcdefghijklmnopqrstuvwxyz1234567890!§$%&()=?´'.:-^°@#+-*/[]{}\";

            for (int i = 0; i < nameLength; i++)
            {
                resultText += Random.NextDouble() >= 0.5 ? keyCharacters.Substring(Random.Next(0, keyCharacters.Length), 1).ToUpper() : keyCharacters.Substring(Random.Next(0, keyCharacters.Length), 1);
            }

            return resultText;
        }
    }
}
