using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Threading.Tasks;

namespace DotNETWork.Globals
{
    // SOURCE: http://stackoverflow.com/a/30435601
    public static class Extension
    {
        public static byte[] Serialize(this object _object)
        {
            byte[] bytes;
            using (var _MemoryStream = new MemoryStream())
            {
                IFormatter _BinaryFormatter = new BinaryFormatter();
                _BinaryFormatter.Serialize(_MemoryStream, _object);
                bytes = _MemoryStream.ToArray();
            }
            return bytes;
        }

        public static dynamic Deserialize(this byte[] _byteArray)
        {
            using (var _MemoryStream = new MemoryStream(_byteArray))
            {
                IFormatter _BinaryFormatter = new BinaryFormatter();
                var ReturnValue = _BinaryFormatter.Deserialize(_MemoryStream);
                return ReturnValue;
            }
        }
    }
}
