using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNETWork.Tcp
{
    public struct ClientParameters<T> where T : IClient, new()
    {
        public DotTcpServer<T> ServerHandler;
        public byte[] DecryptedBytes;
    }
}
