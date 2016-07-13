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
namespace DotNETWork.Tcp
{
    public interface IClient 
    {
        string UserID { get; set; }

        IPEndPoint ClientEndPoint { get; set; }
        TcpClient TcpClient { get; set; }

        BinaryReader BinReader { get; set; }
        BinaryWriter BinWriter { get; set; }

        string PublicKeyXML { get; set; }

        /// <summary>
        /// The parameter contains the DotNETWork-TcpServer.
        /// </summary>
        /// <param name="parameter"></param>
        void Call(object parameter);
    }
}
