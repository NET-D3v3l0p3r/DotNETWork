using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNETWork
{
    public class DotTcpException : Exception
    {
        private string errorMessage = "";
        public override string Message
        {
            get
            {
                return errorMessage;
            }
        }

        public DotTcpException(string message)
        {
            errorMessage = message;
        }
    }
}
