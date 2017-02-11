using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNETWork
{
    public class DotUserException : Exception 
    {
        private string errorMessage = "";
        public override string Message
        {
            get
            {
                return errorMessage;
            }
        }

        public DotUserException(string message)
        {
            errorMessage = message;
        }
    }
}
