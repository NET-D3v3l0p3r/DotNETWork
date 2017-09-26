using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DotNETWork.DotCertificate
{
    [Serializable]
    public class Certificate
    {
        public string Id { get; set; }
        public string PublicKey { get; set; }

        public string Owner { get; set; }

        public override bool Equals(object obj)
        {
            Certificate _obj = (Certificate)obj;
            return _obj.Id.Equals(Id) && _obj.Owner.Equals(Owner);
        }
        public override int GetHashCode()
        {
            return Id.GetHashCode();
        }
        public override string ToString()
        {
            return 
@"
Id: $ID
PublicKey: $KEY
Owner: $OWNER
".Replace("$ID", Id).Replace("$KEY", PublicKey).Replace("$OWNER", Owner);
        }
    }
}
