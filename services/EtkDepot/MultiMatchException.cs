using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;

namespace Egelke.EHealth.Client.Services.EtkDepot
{
    public class MultiMatchException : ApplicationException
    {
        public IdentifierType Requested { get; }

        public IdentifierType[] Matching { get; }

        public MultiMatchException(IdentifierType requested, IdentifierType[] matching)
            : base(String.Format("Multiple matches found for {0}={1}, {2}", requested.Type, requested.Value, requested.ApplicationID))
        {
            Requested = requested;
            Matching = matching;
        }

        public MultiMatchException(IdentifierType requested, IdentifierType[] matching, string message) : base(message)
        {
            Requested = requested;
            Matching = matching;
        }

    }
}
