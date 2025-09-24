using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client.Services.Helper
{
    public static class IdentifierTypeExt
    {
        private static readonly Regex EhealthExp = new Regex("CN=\"(?<type>[^=]+)=(?<value>[^\",]+)(, ?(?<app>[^\"]+))?\"", RegexOptions.Compiled);

        private static readonly Regex EidExp = new Regex("SERIALNUMBER=(?<value>\\d{11})", RegexOptions.Compiled);

        public static IdentifierType ToIdentifierType(this X509Certificate2 cert)
        {
            var match = EhealthExp.Match(cert.Subject);
            if (match.Success)
            {
                return new IdentifierType()
                {
                    Type = match.Groups["type"].Value,
                    Value = match.Groups["value"].Value,
                    ApplicationID = match.Groups["app"].Value
                };
            }
            else
            {
                match = EidExp.Match(cert.Subject);
                if (!match.Success) throw new ArgumentException("Subject format not supported (ehealth or eid)", nameof(cert));
                return new IdentifierType()
                {
                    Type = "SSIN",
                    Value = match.Groups["value"].Value,
                };
            }
        }
    }
}
