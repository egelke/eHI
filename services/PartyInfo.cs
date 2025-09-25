using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Org.BouncyCastle.Crypto;

namespace Egelke.EHealth.Client.Services
{
    public class PartyInfo
    {
        private static readonly Regex EhealthExp = new Regex("CN=\"(?<type>[^=-]+)(-(?<quality>[^=]+))?=(?<value>[^\",]+)(, ?(?<app>[^\"]+))?\"", RegexOptions.Compiled);

        private static readonly Regex EidExp = new Regex("SERIALNUMBER=(?<value>\\d{11})", RegexOptions.Compiled);


        public static PartyInfo FromCertificate(X509Certificate cert)
        {
            var match = EhealthExp.Match(cert.Subject);
            if (match.Success)
            {
                string type = match.Groups["type"].Value;
                switch(type)
                {
                    case "SSIN":
                        return new PartyInfo()
                        {
                            Ssin = match.Groups["value"].Value,
                            Application = match.Groups["app"].Value
                        };
                    case "CBE":
                        return new PartyInfo()
                        {
                            Cbe = match.Groups["value"].Value,
                            Application = match.Groups["app"].Value
                        };
                    case "NIHII":
                        return new PartyInfo()
                        {
                            Nihii8 = match.Groups["value"].Value,
                            Application = match.Groups["app"].Value,
                            Quality = match.Groups["quality"].Value
                        };
                    default:
                        throw new ArgumentException("Invalid or unsupported eHealth certificiate", nameof(cert));
                }
            }
            else
            {
                match = EidExp.Match(cert.Subject);
                if (!match.Success) throw new ArgumentException("Subject format not supported (ehealth or eid)", nameof(cert));
                return new PartyInfo()
                {
                    Ssin = match.Groups["value"].Value
                };
            }
        }

        public EncryptionToken Etk {  get; set; }

        public string Ssin {  get; set; }

        public string Nihii8 { get; set; }

        public string Cbe { get; set; }

        public string NihiiExt { get; set; }

        public string Nihii11
        {
            get
            {
                return Nihii8 + (NihiiExt ?? "000");
            }
            set
            {
                Nihii8 = value.Substring(0, 8);
                NihiiExt = value.Substring(8);
            }
        }

        public string Quality { get; set; }

        public string Application {  get; set; }

        public bool HasId()
        {
            return !String.IsNullOrWhiteSpace(Ssin)
                || !String.IsNullOrWhiteSpace(Cbe)
                || !String.IsNullOrWhiteSpace(Nihii8);
        }

        public IdentifierType ToIdentifierType()
        {
            if (!String.IsNullOrWhiteSpace(Ssin))
            {
                return new IdentifierType()
                {
                    Type = "SSIN",
                    Value = Ssin,
                    ApplicationID = Application ?? ""
                };
            }
            else if (!String.IsNullOrWhiteSpace(Cbe))
            {
                return new IdentifierType()
                {
                    Type = "CBE",
                    Value = Cbe,
                    ApplicationID = Application ?? ""
                };
            }
            else if (!String.IsNullOrWhiteSpace(Nihii8))
            {
                return new IdentifierType()
                {
                    Type = Quality == null ? "NIHII" : "NIHII-" + Quality,
                    Value = Nihii8,
                    ApplicationID = Application ?? ""
                };
            }
            else
            {
                throw new InvalidOperationException("No supported ID is specified");
            }
        }

        public CareProviderType ToCareProvider()
        {
            //todo::make more inteligent
            return new CareProviderType()
            {
                PhysicalPerson = new IdType1() //Depending on the list of wsdls this is either IdType or IdType1 (whatever comes first while generating)
                {
                    Ssin = new ValueRefString()
                    {
                        Value = Ssin
                    }
                },
                Nihii = new NihiiType()
                {
                    Quality = Quality,
                    Value = new ValueRefString()
                    {
                        Value = Nihii11
                    }
                }
            };
        }

        public AuthClaimSet ToAuthClaimSet()
        {
            //see: https://www.ehealth.fgov.be/ehealthplatform/file/cc73d96153bbd5448a56f19d925d05b1379c7f21/633552b42b6cc30b0d7e1257cf326955ad2d1def/i.am---federation-attributes-v1.3-dd-19052021.pdf
            if (!String.IsNullOrWhiteSpace(Ssin))
            {
                return new AuthClaimSet()
                {
                    new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", Ssin, AuthClaimSet.Dialect),
                    new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", Ssin, AuthClaimSet.Dialect)
                };
            }
            else if (!String.IsNullOrWhiteSpace(Cbe))
            {
                return new AuthClaimSet()
                {
                    new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:kbo-bce:organization:cbe-number", Cbe, AuthClaimSet.Dialect),
                    new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:enterprise:cbe-number", Cbe, AuthClaimSet.Dialect)
                };
            }
            else if (!String.IsNullOrWhiteSpace(Nihii8))
            {
                return new AuthClaimSet()
                {
                    new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:"+Quality.ToLower()+":nihii-number'", Nihii8, AuthClaimSet.Dialect),
                    new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:"+Quality.ToLower()+":nihii-number", Nihii8, AuthClaimSet.Dialect)
                };
            }
            else
            {
                throw new InvalidOperationException("No supported ID is specified");
            }

        }
    }
}
