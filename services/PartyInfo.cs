using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Services.Helper;
using Egelke.EHealth.Etee.Crypto;
using Org.BouncyCastle.Crypto;

namespace Egelke.EHealth.Client.Services
{
    public class PartyInfo
    {
        public EncryptionToken Etk {  get; set; }

        public IdentifierType Id { get; set; }

        private string _ssin;

        public string Ssin { 
            get 
            {
                return _ssin ?? (Id.Type == "SSIN" ? Id.Value : null);
            } 
            set
            {
                _ssin = value;
            }
        }

        private string _nihii8;

        public string Nihii8
        {
            get
            {
                return _nihii8 ?? (Id.Type == "NIHII" ? Id.Value : null);
            }
            set
            {
                _nihii8 = value;
            }
        }

        private string _cbe;

        public string Cbe
        {
            get
            {
                return _cbe ?? (Id.Type == "CBE" ? Id.Value : null);
            }
            set { _cbe = value; }
        }

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
    }
}
