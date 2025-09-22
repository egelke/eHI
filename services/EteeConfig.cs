using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;

namespace Egelke.EHealth.Client.Services
{
    public class EteeConfig
    {
        public EncryptionToken Etk {  get; set; }

        public List<EHealthP12> Keys { get; set; } = new List<EHealthP12>();
    }
}
