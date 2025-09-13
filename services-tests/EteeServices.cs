using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Services.EtkDepot;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class EteeServices : BaseTest
    {

        private EndpointAddress etkDepot;

        public EteeServices()
        {
            etkDepot = new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");
        }

        [Fact]
        public void GetCinMyCarenetRsaEtk()
        {
            var target = new EtkDepotClient(etkDepot, loggerFactory.CreateLogger<EtkDepotClient>());

            var rsp = target.GetEtk(new IdentifierType()
            {
                Type = "CBE",
                Value = "0820563481",
                ApplicationID = "MYCARENET"
            });

            Assert.Single(rsp);
            Assert.Contains("CN=\"CBE=0820563481, MYCARENET\"", rsp[0].ToCertificate().Subject);
        }

        [Fact]
        public void GetCinMyCarenetEcEtk()
        {
            var target = new EtkDepotClient(etkDepot, loggerFactory.CreateLogger<EtkDepotClient>());

            var rsp = target.GetEtk(new IdentifierType()
            {
                Type = "CBE",
                Value = "0820563481",
                ApplicationID = "MYCARENET-EC"
            });

            Assert.Single(rsp);
            Assert.Contains("CN=\"CBE=0820563481, MYCARENET-EC\"", rsp[0].ToCertificate().Subject);
        }
    }
}
