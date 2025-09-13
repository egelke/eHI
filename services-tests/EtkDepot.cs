using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Client.Services.EtkDepot;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class EtkDepot : BaseTest
    {

        private EtkDepotClient target;

        public EtkDepot()
        {
            var etkDepot = new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");

            target = new EtkDepotClient(etkDepot, loggerFactory.CreateLogger<EtkDepotClient>());
        }




        [Fact]
        public void GetOwnEtk()
        {
            var req = new IdentifierType()
            {
                Type = "SSIN",
                Value = ssin,
                ApplicationID = ""
            };

            var rsp = target.GetEtk(req);

            Assert.Single(rsp);
            Assert.Contains("CN=\"SSIN="+ssin+"\"", rsp[0].ToCertificate().Subject);

            //File.WriteAllBytes("c:/Data/79021802145.etk", rsp[0].GetEncoded());
        }

        [Fact]
        public void GetCinMyCarenetRsaEtk()
        {
            var req = new IdentifierType()
            {
                Type = "CBE",
                Value = "0820563481",
                ApplicationID = "MYCARENET"
            };

            var rsp = target.GetEtk(req);

            Assert.Single(rsp);
            Assert.Contains("CN=\"CBE=0820563481, MYCARENET\"", rsp[0].ToCertificate().Subject);

            //File.WriteAllBytes("c:/Data/mycarenet.etk", rsp[0].GetEncoded());
        }

        [Fact]
        public void GetCinMyCarenetEcEtk()
        {
            var req = new IdentifierType()
            {
                Type = "CBE",
                Value = "0820563481",
                ApplicationID = "MYCARENET-EC"
            };

            var rsp = target.GetEtk(req);

            Assert.Single(rsp);
            Assert.Contains("CN=\"CBE=0820563481, MYCARENET-EC\"", rsp[0].ToCertificate().Subject);

            //File.WriteAllBytes("c:/Data/mycarenet-ec.etk", rsp[0].GetEncoded());
        }


        [Fact]
        public void NotFound()
        {
            var req = new IdentifierType()
            {
                Type = "SSIN",
                Value = "00000000000",
                ApplicationID = ""
            };

            var ex = Assert.Throws<ServiceException>(() => target.GetEtk(req));
            Assert.Equal("NO_MATCHING_ETK", ex.Code);
        }

        [Fact]
        public void MultipleFound()
        {
            var req = new IdentifierType()
            {
                Type = "CBE",
                Value = "0820563481",
            };

            var ex = Assert.Throws<MultiMatchException>(() => target.GetEtk(req));
            Assert.Equal("0820563481", ex.Requested.Value);
            Assert.NotEmpty(ex.Matching);
        }
    }
}
