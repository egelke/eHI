using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services.Tsa;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class TsaRetirementTest : BaseTest
    {
        private TimeStampAuthorityClient target;

        public TsaRetirementTest() {
            var store = new EHealthP12("files/ehealth-cin-nic.acc.p12", File.ReadAllText("files/ehealth-cin-nic.acc.p12.pwd"));
            //var store = new EHealthP12("files/NIHII-RETIREMENT=73999914 20250923-102623.acc.p12", File.ReadAllText("files/NIHII-RETIREMENT=73999914 20250923-102623.acc.p12.pwd"));

            target = new TimeStampAuthorityClient(store, new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            target.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));
        }

        [Fact]
        public void Sha256UsingProvider()
        {
            string msg = "Hello Bob, this is Alice";
            byte[] msgDigest;
            using (var sha256 = SHA256.Create())
            {
                msgDigest = sha256.ComputeHash(Encoding.UTF8.GetBytes(msg));
            }


            var tsaProvider = new EHealthTimestampProvider(target);
            var hash = tsaProvider.GetTimestampFromDocumentHash(msgDigest, "http://www.w3.org/2001/04/xmlenc#sha256");

            Assert.NotNull(hash);
        }
    }
}
