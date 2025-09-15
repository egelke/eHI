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
    public class TsaTest
    {

        protected ILoggerFactory loggerFactory;

        public TsaTest() {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });
        }

        [Fact]
        public void Tsa()
        {
            var p12 = new EHealthP12("files/ehealth-cin-nic.acc.p12", File.ReadAllText("files/ehealth-cin-nic.acc.p12.pwd"));
            var client = p12["authentication"];

            string msg = "Hello Bob, this is Alice";
            byte[] msgDigest;
            using (var sha256 = SHA256.Create())
            {
                msgDigest = sha256.ComputeHash(Encoding.UTF8.GetBytes(msg));
            }

            //var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            var tsa = new TimeStampAuthorityClient(new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            tsa.ClientCredentials.ClientCertificate.Certificate = client;
            tsa.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            var tsaProvider = new EHealthTimestampProvider(tsa);
            var hash = tsaProvider.GetTimestampFromDocumentHash(msgDigest, "http://www.w3.org/2001/04/xmlenc#sha256");

            Assert.NotNull(hash);
        }
    }
}
