using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IO;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Client.Services.Mda;
using Egelke.EHealth.Client.Sts;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class IcnMdaRetirementTest : BaseTest
    {

        private MdaClient target;

        public IcnMdaRetirementTest()
        {
            //mdaEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IrisCareNet/MemberData/v1");
            var store = new EHealthP12("files/NIHII-RETIREMENT=73999914 20250923-102623.acc.p12", File.ReadAllText("files/NIHII-RETIREMENT=73999914 20250923-102623.acc.p12.pwd"));

            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstAddress;
            //binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:ehealth:1.0:retirement:nihii-number:recognisedretirement:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:ehealth:1.0:retirement:nihii-number:recognisedretirement:nihii11", null, AuthClaimSet.Dialect));
            target = new MdaClient(store, binding, new EndpointAddress("https://services-acpt.ehealth.fgov.be/MyCareNet/MemberData/v1"), loggerFactory.CreateLogger<MdaClient>())
            {
                IsTest = true,
                License = new LicenseType()
                {
                    Username = File.ReadAllText("files/license.txt"),
                    Password = File.ReadAllText("files/license.pwd")
                }
            };
            target.Service = new PartyInfo()
            {
                Cbe = "0820563481",
                Application = "MYCARENET-EC"
            };
            target.InitEncryptionTokens(new EtkDepotClient(new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1")));


            target.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            

        }

        
    }
}
