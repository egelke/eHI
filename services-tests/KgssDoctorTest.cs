using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IO;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Client.Services.Kgss;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class KgssDoctorTest : BaseTest
    {
        private KgssClient senderClient;

        private KgssClient receiverClient;

        public KgssDoctorTest()
        {
            var kgss = new EndpointAddress("https://services-acpt.ehealth.fgov.be/Kgss/v1");
            var etkDepot = new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");

            var store = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));

            senderClient = new KgssClient(store, kgss, loggerFactory.CreateLogger<KgssClient>());
            senderClient.InitEncryptionTokens(new EtkDepotClient(etkDepot));

            senderClient.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));


            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstAddress;
            //binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));
            receiverClient = new KgssClient(store, binding, kgss, loggerFactory.CreateLogger<KgssClient>());
            receiverClient.Sender.Etk = senderClient.Sender.Etk;
            receiverClient.Service.Etk = senderClient.Service.Etk;


            receiverClient.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));
        }

        [Fact]
        public void AllowAllDoctorsUsingBooleanAttr()
        {
            //sender creates a new key for all doctors
            
            SecretKey senderKey = senderClient.GetNewKey(new CredentialType()
            {
                Namespace = "urn:be:fgov:certified-namespace:ehealth",
                Name = "urn:be:fgov:person:ssin:doctor:boolean",
                Values = new List<string> { "true" }
            });


            SecretKey receiverKey = receiverClient.GetKey(senderKey.Id);

            Assert.Equal(senderKey, receiverKey);
        }

        [Fact]
        public void AllowAllDoctorsAndNursesUsingEmptyNihiiValues()
        {
            //sender creates a new key for all doctors and nurse
            SecretKey senderKey = senderClient.GetNewKey(
                new CredentialType()
                {
                    Namespace = "urn:be:fgov:certified-namespace:ehealth",
                    Name = "urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11"
                },
                new CredentialType() //all nurses
                {
                    Namespace = "urn:be:fgov:certified-namespace:ehealth",
                    Name = "urn:be:fgov:person:ssin:ehealth:1.0:nihii:nurse:nihii11"
                }
            );

            //receiver, a doctor, retrieves the key
            SecretKey receiverKey = receiverClient.GetKey(senderKey.Id);

            Assert.Equal(senderKey, receiverKey);
        }

        [Fact]
        public void AllowNurseButCallDoctor()
        {
            //sender creates a new key for all nurses but not doctors
            SecretKey senderKey = senderClient.GetNewKey(new CredentialType() //all nurses
            {
                Namespace = "urn:be:fgov:certified-namespace:ehealth",
                Name = "urn:be:fgov:person:ssin:ehealth:1.0:nihii:nurse:nihii11"
            }
            );

            //receiver, a doctor, retrieves the key
            var ex = Assert.ThrowsAny<ServiceException>(() => receiverClient.GetKey(senderKey.Id));

            Assert.Equal("NO_KEY_FOUND", ex.Code);
            Assert.NotEmpty(ex.Message);
        }
        
    }
}
