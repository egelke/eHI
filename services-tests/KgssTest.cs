using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.Linq;
using System.Net;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Client.Services.Kgss;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class KgssTest : BaseTest
    {
        private EndpointAddress kgss = new EndpointAddress("https://services-acpt.ehealth.fgov.be/Kgss/v1");

        private EndpointAddress etkDepot = new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1");
        

        public KgssTest()
        {

        }

        [Fact]
        public void AllowAllDoctorsUsingBooleanAttr()
        {
            //sender creates a new key for all doctors
            KgssClient sender = new KgssClient(store, kgss, loggerFactory.CreateLogger<KgssClient>());
            sender.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));
            sender.InitEncryptionTokens(new EtkDepotClient(etkDepot));
            SecretKey senderKey = sender.GetNewKey(new CredentialType()
            {
                Namespace = "urn:be:fgov:certified-namespace:ehealth",
                Name = "urn:be:fgov:person:ssin:doctor:boolean",
                Values = new List<string> { "true" }
            });

            //receiver, a doctor, retrieves the key
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));
            KgssClient receiver = new KgssClient(store, binding, kgss, loggerFactory.CreateLogger<KgssClient>());
            receiver.Etk = sender.Etk;
            receiver.Kgss = sender.Kgss;
            receiver.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            SecretKey receiverKey = receiver.GetKey(senderKey.Id);

            Assert.Equal(senderKey, receiverKey);
        }

        [Fact]
        public void AllowAllDoctorsAndNursesUsingEmptyNihiiValues()
        {
            //sender creates a new key for all doctors and nurse
            KgssClient sender = new KgssClient(store, kgss, loggerFactory.CreateLogger<KgssClient>());
            sender.InitEncryptionTokens(new EtkDepotClient(etkDepot));
            SecretKey senderKey = sender.GetNewKey(
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
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));
            KgssClient receiver = new KgssClient(store, binding, kgss, loggerFactory.CreateLogger<KgssClient>());
            receiver.Etk = sender.Etk;
            receiver.Kgss = sender.Kgss;

            SecretKey receiverKey = receiver.GetKey(senderKey.Id);

            Assert.Equal(senderKey, receiverKey);
        }

        [Fact]
        public void AllowNurseButCallDoctor()
        {
            //sender creates a new key for all nurses but not doctors
            KgssClient sender = new KgssClient(store, kgss, loggerFactory.CreateLogger<KgssClient>());
            sender.InitEncryptionTokens(new EtkDepotClient(etkDepot));
            SecretKey senderKey = sender.GetNewKey(new CredentialType() //all nurses
            {
                Namespace = "urn:be:fgov:certified-namespace:ehealth",
                Name = "urn:be:fgov:person:ssin:ehealth:1.0:nihii:nurse:nihii11"
            }
            );

            //receiver, a doctor, retrieves the key
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));
            KgssClient receiver = new KgssClient(store, binding, kgss, loggerFactory.CreateLogger<KgssClient>());
            receiver.Etk = sender.Etk;
            receiver.Kgss = sender.Kgss;

            var ex = Assert.ThrowsAny<ServiceException>(() => receiver.GetKey(senderKey.Id));

            Assert.Equal("NO_KEY_FOUND", ex.Code);
            Assert.NotEmpty(ex.Message);
        }
        
    }
}
