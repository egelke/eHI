using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Claims;
using System.IO;
using System.ServiceModel;
using System.Xml;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Client.Services.Mda;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace services_tests
{
    public class McnMdaDoctorTest : BaseTest
    {
        private MdaClient target;

        public McnMdaDoctorTest()
        {
            var store = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));

            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstAddress;
            //binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));
            target = new MdaClient(store, binding, new EndpointAddress("https://services-acpt.ehealth.fgov.be/MyCareNet/MemberData/v1"), loggerFactory.CreateLogger<MdaClient>())
            {
                IsTest = true,
                License = new LicenseType()
                {
                    Username = File.ReadAllText("files/license.txt"),
                    Password = File.ReadAllText("files/license.pwd")
                }
            };
            target.Sender.Quality = "DOCTOR";
            target.Sender.Nihii11 = "19997341001";
            target.Service.Id = new IdentifierType()
            {
                Type = "CBE",
                Value = "0820563481",
                ApplicationID = "MYCARENET"
            };

            target.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            target.InitEncryptionTokens(new EtkDepotClient(new EndpointAddress("https://services-acpt.ehealth.fgov.be/EtkDepot/v1")));
        }

        [Fact]
        public void ClearRequestAndResponse()
        {
            //Create the query
            XmlElement query = target.CreateQuery(
                File.ReadAllText("files/patient.ssin"),
                DateTime.Today.AddDays(-2),
                DateTime.Today.AddDays(-1),
                Facet.CreateInsurability(Dimension.VALUE_INFORMATION, Dimension.VALUE_OTHER)
                );

            //Consult to get the assertions
            var assertions = target.Consult(query);

            //Verify
            Assert.NotEmpty(assertions);
        }

        [Fact]
        public void EncryptedRequest()
        {
            //Create the query
            XmlElement query = target.CreateQuery(
                File.ReadAllText("files/patient.ssin"),
                DateTime.Today.AddDays(-2),
                DateTime.Today.AddDays(-1),
                Facet.CreateInsurability(Dimension.VALUE_INFORMATION, Dimension.VALUE_OTHER)
                );

            //Consult to get the assertions
            var assertions = target.Consult(query, true);

            //Verify
            Assert.NotEmpty(assertions);
        }

        [Fact]
        public void ClearRequestEncryptedResponse()
        {
            //Create the query
            XmlElement query = target.CreateQuery(
                File.ReadAllText("files/patient.ssin"),
                DateTime.Today.AddDays(-2),
                DateTime.Today.AddDays(-1),
                Facet.CreateInsurability(Dimension.VALUE_INFORMATION, Dimension.VALUE_OTHER),
                Facet.CreateCarePath(Dimension.VALUE_DIABETES, Dimension.VALUE_RENALINSUFFICIENCY)
                );

            //Consult to get the assertions
            var assertions = target.Consult(query);

            //Verify
            Assert.NotEmpty(assertions);
        }


    }
}