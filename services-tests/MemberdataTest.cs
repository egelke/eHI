using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IO;
using System.ServiceModel;
using System.Xml;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Helper;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Egelke.EHealth.Client.Services.Mda;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class MemberdataTest : BaseTest
    {
        private EndpointAddress mdaEp;

        private string nihii11;

        public MemberdataTest()
        {
            mdaEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/MyCareNet/MemberData/v1");

            nihii11 = "19997341001";
        }

        [Fact]
        public void McnDoctorClearFacets()
        {
            //configure the binding with the STS service
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));

            //configure the client for the MDA service
            var mcnMda = new McnMdaClient(binding, mdaEp, loggerFactory.CreateLogger<McnMdaClient>())
            {
                IsTest = true,
                License = new LicenseType()
                {
                    Username = File.ReadAllText("files/license.txt"),
                    Password = File.ReadAllText("files/license.pwd")
                },
                CareProvider = new CareProviderType()
                {
                    PhysicalPerson = new IdType1() //Depending on the list of wsdls this is either IdType or IdType1 (whatever comes first while generating)
                    {
                        Ssin = new ValueRefString()
                        {
                            Value = ssin
                        }
                    },
                    Nihii = new NihiiType()
                    {
                        Quality = "doctor",
                        Value = new ValueRefString()
                        {
                            Value = nihii11
                        }
                    }
                }
            };
            mcnMda.ClientCredentials.ClientCertificate.Certificate = idCert;
            mcnMda.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            //Use the interface
            IMda target = mcnMda;

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
        public void Encrypted()
        {
            //configure the binding with the STS service
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));

            //configure the client for the MDA service
            var mcnMda = new McnMdaClient(binding, mdaEp, loggerFactory.CreateLogger<McnMdaClient>())
            {
                IsTest = true,
                License = new LicenseType()
                {
                    Username = File.ReadAllText("files/license.txt"),
                    Password = File.ReadAllText("files/license.pwd")
                },
                CareProvider = new CareProviderType()
                {
                    PhysicalPerson = new IdType1() //Depending on the list of wsdls this is either IdType or IdType1 (whatever comes first while generating)
                    {
                        Ssin = new ValueRefString()
                        {
                            Value = ssin
                        }
                    },
                    Nihii = new NihiiType()
                    {
                        Quality = "doctor",
                        Value = new ValueRefString()
                        {
                            Value = nihii11
                        }
                    }
                },
                Encryption = new EteeConfig()
                {
                    Etk = new EncryptionToken(File.ReadAllBytes("files/mycarenet.etk")),
                    Keys = new List<EHealthP12>() //uses authentication-certificate of first p12 to sign
                    {
                        store 
                    }
                },
                Decryption = new EteeConfig()
                {
                    Etk = new EncryptionToken(File.ReadAllBytes("files/79021802145.etk")),
                    Keys = new List<EHealthP12>() //uses encryption-certificate of any p12 to decrypt the response
                    {
                        store
                    }
                }
            };
            mcnMda.ClientCredentials.ClientCertificate.Certificate = idCert;
            mcnMda.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            //Use the interface
            IMda target = mcnMda;

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
        public void McnDoctorEncryptedFacets()
        {
            //configure the binding with the STS service
            var binding = new EhBinding(loggerFactory.CreateLogger<CustomSecurity>());
            binding.Security.Mode = EhSecurityMode.SamlFromWsTrust;
            binding.Security.IssuerAddress = wstEp;
            binding.Security.SessionCertificate.Certificate = sessionCert;
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:identification-namespace}urn:be:fgov:ehealth:1.0:certificateholder:person:ssin", ssin, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:doctor:boolean", null, AuthClaimSet.Dialect));
            binding.Security.AuthClaims.Add(new Claim("{urn:be:fgov:certified-namespace:ehealth}urn:be:fgov:person:ssin:ehealth:1.0:doctor:nihii11", null, AuthClaimSet.Dialect));

            //configure the client for the MDA service
            var mcnMda = new McnMdaClient(binding, mdaEp, loggerFactory.CreateLogger<McnMdaClient>())
            {
                IsTest = true,
                License = new LicenseType()
                {
                    Username = File.ReadAllText("files/license.txt"),
                    Password = File.ReadAllText("files/license.pwd")
                },
                CareProvider = new CareProviderType()
                {
                    PhysicalPerson = new IdType1() //Depending on the list of wsdls this is either IdType or IdType1 (whatever comes first while generating)
                    {
                        Ssin = new ValueRefString()
                        {
                            Value = ssin
                        }
                    },
                    Nihii = new NihiiType()
                    {
                        Quality = "doctor",
                        Value = new ValueRefString()
                        {
                            Value = nihii11
                        }
                    }
                },
                Decryption = new EteeConfig()
                {
                    Etk = new EncryptionToken(File.ReadAllBytes("files/79021802145.etk")),
                    Keys = new List<EHealthP12>()
                    {
                        store
                    }
                }
            };
            mcnMda.ClientCredentials.ClientCertificate.Certificate = idCert;
            mcnMda.Endpoint.EndpointBehaviors.Add(new LoggingEndpointBehavior(loggerFactory.CreateLogger<LoggingMessageInspector>()));

            //Use the interface
            IMda target = mcnMda;

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