using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class BaseTest
    {
        protected ILoggerFactory loggerFactory;

        protected X509Certificate2 idCert;

        protected X509Certificate2 sessionCert;

        protected string ssin;

        protected EndpointAddress wstEp;

        public BaseTest() {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            wstEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");

            var p12 = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));
            idCert = p12["authentication"];
            sessionCert = null;

            Match match = Regex.Match(idCert.Subject, @"(SSIN|SERIALNUMBER)=(\d{11})");
            Assert.True(match.Success, "need an ssin in the cert subject (is an eID available?)");
            ssin = match.Groups[2].Value;
        }
    }
}
