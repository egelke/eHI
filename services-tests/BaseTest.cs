using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Egelke.EHealth.Client;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class BaseTest
    {
        protected ILoggerFactory loggerFactory;

        protected EndpointAddress wstAddress;

        public BaseTest()
        {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            wstAddress = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IAM/SecurityTokenService/v1");
        }
    }
}
