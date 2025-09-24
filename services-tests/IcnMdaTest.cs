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
using Egelke.EHealth.Client.Services.Mda;
using Egelke.EHealth.Client.Sts;
using Microsoft.Extensions.Logging;
using Xunit;

namespace services_tests
{
    public class IcnMdaTest : BaseTest
    {

        private MdaClient target;

        public IcnMdaTest()
        {
            //mdaEp = new EndpointAddress("https://services-acpt.ehealth.fgov.be/IrisCareNet/MemberData/v1");
        }

        
    }
}
