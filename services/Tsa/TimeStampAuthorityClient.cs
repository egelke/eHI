using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.Tsa
{
    public class TimeStampAuthorityClient : ServiceClient<timestampauthorityPort>
    {


        public TimeStampAuthorityClient(EHealthP12 store, EndpointAddress remoteAddress, ILogger<TimeStampAuthorityClient> logger = null)
            : base(store, new EhBinding(), remoteAddress, logger)
        {

        }

        public TimeStampAuthorityClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<TimeStampAuthorityClient> logger = null)
            : base(store, binding, remoteAddress, logger)
        { }

        public SignResponse Stamp(SignRequest request)
        {
            var reqMsg = new stampRequest()
            {
                SignRequest = request
            };

            var rspMsg = Channel.stamp(reqMsg);

            return rspMsg.SignResponse;
        }
    }
}
