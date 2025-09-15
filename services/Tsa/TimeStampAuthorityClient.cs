using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.Tsa
{
    public class TimeStampAuthorityClient : ClientBase<timestampauthorityPort>
    {
        private readonly ILogger<TimeStampAuthorityClient> _logger;

        public TimeStampAuthorityClient(EndpointAddress remoteAddress, ILogger<TimeStampAuthorityClient> logger = null)
            : base(new EhBinding(), remoteAddress)
        {
            _logger = logger;
        }

        public TimeStampAuthorityClient(Binding binding, EndpointAddress remoteAddress, ILogger<TimeStampAuthorityClient> logger = null)
            : base(binding, remoteAddress)
        {
            _logger = logger;
        }

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
