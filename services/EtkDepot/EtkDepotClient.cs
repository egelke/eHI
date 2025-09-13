using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Etee.Crypto;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.Pkcs;

namespace Egelke.EHealth.Client.Services.EtkDepot
{
    public class EtkDepotClient : ClientBase<EtkDepotPortType>
    {

        private readonly ILogger<EtkDepotClient> _logger;


        public EtkDepotClient(EndpointAddress remoteAddress, ILogger<EtkDepotClient> logger = null)
            : base(new BasicHttpsBinding(), remoteAddress)
        {
            _logger = logger;
        }

        public EtkDepotClient(Binding binding, EndpointAddress remoteAddress, ILogger<EtkDepotClient> logger = null)
            : base(binding, remoteAddress)
        {
            _logger = logger;
        }

        public EncryptionToken[] GetEtk(params IdentifierType[] searchCriteria)
        {
            var req = new GetEtkRequest1()
            {
                GetEtkRequest = new GetEtkRequest()
                {
                    SearchCriteria = searchCriteria
                }
            };

            _logger?.LogInformation("Retreiving Etk(s) from depot, # criteria={}", searchCriteria?.Length);
            foreach (IdentifierType identifier in searchCriteria)
            {
                _logger?.LogDebug("Retreiving Etk from depot for {0}={1}, {2}",
                    identifier.Type, identifier.Value, identifier.ApplicationID);
            }
            var rsp = Channel.GetEtk(req)?.GetEtkResponse;
            _logger?.LogInformation("Retrived Etk(s) from depot: Status={0}, Message=\"{1}\", # items={1}",
                rsp?.Status?.Code, rsp?.Status?.Message?.FirstOrDefault()?.Value, rsp?.Items?.Length);

            if (rsp?.Status?.Code != "200")
            {
                _logger?.LogWarning("Failed to obtain ETK, Status Error returned {0}: {1}", rsp?.Status?.Code,
                    String.Join(", ", rsp?.Status?.Message?.Select(m => m?.Value)));
                throw new ServiceException(rsp?.Status?.Code, rsp?.Status?.Message?.FirstOrDefault()?.Value);
            }
            var errors = rsp.Items
                .OfType<ErrorType1>()
                .ToList();
            foreach (var error in errors) {
                _logger?.LogWarning("Failed to obtain ETK, Message Error returned {0}: {1}", error.Code, error.Message);
            }
            if (errors.Any())
            {
                var error = errors.First();
                throw new ServiceException(error.Code, error.Message);
            }

            for (int i = 0; i < rsp.Items.Length; i++)
            {
                if (rsp.Items[i] is MatchingEtk matching)
                {
                    IdentifierType criterial = rsp.GivenSearchCriteria[i];
                    _logger?.LogWarning("criteria returned multiple matches {0}={1}, {2}", criterial.Type, criterial.Value, criterial.ApplicationID);
                    throw new MultiMatchException(criterial, matching.Identifier);
                }
            }

            return rsp.Items
                .OfType<byte[]>()
                .Select(i => new EncryptionToken(i))
                .ToArray();
        }
    }
}
