using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security;
using System.Security.Cryptography;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.Kgss
{
    public class KgssClient : ServiceClient<KgssPortType>
    {
        internal static readonly XNamespace NS_KGSS = "urn:be:fgov:ehealth:etee:kgss:1_0:protocol";

        public KgssClient(EHealthP12 store, EndpointAddress remoteAddress, ILogger<KgssClient> logger = null)
            : this(store, new BasicHttpsBinding(), remoteAddress, logger)
        { }

        public KgssClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<KgssClient> logger = null)
            : base(store, binding, remoteAddress, logger)
        {
            Service.Id = new IdentifierType()
            {
                Type = "CBE",
                Value = "0809394427",
                ApplicationID = "KGSS"
            };
        }

        public SecretKey GetNewKey(params CredentialType[] allowed)
        {
            var reqContent = CreateGetNewKeyRequestContent(allowed);
            var req = new GetNewKeyRequest1()
            {
                GetNewKeyRequest = new GetNewKeyRequest()
                {
                    SealedNewKeyRequest = new SealedContentType()
                    {
                        SealedContent = EncryptForService(reqContent)
                    }
                }
            };

            _logger.LogInformation("Requesting New Key from KGSS, for {0} allowed", allowed?.Length);
            var rsp = Channel.GetNewKey(req)?.GetNewKeyResponse;
            if (rsp?.Status?.Code != "200")
            {
                _logger.LogWarning("Failed to retrieve New Key from KGSS {0}: {1}", rsp?.Status?.Code, rsp?.Status?.Message);
                foreach(var error in rsp.Error)
                {
                    _logger.LogWarning("Error detail for New Key from KGSS {0}: {1}", error.Code, error.Message?.FirstOrDefault()?.Value);
                }
                throw new ServiceException(rsp?.Status?.Code, rsp?.Status?.Message);
            }
            if (rsp?.Error != null)
            {
                foreach (var error in rsp?.Error)
                {
                    _logger?.LogWarning("Failed to obtain ETK, Message Error returned {0}: {1}", error.Code, error.Message);
                }
                if (rsp?.Error?.Length > 0)
                {
                    var error = rsp.Error[0];
                    throw new ServiceException(error.Code, error?.Message?.Length > 0 ? error.Message[0]?.Value : null);
                }
            }

            _logger.LogInformation("Received New Key from KGSS with response id {0}", rsp?.Id);
            var rspContent = Decrypt<XmlElement>(rsp.SealedNewKeyResponse.SealedContent);
            return ParseGetNewKeyResponseContent(rspContent);
        }

        public SecretKey GetKey(byte[] id)
        {
            var reqContent = CreateGetKeyRequestContent(id);
            var req = new GetKeyRequest1()
            {
                GetKeyRequest = new GetKeyRequest()
                {
                    SealedKeyRequest = new SealedContentType()
                    {
                        SealedContent = EncryptForService(reqContent)
                    }
                }
            };

            _logger.LogInformation("Requesting Key from KGSS, with id {0}", Convert.ToBase64String(id));
            var rsp = Channel.GetKey(req)?.GetKeyResponse;
            if (rsp?.Status?.Code != "200")
            {
                _logger.LogWarning("Failed to retrieve Key from KGSS {0}: {1}", rsp?.Status?.Code, rsp?.Status?.Message);
                foreach (var error in rsp.Error)
                {
                    _logger.LogWarning("Error detailfor Key from KGSS {0}: {1}", error.Code, error.Message?.FirstOrDefault()?.Value);
                }
                throw new ServiceException(rsp?.Status?.Code, rsp?.Status?.Message);
            }
            if (rsp?.Error != null)
            {
                foreach (var error in rsp?.Error)
                {
                    _logger?.LogWarning("Failed to obtain ETK, Message Error returned {0}: {1}", error.Code, error.Message);
                }
                if (rsp?.Error?.Length > 0)
                {
                    var error = rsp.Error[0];
                    throw new ServiceException(error.Code, error?.Message?.Length > 0 ? error.Message[0]?.Value : null);
                }
            }

            _logger.LogInformation("Received New Key from KGSS with response id {0}", rsp?.Id);
            var rspContent = Decrypt<XmlElement>(rsp.SealedKeyResponse.SealedContent);
            var key = ParseGetKeyResponseContent(rspContent);

            return new SecretKey(id, key);
        }

        protected XmlElement CreateGetNewKeyRequestContent(CredentialType[] allowed)
        {
            var doc = new XDocument(
                new XElement(NS_KGSS + "GetNewKeyRequestContent",
                    allowed.Select(c => c.ToXElement(CredentialType.ROOTNAME_ALLOWED)),
                    new XElement(NS_KGSS + "ETK", Sender.Etk.GetEncodedAsString())
                    )
                );
            return ToXmlElement(doc);
        }

        protected XmlElement CreateGetKeyRequestContent(byte[] id)
        {
            var doc = new XDocument(
                new XElement(NS_KGSS + "GetKeyRequestContent",
                    new XElement(NS_KGSS + "KeyIdentifier", Convert.ToBase64String(id)),
                    new XElement(NS_KGSS + "ETK", Sender.Etk.GetEncodedAsString())
                    )
                );
            return ToXmlElement(doc);
        }

        protected SecretKey ParseGetNewKeyResponseContent(XmlElement rsp)
        {
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(rsp.OwnerDocument.NameTable);
            nsMngr.AddNamespace("kgss", NS_KGSS.NamespaceName);

            string id = rsp.SelectSingleNode("/kgss:GetNewKeyResponseContent/kgss:NewKeyIdentifier", nsMngr)?.InnerText;
            string value = rsp.SelectSingleNode("/kgss:GetNewKeyResponseContent/kgss:NewKey", nsMngr)?.InnerText;

            if (String.IsNullOrEmpty(id) || String.IsNullOrEmpty(value))
                throw new ArgumentException("No id or value found in the GetNewKeyResponseContent message", nameof(rsp));

            return new SecretKey(id, value);
        }

        protected byte[] ParseGetKeyResponseContent(XmlElement rsp)
        {
            XmlNamespaceManager nsMngr = new XmlNamespaceManager(rsp.OwnerDocument.NameTable);
            nsMngr.AddNamespace("kgss", NS_KGSS.NamespaceName);

            var keyString = rsp.SelectSingleNode("/kgss:GetKeyResponseContent/kgss:Key", nsMngr)?.InnerText;
            return keyString != null ? Convert.FromBase64String(keyString) : null;
        }

    }
}
