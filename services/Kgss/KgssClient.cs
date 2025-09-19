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
    public class KgssClient : ClientBase<KgssPortType>
    {
        internal static readonly XNamespace NS_KGSS = "urn:be:fgov:ehealth:etee:kgss:1_0:protocol";

        private static readonly Regex IdExp = new Regex("CN=\"(?<type>[^=]+)=(?<value>[^\",]+)(, ?(?<app>[^\"]+))?\"", RegexOptions.Compiled);

        private readonly ILogger<KgssClient> _logger;

        public EHealthP12 Store { get; }

        public EncryptionToken Etk { get; set; }

        public EncryptionToken Kgss {  get; set; }

        public KgssClient(EHealthP12 store, EndpointAddress remoteAddress, ILogger<KgssClient> logger = null)
            : this(store, new EhBinding(), remoteAddress, logger)
        { }

        public KgssClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<KgssClient> logger = null)
            : base(binding, remoteAddress)
        {
            Store = store;
            _logger = logger;

            base.ClientCredentials.ClientCertificate.Certificate = Store["authentication"];
        }

        public void InitEncryptionTokens(EtkDepotClient client)
        {
            var mySubject = Store["authentication"].Subject;
            GroupCollection myCnGroups = IdExp.Match(mySubject).Groups;
            Etk = client.GetEtk(new IdentifierType()
            {
                Type = myCnGroups["type"].Value,
                Value = myCnGroups["value"].Value,
                ApplicationID = myCnGroups["app"].Value
            })[0];

            Kgss = client.GetEtk(new IdentifierType()
            {
                Type = "CBE",
                Value = "0809394427",
                ApplicationID = "KGSS"
            })[0];
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
                        SealedContent = SealForKgss(reqContent)
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
            var rspContent = UnsealFromKgss(rsp.SealedNewKeyResponse.SealedContent);
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
                        SealedContent = SealForKgss(reqContent)
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
            var rspContent = UnsealFromKgss(rsp.SealedKeyResponse.SealedContent);
            var key = ParseGetKeyResponseContent(rspContent);

            return new SecretKey(id, key);
        }

        protected XmlElement CreateGetNewKeyRequestContent(CredentialType[] allowed)
        {
            var doc = new XDocument(
                new XElement(NS_KGSS + "GetNewKeyRequestContent",
                    allowed.Select(c => c.ToXElement(CredentialType.ROOTNAME_ALLOWED)),
                    new XElement(NS_KGSS + "ETK", Etk.GetEncodedAsString())
                    )
                );
            return ToXmlElement(doc);
        }

        protected XmlElement CreateGetKeyRequestContent(byte[] id)
        {
            var doc = new XDocument(
                new XElement(NS_KGSS + "GetKeyRequestContent",
                    new XElement(NS_KGSS + "KeyIdentifier", Convert.ToBase64String(id)),
                    new XElement(NS_KGSS + "ETK", Etk.GetEncodedAsString())
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

        private byte[] SealForKgss(XmlElement content)
        {
            var contentStream = new MemoryStream();
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false), // Disable BOM
                Indent = true,                      // Optional: pretty print
                OmitXmlDeclaration = false,         // Include XML declaration
                IndentChars = "  ",
                NewLineHandling = NewLineHandling.Replace
            };
            using (var writer = XmlWriter.Create(contentStream, settings))
            {
                content.WriteTo(writer);
            }
            contentStream.Position = 0;

            _logger.LogDebug("Sealing content for KGSS: {0}", Encoding.UTF8.GetString(contentStream.ToArray()));

            var sender = new EhDataSealerFactory().Create(Level.B_Level, Store);
            var contentCipherStream = sender.Seal(contentStream, Kgss);
            return new BinaryReader(contentCipherStream).ReadBytes((int)contentCipherStream.Length);
        }

        private XmlElement UnsealFromKgss(byte[] cipherContent)
        {
            var receiver = new DataUnsealerFactory().Create(Level.B_Level, Store);
            var result = receiver.Unseal(new MemoryStream(cipherContent));

            if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid)
                throw new SecurityException("Clear text not valid");
            if (result.SecurityInformation.TrustStatus == TrustStatus.None)
                throw new SecurityException("Clear text untrused");

            if (result.UnsealedData is MemoryStream ms)
            {
                _logger.LogDebug("Unealing content from KGSS: {0}", Encoding.UTF8.GetString(ms.ToArray()));
            }

            var encDoc = new XmlDocument();
            encDoc.PreserveWhitespace = true;
            encDoc.Load(result.UnsealedData);

            return encDoc.DocumentElement;
        }

        private XmlElement ToXmlElement(XDocument doc)
        {
            var xmlDoc = new XmlDocument();
            using (var reader = doc.CreateReader())
            {
                xmlDoc.Load(reader);
            }
            return xmlDoc.DocumentElement;
        }
    }
}
