using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Ocsp;

namespace Egelke.EHealth.Client.Services
{
    public class GenSyncClient<Port> : ClientBase<Port> where Port : class
    {
        private const string CIN_ENC_NS = "urn:be:cin:encrypted";

        protected readonly ILogger<GenSyncClient<Port>> _logger;

        protected GenSyncClient(Binding binding, EndpointAddress remoteAddress, ILogger<GenSyncClient<Port>> logger = null)
            : base(binding, remoteAddress)
        {
            _logger = logger;
        }

        public LicenseType License { get; set; }

        public CareProviderType CareProvider { get; set; }

        public bool IsTest { get; set; } = false;

        public EteeConfig Encryption { get; set; } = new EteeConfig();

        public EteeConfig Decryption { get; set; } = new EteeConfig();


        protected XmlElement ToXmlElement(XDocument doc)
        {
            return ToXmlDocument(doc).DocumentElement;
        }

        protected XmlDocument ToXmlDocument(XDocument doc)
        {
            var xmlDoc = new XmlDocument();
            using (var reader = doc.CreateReader())
            {
                xmlDoc.Load(reader);
            }
            return xmlDoc;
        }

        protected SendRequest CreateRequest<SendRequest>(String inputRef, XmlElement reqEl, bool encrypt = false) where SendRequest : SendRequestType, new()
        {
            var reqBodyStream = new MemoryStream();
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false), // Disable BOM
                Indent = true,                      // Optional: pretty print
                OmitXmlDeclaration = false,         // Include XML declaration
                IndentChars = "  ",
                NewLineHandling = NewLineHandling.Replace
            };
            using (var writer = XmlWriter.Create(reqBodyStream, settings))
            {
                reqEl.WriteTo(writer);
                
            }

            return CreateRequest<SendRequest>(inputRef, "text/xml", reqBodyStream.ToArray());
        }

        protected SendRequest CreateRequest<SendRequest>(String inputRef, String contentType, byte[] value, bool encrypt = false) where SendRequest : SendRequestType, new()
        {
            var req = new SendRequest()
            {
                Id = "_" + Guid.NewGuid().ToString(),
                CommonInput = new CommonInputType()
                {
                    InputReference = inputRef,
                    Request = new RequestType1()
                    {
                        IsTest = IsTest,
                    },
                    Origin = new OriginType()
                    {
                        Package = new PackageType()
                        {
                            License = License
                        },
                        CareProvider = CareProvider
                    }
                },
                Detail = new BlobType()
                {
                    ContentType = contentType,
                    ContentEncoding = "none",
                    Value = value,
                }
            };

            return req;
        }

        protected Response HandleReturn<Response>(ResponseReturnType rsp) where Response : class
        {
            _logger?.LogInformation("Received response for {0} with out-ref {1} and nip-ref {2}",
                rsp.CommonOutput.InputReference,
                rsp?.CommonOutput?.OutputReference,
                rsp?.CommonOutput?.NIPReference);

            byte[] rspBody;
            string contentType;
            switch (rsp?.Detail?.ContentEncryption)
            {
                case null:
                    rspBody = rsp?.Detail?.Value;
                    contentType = rsp?.Detail?.ContentType;
                    break;
                case "encryptedForKnownRecipient":
                    //check content type, should be text/plain (a somewhat dubious choice)
                    if (rsp?.Detail?.ContentType != "text/plain") throw new InvalidOperationException("content type not supported for encrypted content: " + rsp?.Detail?.ContentType);
                    rspBody = DecryptForKnown(rsp?.Detail?.Value, out contentType);
                    break;
                default:
                    throw new NotImplementedException("encryption is not yet supported");
            }

            _logger?.LogDebug("Recieved respronse for {0}: {1}",
                rsp.CommonOutput.InputReference,
                Encoding.UTF8.GetString(rspBody));

            switch (typeof(Response))
            {
                case Type r when r == typeof(XmlElement):
                    if (contentType != "text/xml" && contentType != "application/xml") throw new InvalidOperationException("content type not matching the requested return type: "+ contentType);
                    var rspDoc = new XmlDocument();
                    rspDoc.PreserveWhitespace = true;
                    rspDoc.Load(new MemoryStream(rspBody));
                    return rspDoc.DocumentElement as Response;
                default:
                    throw new NotImplementedException("Only text/xml responses are supported at this moment");
            }
        }

        private byte[] DecryptForKnown(byte[] cypherText, out string contentType)
        {
            var receiverFactory = new DataUnsealerFactory();
            var receiver = receiverFactory.Create(Level.B_Level, Decryption.Keys.ToArray());

            Stream cypherStream = new MemoryStream(cypherText);
            UnsealResult result = receiver.Unseal(cypherStream);

            if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid)
                throw new SecurityException("Clear text not valid");
            if (result.SecurityInformation.TrustStatus == TrustStatus.None)
                throw new SecurityException("Clear text untrused");

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                String msg = new StreamReader(result.UnsealedData).ReadToEnd();
                _logger.LogDebug("encrypted content: {0}", msg);
                result.UnsealedData.Position = 0;
            }

            var encDoc = new XmlDocument();
            encDoc.PreserveWhitespace = true;
            encDoc.Load(result.UnsealedData);

            XmlNamespaceManager encMngr = new XmlNamespaceManager(encDoc.NameTable);
            encMngr.AddNamespace("e", CIN_ENC_NS);

            string businessContentStr = encDoc.SelectSingleNode("/e:EncryptedKnownContent/e:BusinessContent", encMngr)?.InnerText;
            contentType = encDoc.SelectSingleNode("/e:EncryptedKnownContent/e:BusinessContent/@ContentType", encMngr)?.Value;
            //todo::support content encoding
            return Convert.FromBase64String(businessContentStr);
        }

    }
}
