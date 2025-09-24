using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services
{
    public class GenSyncClient<Port> : ServiceClient<Port> where Port : class
    {
        private const string CIN_ENC_NS = "urn:be:cin:encrypted";

        public LicenseType License { get; set; }

        public CareProviderType CareProvider { get; set; }

        public bool IsTest { get; set; } = false;

        protected GenSyncClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<GenSyncClient<Port>> logger = null)
            : base(store, binding, remoteAddress, logger)
        {

        }
            

        protected SendRequest CreateRequest<SendRequest>(String inputRef, XmlElement value, EncryptionType? etee = null) where SendRequest : SendRequestType, new()
        {
            return CreateRequest<SendRequest>(inputRef, "text/xml", ToByteArray(value), etee);
        }

        protected SendRequest CreateRequest<SendRequest>(String inputRef, String contentType, byte[] value, EncryptionType? etee = null) where SendRequest : SendRequestType, new()
        {
            byte[] blobValue;
            string blobContentType;
            string contentEncryption;
            switch(etee)
            {
                case null:
                    blobValue = value;
                    blobContentType = contentType;
                    contentEncryption = null;
                    break;
                case EncryptionType.EncryptedForKnownBED:
                    blobValue = EncryptForBed(inputRef, value, contentType);
                    blobContentType = "text/plain";
                    contentEncryption = "encryptedForKnownBED";
                    break;
                default:
                    throw new NotImplementedException("Encryption type not supported yet");
            }

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
                        CareProvider = CareProvider ?? Sender?.ToCareProvider()
                    }
                },
                Detail = new BlobType()
                {
                    ContentType = blobContentType,
                    ContentEncoding = "none", //todo::support encodings
                    Value = blobValue,
                    ContentEncryption = contentEncryption    
                }
                //todo::support xades-t
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
                    return ToXmlElement(rspBody) as Response;
                default:
                    throw new NotImplementedException("Only text/xml responses are supported at this moment");
            }
        }

        protected byte[] EncryptForBed(String inputRef, byte[] clearText, string contentType)
        {
            XNamespace ns_e = "urn:be:cin:encrypted";
            var ekc = new XDocument(
                    new XElement(ns_e + "EncryptedKnownContent",
                        new XElement(ns_e + "BusinessContent",
                            new XAttribute("id", inputRef),
                            new XAttribute("ContentType", contentType),
                            new XAttribute("ContentEncoding", "none"),
                            Convert.ToBase64String(clearText)
                        )
                        //todo::support xades
                    )
            );
            //injectreply to etk as the first element if needed.
            if (Sender?.Etk != null) {
                ekc.Root.AddFirst(
                    new XElement(ns_e + "Reply-to-Etk",
                            Sender.Etk.GetEncodedAsString()
                        )
                );
            }
            return EncryptForService(ToMemoryStream(ToXmlElement(ekc)), Level.B_Level);
        }

        protected byte[] DecryptForKnown(byte[] cypherText, out string contentType)
        {
            XmlElement clearEl = Decrypt<XmlElement>(cypherText);

            XmlNamespaceManager encMngr = new XmlNamespaceManager(clearEl.OwnerDocument.NameTable);
            encMngr.AddNamespace("e", CIN_ENC_NS);

            string businessContentStr = clearEl.SelectSingleNode("/e:EncryptedKnownContent/e:BusinessContent", encMngr)?.InnerText;
            contentType = clearEl.SelectSingleNode("/e:EncryptedKnownContent/e:BusinessContent/@ContentType", encMngr)?.Value;
            //todo::support content encoding
            return Convert.FromBase64String(businessContentStr);
        }

    }
}
