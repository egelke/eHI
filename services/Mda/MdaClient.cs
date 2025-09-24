using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Runtime;
using System.Security;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Egelke.EHealth.Client.Pki;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services.Mda
{

    public class MdaClient : GenSyncClient<MycarenetMemberDataPortType>
    {
        private const string SAML2P_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

        private const string SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

        private const string CIN_TYPES_NS = "urn:be:cin:types:v1";


        public MdaClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<MdaClient> logger = null) 
            : base(store, binding, remoteAddress, logger)
        { }

        public XmlElement CreateQuery(string ssin, DateTime start, DateTime end, params Facet[] facets)
        {
            string reqId = (IsTest ? "T" : "P") + "MDA" + DateTime.Now.ToString("yyyyMMddHHmmss");
            var cp = CareProvider ?? Sender?.ToCareProvider();

            XNamespace ns_samlp = SAML2P_NS;
            XNamespace ns_saml = SAML2_NS;
            XNamespace ns_xsi = "http://www.w3.org/2001/XMLSchema-instance";
            var reqBody = new XDocument(
                    new XElement(ns_samlp + "AttributeQuery",
                        new XAttribute("ID", "_" + reqId),
                        new XAttribute("Version", "2.0"),
                        new XAttribute("IssueInstant", DateTime.UtcNow.ToString("s")),
                        new XAttribute(XNamespace.Xmlns + "samlp", ns_samlp),
                        new XAttribute(XNamespace.Xmlns + "saml", ns_saml),
                        new XElement(ns_saml + "Issuer",
                            new XAttribute("Format", "urn:be:cin:nippin:nihii11"),
                            cp.Nihii.Value.Value
                        ),
                        new XElement(ns_samlp + "Extensions",
                            new XAttribute(XNamespace.Xmlns + "ext", Facet.EXT_NS),
                            new XAttribute(XNamespace.Xmlns + "xsi", ns_xsi),
                            new XAttribute(ns_xsi + "type", "ext:ExtensionsType"),
                            facets.Select(f => f.ToXElement()).ToArray()
                        ),
                        new XElement(ns_saml + "Subject",
                            new XElement(ns_saml + "NameID",
                                new XAttribute("Format", "urn:be:fgov:person:ssin"),
                                ssin
                            ),
                            new XElement(ns_saml + "SubjectConfirmation",
                                new XAttribute("Method", "urn:be:cin:nippin:memberIdentification"),
                                new XElement(ns_saml + "SubjectConfirmationData",
                                    new XAttribute("NotBefore", start.ToString("s")),
                                    new XAttribute("NotOnOrAfter", end.ToString("s"))
                                )
                            )
                        )
                    )
                );

            return ToXmlElement(reqBody);
        }

        public IEnumerable<XmlElement> Consult(XmlElement query, bool etee = false)
        {
            XmlNamespaceManager reqMngr = new XmlNamespaceManager(query.OwnerDocument.NameTable);
            reqMngr.AddNamespace("saml2p", SAML2P_NS);
            reqMngr.AddNamespace("saml2", SAML2_NS);

            string reqId = query.SelectSingleNode("/saml2p:AttributeQuery/@ID", reqMngr)?.Value?.Substring(1);

            var req = CreateRequest<SendRequestMemberDataType>(reqId, query, etee ? EncryptionType.EncryptedForKnownBED : (EncryptionType?) null);
            _logger?.LogInformation("Calling MyCareNet MDA, ref={0}", req.CommonInput.InputReference);
            _logger?.LogDebug("Calling MyCareNet MDA {0} with query: {1}", req.CommonInput.InputReference, query.OuterXml);

            ResponseReturnType rtn = Channel.memberDataConsultation(
                    new memberDataConsultationRequest() {  MemberDataConsultationRequest = req }
                )?.MemberDataConsultationResponse?.Return;

            XmlElement rsp = HandleReturn<XmlElement>( rtn );

            XmlNamespaceManager rspMngr = new XmlNamespaceManager(rsp.OwnerDocument.NameTable);
            rspMngr.AddNamespace("saml2p", SAML2P_NS);
            rspMngr.AddNamespace("saml2", SAML2_NS);
            rspMngr.AddNamespace("t", CIN_TYPES_NS);
            

            string statusCode = rsp.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusCode/@Value", rspMngr)?.Value;
            if (statusCode != "urn:oasis:names:tc:SAML:2.0:status:Success")
            {
                string statusMessage = rsp.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusMessage", rspMngr)?.InnerText;

                string faultCode = rsp.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusDetail/Fault/t:FaultCode", rspMngr)?.InnerText;
                string faultMessage = rsp.SelectSingleNode("/saml2p:Response/saml2p:Status/saml2p:StatusDetail/Fault/t:Message", rspMngr)?.InnerText;

                throw new ServiceException(faultCode ?? statusCode, faultMessage ?? statusMessage);
            }

            return rsp.SelectNodes("/saml2p:Response/saml2:Assertion", rspMngr).Cast<XmlElement>();
        }

        
    }
}
