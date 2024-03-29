using Egelke.EHealth.Client.Helper;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Xml;

namespace Egelke.EHealth.Client.Security
{
    /// <summary>
    /// Add the actual security headers to the message after the other channels created the message.
    /// </summary>
    /// <seealso href="https://github.com/dotnet/wcf/blob/main/src/System.Private.ServiceModel/src/System/ServiceModel/Security/SecurityAppliedMessage.cs">Insipred on</seealso>
    public class CustomSecurityAppliedMessage : Message
    {
        private ILogger _logger;

        private Message _innerMessage;

        /// <summary>
        /// Constructor that wraps a message.
        /// </summary>
        /// <param name="innerMessage">Message from the previous channels</param>
        public CustomSecurityAppliedMessage(ILogger logger, Message innerMessage)
        {
            _logger = logger;
            _innerMessage = innerMessage;
        }

        public ClientCredentials ClientCredentials { get; set; }

        public SecurityVersion MessageSecurityVersion { get; set; }

        public SignParts SignParts { get; set; }

        /// <inheritdoc/>
        public override bool IsEmpty
        {
            get
            {
                return _innerMessage.IsEmpty;
            }
        }

        /// <inheritdoc/>
        public override bool IsFault
        {
            get { return _innerMessage.IsFault; }
        }

        /// <inheritdoc/>
        public override MessageHeaders Headers
        {
            get { return _innerMessage.Headers; }
        }

        /// <inheritdoc/>
        public override MessageProperties Properties
        {
            get { return _innerMessage.Properties; }
        }

        /// <inheritdoc/>
        public override MessageVersion Version
        {
            get { return _innerMessage.Version; }
        }

        /// <inheritdoc/>
        protected override void OnClose()
        {
            base.OnClose();
            _innerMessage.Close();
        }

        /// <summary>
        /// Called to write the message to the writer.  This implementation add the security headers.
        /// </summary>
        /// <remarks>
        /// It writes the message to memory (of temp file) in order to do so.
        /// </remarks>
        /// <param name="writer">The xml writer to write the message too</param>
        protected override void OnWriteMessage(XmlDictionaryWriter writer)
        {
            using (var memStream = new MemoryStream())
            {
                var wss = WSS.Create(MessageSecurityVersion);

                //Write the document without security headers in memory
                using (var memWriter = XmlDictionaryWriter.CreateTextWriter(memStream, Encoding.UTF8, false))
                {
                    _innerMessage.WriteMessage(memWriter);
                }
                memStream.Position = 0;
                if (_logger != null && _logger.IsEnabled(LogLevel.Trace))
                {
                    String org = new StreamReader(memStream).ReadToEnd();
                    _logger.LogTrace(org);
                    memStream.Position = 0;
                }

                //parse the document to add the security headers
                var env = new XmlDocument
                {
                    PreserveWhitespace = true
                };
                env.Load(memStream);

                //Make preperations to do some xpath
                string soapPrefix = env.DocumentElement.Prefix;
                string soapNs = env.DocumentElement.NamespaceURI;
                XmlNamespaceManager nsmgr = new XmlNamespaceManager(env.NameTable);
                nsmgr.AddNamespace("s", soapNs);

                //Find the body, add an id if needed.
                XmlElement body = (XmlElement)env.DocumentElement.SelectSingleNode("./s:Body", nsmgr);
                string bodyIdValue = body.GetAttribute("Id", wss.UtilityNs);
                if (bodyIdValue == string.Empty)
                {
                    bodyIdValue = "uuid-" + Guid.NewGuid().ToString("D");
                    var bodyId = env.CreateAttribute(wss.UtilityPrefix, "Id", wss.UtilityNs);
                    bodyId.Value = bodyIdValue;
                    body.SetAttributeNode(bodyId);
                }

                //Find the soap header, create if needed.
                XmlElement header = (XmlElement)env.DocumentElement.SelectSingleNode("./s:Header", nsmgr);
                if (header == null)
                {
                    header = env.CreateElement(soapPrefix, "Header", soapNs);
                    env.DocumentElement.InsertBefore(header, env.DocumentElement.FirstChild);
                }

                //Apply the security
                //see github\dotnet\wcf\src\System.Private.ServiceModel\src\System\IdentityModel\Tokens\SecurityTokenTypes.cs
                
                SecurityTokenRequirement requirement = new SecurityTokenRequirement()
                {
                    TokenType = "http://schemas.microsoft.com/ws/2006/05/identitymodel/tokens/X509Certificate"
                };

                //SecurityTokenResolver resolver;
                //var tokenManager = ClientCredentials.CreateSecurityTokenManager();
                //var authenticator = tokenManager.CreateSecurityTokenAuthenticator(requirement, out resolver);
                //var provider = tokenManager.CreateSecurityTokenProvider(requirement);
                wss.ApplyOnRequest(ref header, bodyIdValue, ClientCredentials.ClientCertificate.Certificate, SignParts);

                //Write the modified version with security header to the original streams.
                env.Save(writer);
            }
        }

        /// <inheritdoc/>
        protected override void OnWriteBodyContents(XmlDictionaryWriter writer)
        {
            _innerMessage.WriteBodyContents(writer);
        }
    }
}
