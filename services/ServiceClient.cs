using System;
using System.Collections.Generic;
using System.IdentityModel.Claims;
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
using Egelke.EHealth.Client.Services.EtkDepot;
using Egelke.EHealth.Client.Sts;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;

namespace Egelke.EHealth.Client.Services
{
    public class ServiceClient<Port> : ClientBase<Port> where Port : class
    {
        protected readonly ILogger<ServiceClient<Port>> _logger;

        public static ServiceClient<Port> Create(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
        {
            return new ServiceClient<Port>(store, binding, remoteAddress, logger);
        }

        public PartyInfo Sender {  get; set; } = new PartyInfo();

        public PartyInfo Service { get; set; } = new PartyInfo();

        public EHealthP12 Store { get; set; }

        public List<EHealthP12> ExpiredStores { get; set; } = new List<EHealthP12>();

        protected ServiceClient(EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : this(null, new EhBinding(), remoteAddress, logger)
        { }

        protected ServiceClient(EHealthP12 store, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : this(store, new EhBinding(), remoteAddress, logger)
        { }

        protected ServiceClient(Binding binding, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : this(null, binding, remoteAddress, logger)
        { }


        protected ServiceClient(EHealthP12 store, Binding binding, EndpointAddress remoteAddress, ILogger<ServiceClient<Port>> logger = null)
            : base(Enrich(binding, store), remoteAddress)
        {
            _logger = logger;
            Store = store;

            if (store != null)
            {
                var idCert = Store["authentication"];
                Sender = PartyInfo.FromCertificate(idCert);
                ClientCredentials.ClientCertificate.Certificate = idCert;
            }
        }

        private static Binding Enrich(Binding binding, EHealthP12 store)
        {
            if (binding is EhBinding ehBinding && ehBinding.Security.Mode == EhSecurityMode.SamlFromWsTrust && store != null)
            {
                var id = PartyInfo.FromCertificate(store["authentication"]);
                if (id.HasId())
                {
                    foreach (var claim in id.ToAuthClaimSet())
                    {
                        ehBinding.Security.AuthClaims.Add(claim);
                    }
                }
            }
            return binding;
        }

        public void InitEncryptionTokens(EndpointAddress etkDepotAddress)
        {
            InitEncryptionTokens(new EtkDepotClient(etkDepotAddress));
        }

        public void InitEncryptionTokens(EtkDepotClient etkDepot)
        {
            if (etkDepot == null) throw new ArgumentNullException(nameof(etkDepot));

            if (Sender.Etk == null && Sender.HasId()) Sender.Etk = etkDepot.GetEtk(Sender.ToIdentifierType()).FirstOrDefault();
            if (Service.Etk == null && Service.HasId()) Service.Etk = etkDepot.GetEtk(Service.ToIdentifierType()).FirstOrDefault();
        }

        protected XmlElement ToXmlElement(byte[] bytes)
        {
            return ToXmlElement(new MemoryStream(bytes));
        }
        protected XmlElement ToXmlElement(Stream stream)
        {
            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(stream);

            return doc.DocumentElement;
        }

        protected XmlElement ToXmlElement(XDocument doc)
        {
            var xmlDoc = new XmlDocument();
            using (var reader = doc.CreateReader())
            {
                xmlDoc.Load(reader);
            }
            return xmlDoc.DocumentElement;
        }

        protected MemoryStream ToMemoryStream(XmlElement el)
        {
            var stream = new MemoryStream();
            var settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false), // Disable BOM
                Indent = true,                      // Optional: pretty print
                OmitXmlDeclaration = false,         // Include XML declaration
                IndentChars = "  ",
                NewLineHandling = NewLineHandling.Replace
            };
            using (var writer = XmlWriter.Create(stream, settings))
            {
                el.WriteTo(writer);

            }
            stream.Position = 0;

            return stream;
        }

        protected byte[] ToByteArray(XmlElement el)
        {
            return ToMemoryStream(el).ToArray();
        }

        protected byte[] EncryptForService<ClearType>(ClearType clearText, Level level = Level.B_Level) where ClearType : class
        {
            return Encrypt(clearText, level, Service.Etk);
        }

        protected byte[] Encrypt<ClearType>(ClearType clearText, Level level, params EncryptionToken[] recepients) where ClearType : class
        {
            Stream clearStream;
            switch (clearText)
            {
                case Stream stream:
                    clearStream = stream;
                    break;
                case byte[] bytes:
                    clearStream = new MemoryStream(bytes);
                    break;
                case XmlElement xmlElement:
                    clearStream = ToMemoryStream(xmlElement);
                    break;
                default:
                    throw new NotImplementedException("Clear text type not supported yet");
            }

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("encrypted content: {0}", new StreamReader(clearStream).ReadToEnd());
                clearStream.Position = 0;
            }

            var senderFactory = new DataSealerFactory();
            var sender = senderFactory.Create(level, base.ClientCredentials.ClientCertificate.Certificate);

            Stream cypherStream = sender.Seal(clearStream, recepients);

            byte[] cypherBytes = new BinaryReader(cypherStream).ReadBytes((int)cypherStream.Length);

            return cypherBytes;
        }

        protected ClearType Decrypt<ClearType>(byte[] cypherText) where ClearType : class
        {
            var receiverFactory = new DataUnsealerFactory();
            var receiver = receiverFactory.Create(Level.B_Level, Store, ExpiredStores.ToArray());

            Stream cypherStream = new MemoryStream(cypherText);
            UnsealResult result = receiver.Unseal(cypherStream);

            if (result.SecurityInformation.ValidationStatus != ValidationStatus.Valid)
                throw new SecurityException("Clear text not valid");
            if (result.SecurityInformation.TrustStatus == TrustStatus.None)
                throw new SecurityException("Clear text untrused");

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                String msg = new StreamReader(result.UnsealedData).ReadToEnd();
                _logger.LogDebug("decrypted content: {0}", msg);
                result.UnsealedData.Position = 0;
            }

            switch (typeof(ClearType))
            {
                case Type ct when ct == typeof(Stream):
                    return result.UnsealedData as ClearType;
                case Type ct when ct == typeof(byte[]):
                    return new BinaryReader(result.UnsealedData).ReadBytes((int)result.UnsealedData.Length) as ClearType;
                case Type ct when ct == typeof(XmlElement):
                    return ToXmlElement(result.UnsealedData) as ClearType;
                default:
                    throw new NotImplementedException("Clear text type not supported yet");
            }
        }
    }
}
