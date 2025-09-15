using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Client.Services.Tsa;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Receiver;
using Egelke.EHealth.Etee.Crypto.Sender;
using Egelke.EHealth.Etee.Crypto.Status;
using Microsoft.Extensions.Logging;
using Xunit;
using TrustStatus = Egelke.EHealth.Etee.Crypto.Status.TrustStatus;

namespace etee_crypto_tests
{
    public class RoundTrip
    {
        private const String clearMessage = "This is a secret message to myself";

        public static IEnumerable<object[]> Credentials()
        {
            return new List<object[]>()
            {
                new object[] {
                    new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd")),
                    new EncryptionToken(File.ReadAllBytes("files/79021802145.etk")),
                    new Rfc3161TimestampProvider(new Uri("http://tsa.belgium.be/connect"))
                }
            };
        }

        protected Stream clearStream;

        protected EhDataSealerFactory senderFactory;

        protected DataUnsealerFactory receiverFactory;

        public RoundTrip()
        {
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            senderFactory = new EhDataSealerFactory(loggerFactory);

            receiverFactory = new DataUnsealerFactory(loggerFactory);

            clearStream = new MemoryStream(Encoding.UTF8.GetBytes(clearMessage));


            //tsa = new TimeStampAuthorityClient(new EndpointAddress("https://services-acpt.ehealth.fgov.be/TimestampAuthority/v2"));
            //tsp = new EHealthTimestampProvider(tsa);
        }

        [Theory]
        [MemberData(nameof(Credentials))]
        public void BLevel(EHealthP12 senderId, EncryptionToken receiverId, ITimestampProvider tsp)
        {
            IDataSealer sealer = senderFactory.Create(Level.B_Level, senderId);

            Stream cypherStream = sealer.Seal(clearStream, receiverId);

            IDataUnsealer receiver = receiverFactory.Create(Level.B_Level, senderId);

            UnsealResult result = receiver.Unseal(cypherStream);

            Assert.Equal(senderId["authentication"], result.SigningCertificate);
            Assert.Equal(senderId["authentication"].Subject, result.RecipientCertificate.Issuer);

            Assert.Null(result.SealValidUntil);

            Assert.Equal(TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.Empty(result.SecurityInformation.SecurityViolations);

            Assert.Equal(clearMessage, new StreamReader(result.UnsealedData).ReadToEnd());
        }

        [Theory]
        [MemberData(nameof(Credentials))]
        public void TLevel(EHealthP12 senderId, EncryptionToken receiverId, ITimestampProvider tsp)
        {
            IDataSealer sealer = senderFactory.Create(Level.T_Level, tsp, senderId);

            Stream cypherStream = sealer.Seal(clearStream, receiverId);

            IDataUnsealer receiver = receiverFactory.Create(Level.T_Level, senderId);

            UnsealResult result = receiver.Unseal(cypherStream);

            Assert.Equal(senderId["authentication"], result.SigningCertificate);
            Assert.Equal(senderId["authentication"].Subject, result.RecipientCertificate.Issuer);

            Assert.NotNull(result.SealValidUntil);

            Assert.Equal(TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.Empty(result.SecurityInformation.SecurityViolations);

            Assert.Equal(clearMessage, new StreamReader(result.UnsealedData).ReadToEnd());
        }

        [Theory]
        [MemberData(nameof(Credentials))]
        public void LTLevel(EHealthP12 senderId, EncryptionToken receiverId, ITimestampProvider tsp)
        {
            IDataSealer sealer = senderFactory.Create(Level.LT_Level, tsp, senderId);

            Stream cypherStream = sealer.Seal(clearStream, receiverId);

            IDataUnsealer receiver = receiverFactory.Create(Level.LT_Level, senderId);

            UnsealResult result = receiver.Unseal(cypherStream);

            Assert.Equal(senderId["authentication"], result.SigningCertificate);
            Assert.Equal(senderId["authentication"].Subject, result.RecipientCertificate.Issuer);

            Assert.NotNull(result.SealValidUntil);

            Assert.Equal(TrustStatus.Full, result.SecurityInformation.TrustStatus);
            Assert.Equal(ValidationStatus.Valid, result.SecurityInformation.ValidationStatus);
            Assert.Empty(result.SecurityInformation.SecurityViolations);

            Assert.Equal(clearMessage, new StreamReader(result.UnsealedData).ReadToEnd());
        }
    }
}
