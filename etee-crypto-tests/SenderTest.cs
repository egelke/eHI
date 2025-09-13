using System;
using System.IO;
using System.Text;
using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Sender;
using Microsoft.Extensions.Logging;
using Xunit;

namespace etee_crypto_tests
{
    public class SenderTest
    {
        const String clearMessage = "This is a secret message from Alice for Bob";

        protected ILoggerFactory loggerFactory;

        protected EHealthP12 sender;

        protected EncryptionToken rsaTarget;

        protected EhDataSealerFactory factory;

        protected Stream clearStream;


        public SenderTest()
        {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            sender = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));

            rsaTarget = new EncryptionToken(File.ReadAllBytes("files/mycarenet.etk"));

            factory = new EhDataSealerFactory(loggerFactory);

            clearStream = new MemoryStream(Encoding.UTF8.GetBytes(clearMessage));
        }

        [Fact]
        public void RsaBLevel()
        {
            IDataSealer target = factory.Create(Level.B_Level, sender);

            Stream rsp = target.Seal(clearStream, rsaTarget);

        }
    }
}