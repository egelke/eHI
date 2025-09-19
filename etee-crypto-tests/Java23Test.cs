using Egelke.EHealth.Client.Pki;
using Egelke.EHealth.Etee.Crypto;
using Egelke.EHealth.Etee.Crypto.Sender;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace etee_crypto_tests
{
    public class Java23Test
    {
        private const String JAVA_PATH = "C:\\Program Files\\Java\\jdk-21\\bin\\java.exe";

        protected ILoggerFactory loggerFactory;

        protected EHealthP12 sender;

        protected EncryptionToken receiver;

        protected EhDataSealerFactory factory;

        protected Stream clearStream;

        public Java23Test()
        {
            loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(LogLevel.Trace);
            });

            sender = new EHealthP12("files/SSIN=79021802145 20250514-082150.acc.p12", File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"));

            receiver = new EncryptionToken(File.ReadAllBytes("files/79021802145.etk"));

            factory = new EhDataSealerFactory(loggerFactory);

            //clearStream = new MemoryStream(Encoding.UTF8.GetBytes(clearMessage));
        }

        [Fact]
        public void LevelBFromDotNetToJava()
        {
            IDataSealer target = factory.Create(Level.B_Level, sender);

            Stream rsp;
            using (var fs = File.OpenRead("files/send-clear.txt")) {
                rsp = target.Seal(fs, receiver);
            }

            using (FileStream cipherStream = new FileStream("files/cipher.bin", FileMode.Create, FileAccess.ReadWrite))
            {
                rsp.CopyTo(cipherStream);
            }

            RunJava("2.3.0",
                new String[] { "-Djavax.net.ssl.trustStore=files/cacerts" },
                "receive", 
                "\"files/SSIN=79021802145 20250514-082150.acc.p12\"",
                File.ReadAllText("files/SSIN=79021802145 20250514-082150.acc.p12.pwd"),
                "files/cipher.bin",
                "files/rec-clear.txt");
        }

        private void RunJava(String version, String[] jvmArgs, params String[] args)
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.FileName = JAVA_PATH ?? "java.exe";
            p.StartInfo.Arguments = String.Join(" ", jvmArgs) + " -jar files/etee-" +version+".jar " + String.Join(" ", args);
            p.StartInfo.WorkingDirectory = Environment.CurrentDirectory;
            p.OutputDataReceived += (sender, outArgs) =>
            {
                if (outArgs.Data != null)
                    Console.WriteLine(outArgs.Data);
            };
            p.ErrorDataReceived += (sender, outArgs) =>
            {
                if (outArgs.Data != null)
                    Console.Write(outArgs.Data);
            };

            p.Start();
            p.BeginErrorReadLine();
            p.BeginOutputReadLine(); // Start async read
            p.WaitForExit();
            Assert.Equal(0, p.ExitCode);
        }

    }
}
