using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Collections;
using Egelke.EHealth.Client.Pki;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Egelke.EHealth.Client.Pki.Test
{
    [TestClass]
    public class EHealthP12TestOnRealP12
    {
        private static EHealthP12 p12;

        [ClassInitialize]
        public static void setup(TestContext ctx)
        {
            p12 = new EHealthP12(@"EHealthP12\eHealth.acc-p12", File.ReadAllText(@"EHealthP12\eHealth.acc-p12.pwd"));
        }

        [TestMethod]
        public void AuthValue()
        {
            X509Certificate2 cert = p12["authentication"];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);

            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            Assert.AreEqual("Microsoft Enhanced RSA and AES Cryptographic Provider", privateKey.CspKeyContainerInfo.ProviderName);
            byte[] signature = privateKey.SignData(data, new SHA1Managed());
            Assert.IsNotNull(signature);
            Assert.AreEqual(2048/8, signature.Length);

            RSACryptoServiceProvider publicKey =  cert.PublicKey.Key as RSACryptoServiceProvider;
            Assert.IsTrue(publicKey.VerifyData(data, new SHA1Managed(), signature));
        }

        [TestMethod]
        public void EncValue()
        {
            X509Certificate2 auth = p12["authentication"];
            string key = p12.Where(e => e.Value.Issuer == auth.Subject).Select(e => e.Key).FirstOrDefault();
            X509Certificate2 cert = p12[key];
            Assert.IsNotNull(cert);
            Assert.IsTrue(cert.HasPrivateKey);


            byte[] data = Encoding.UTF8.GetBytes("My Test");

            RSACryptoServiceProvider publicKey = cert.PublicKey.Key as RSACryptoServiceProvider;
            byte[] enc = publicKey.Encrypt(data, false);
            Assert.IsNotNull(enc);

            RSACryptoServiceProvider privateKey = cert.PrivateKey as RSACryptoServiceProvider;
            Assert.AreEqual("Microsoft Enhanced RSA and AES Cryptographic Provider", privateKey.CspKeyContainerInfo.ProviderName);
            byte[] data_copy = privateKey.Decrypt(enc, false);
            Assert.AreEqual(data.Length,data_copy.Length);
            for (int i=0; i<data.Length; i++)
            {
                Assert.AreEqual(data[i], data_copy[i]);
            }
        }
    }
}
