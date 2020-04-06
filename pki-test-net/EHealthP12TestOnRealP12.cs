﻿using System;
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
            p12 = new EHealthP12(@"EHealthP12\SSIN=79021802145.p12", File.ReadAllText(@"EHealthP12\SSIN=79021802145.txt"));
            //p12 = new EHealthP12(@"..\..\EHealthP12\ehealth.p12", File.ReadAllText(@"..\..\EHealthP12\ehealth.txt"));
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
            X509Certificate2 cert = p12["148459475702464467506498982825636760342"];
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

        [TestMethod, Ignore("Only on demand")]
        public void ReinstallInCurrentUser()
        {
            //Prepare
            X509Store my = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            my.Open(OpenFlags.ReadWrite);
            X509Store cas = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            cas.Open(OpenFlags.ReadWrite);
            X509Store root = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            root.Open(OpenFlags.ReadWrite);
            foreach (X509Certificate2 cert in p12.Values)
            {
                if (my.Certificates.Contains(cert)) 
                    my.Remove(cert);
                if (cas.Certificates.Contains(cert)) 
                    cas.Remove(cert);
                if (root.Certificates.Contains(cert)) 
                    root.Remove(cert);
            }
            
            //Test install
            p12.Install(StoreLocation.CurrentUser);
        }
       
    }
}