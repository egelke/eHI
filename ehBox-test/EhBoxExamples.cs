﻿using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Egelke.EHealth.Client.EhBox;

namespace Egelke.EHealth.Client.EhBoxTest
{
    [TestClass]
    public class EhBoxExamples
    {
        [TestMethod]
        public void ConfigViaConfig()
        {
            ehBoxPublicationPortTypeClient publish = new ehBoxPublicationPortTypeClient("Publish");
            PublicationMessageType publishMessage = new PublicationMessageType();

            //Unique ID to identify the request
            publishMessage.PublicationId = Guid.NewGuid().ToString("N").Substring(18, 13);

            //Indicate your box
            publishMessage.BoxId = new BoxIdType();
            publishMessage.BoxId.Id = "0820563481";
            publishMessage.BoxId.Type = "CBE";
            publishMessage.BoxId.Quality = "INSTITUTION";

            //Indicate the box of the destination (we test with ourselfs)
            publishMessage.DestinationContext = new PublicationMessageTypeDestinationContext[1];
            publishMessage.DestinationContext[0] = new PublicationMessageTypeDestinationContext();
            publishMessage.DestinationContext[0].Id = "83121034221";
            publishMessage.DestinationContext[0].Type = "INSS";
            publishMessage.DestinationContext[0].Quality = "NURSE";

            //We create a new item
            NewsType news = new NewsType();
            news.Title = "eH-I supports ehBox";
            news.Item = Encoding.UTF8.GetBytes("The eH-I library now support publication and consultations of the ehBox");
            news.ItemElementName = ItemChoiceType1.EncryptableTextContent;
            news.MimeType = "test/plain";

            //And the message we send (we use news since it is the most simple)
            publishMessage.ContentContext = new PublicationMessageTypeContentContext();
            publishMessage.ContentContext.Content = new ContentType();
            publishMessage.ContentContext.Content.Item = news;
            publishMessage.ContentContext.ContentSpecification = new ContentSpecificationType();
            publishMessage.ContentContext.ContentSpecification.IsImportant = false;
            publishMessage.ContentContext.ContentSpecification.IsEncrypted = false;
            publishMessage.ContentContext.ContentSpecification.PublicationReceipt = true;
            publishMessage.ContentContext.ContentSpecification.ReceivedReceipt = true;
            publishMessage.ContentContext.ContentSpecification.ReadReceipt = true;
            publishMessage.ContentContext.ContentSpecification.ApplicationName = "eH-I";
            
            //Publish the news.
            SendMessageResponse rsp = publish.sendMessage(publishMessage);

            //check the response
            Assert.AreEqual("100", rsp.Status.Code);
        }
    }
}