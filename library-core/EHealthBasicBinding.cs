using System;
using System.Collections.Generic;
using System.ServiceModel.Channels;
using System.Text;

namespace Egelke.EHealth.Client.Sso
{
    public class EHealthBasicBinding : Binding
    {
        private BindingElement security;

        private BindingElement messageEncoding;

        private BindingElement transport;

        public EHealthBasicBinding()
        {
            security = CreateSecurity();
            messageEncoding = CreateMessageEncoding();
            transport = CreateTransport();
        }

        public override BindingElementCollection CreateBindingElements()
        {
            BindingElementCollection elements = new BindingElementCollection();
            elements.Add(security);
            elements.Add(messageEncoding);
            elements.Add(transport);
            return elements.Clone();
        }

        private BindingElement CreateMessageEncoding()
        {
            TextMessageEncodingBindingElement encoding = new TextMessageEncodingBindingElement();
            encoding.MessageVersion = MessageVersion.Soap11;
            return encoding;
        }

        private BindingElement CreateTransport()
        {
            HttpsTransportBindingElement transport = new HttpsTransportBindingElement();
            transport.AuthenticationScheme = System.Net.AuthenticationSchemes.Anonymous;
            //transport.HostNameComparisonMode = HostNameComparisonMode.WeakWildcard;

            return transport;
        }

        private BindingElement CreateSecurity()
        {
            EHealthBaseSecurityBindingElement security = new EHealthBaseSecurityBindingElement();
            //TransportSecurityBindingElement security = SecurityBindingElement.CreateUserNameOverTransportBindingElement();
            return security;
        }

        public override string Scheme => ((TransportBindingElement) transport).Scheme;
    }
}
