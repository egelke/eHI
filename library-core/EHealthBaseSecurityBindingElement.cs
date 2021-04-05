using System;
using System.Collections.Generic;
using System.Net.Security;
using System.ServiceModel.Channels;
using System.Text;

namespace Egelke.EHealth.Client.Sso
{
    class EHealthBaseSecurityBindingElement : BindingElement
    {
        public EHealthBaseSecurityBindingElement() : base()
        {

        }

        public override BindingElement Clone()
        {
            return new EHealthBaseSecurityBindingElement();
        }

        public override T GetProperty<T>(BindingContext context)
        {
            //if (typeof(T) == typeof(ISecurityCapabilities))
            //{
            //    return (T)(object)new SecurityCapabilities(req: ProtectionLevel.None, 
            //        rsp: ProtectionLevel.None, false, false, false);
            //} else
            {
                return context.GetInnerProperty<T>();
            }
     
        }

        public override bool CanBuildChannelFactory<TChannel>(BindingContext context)
        {
            return typeof(TChannel) == typeof(IRequestChannel);
        }

        public override IChannelFactory<TChannel> BuildChannelFactory<TChannel>(BindingContext context)
        {
            //return base.BuildChannelFactory<TChannel>(context);
            return new EHealthBaseChannelFactory<TChannel>(context);
        }

    }
}
