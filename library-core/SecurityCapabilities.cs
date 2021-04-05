using System;
using System.Collections.Generic;
using System.Net.Security;
using System.ServiceModel.Channels;
using System.Text;

namespace Egelke.EHealth.Client.Sso
{
    internal class SecurityCapabilities : ISecurityCapabilities
    {
        internal SecurityCapabilities(ProtectionLevel req, ProtectionLevel rsp, bool clientAuth, bool clientWinId, bool serverAuth)
        {
            SupportedRequestProtectionLevel = req;
            SupportedResponseProtectionLevel = rsp;
            SupportsClientAuthentication = clientAuth;
            SupportsClientWindowsIdentity = clientWinId;
            SupportsServerAuthentication = serverAuth;
        }

        public ProtectionLevel SupportedRequestProtectionLevel { get; }

        public ProtectionLevel SupportedResponseProtectionLevel { get; }

        public bool SupportsClientAuthentication { get; }

        public bool SupportsClientWindowsIdentity { get; }

        public bool SupportsServerAuthentication { get; }
    }
}
