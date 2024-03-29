/*
 * This file is part of eHealth-Interoperability.
 * 
 * eHealth-Interoperability is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * eHealth-Interoperability  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public License
 * along with eHealth-Interoperability.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel.Description;
using System.Security.Cryptography.X509Certificates;
using System.Configuration;
using System.Xml;

namespace Egelke.EHealth.Client.Sso
{
    public class SessionBehavior : IEndpointBehavior
    {

        private X509Certificate2 session;

        private TimeSpan duration;

        private Type cache;

        private XmlDocument config;

        public SessionBehavior(X509Certificate2 session, TimeSpan duration, Type cache, XmlDocument config)
        {
            this.session = session;
            this.duration = duration;
            this.cache = cache;
            this.config = config;
        }

        #region IEndpointBehavior Members

        public void AddBindingParameters(ServiceEndpoint endpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {
            SsoClientCredentials cred = bindingParameters.Find<SsoClientCredentials>();
            if (cred == null) throw new ConfigurationErrorsException("The session behavior must be used in conjunction with SsoClientCredentials");
            cred.Session = session;
            cred.Duration = duration;
            cred.Cache = cache;
            cred.Config = config;
        }

        public void ApplyClientBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.ClientRuntime clientRuntime)
        {

        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, System.ServiceModel.Dispatcher.EndpointDispatcher endpointDispatcher)
        {

        }

        public void Validate(ServiceEndpoint endpoint)
        {
        }

        #endregion
    }
}
