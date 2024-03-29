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
using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using System.IdentityModel.Selectors;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Sso
{
    public class SsoClientCredentials : ClientCredentials
    {
        private X509Certificate2 session;

        private TimeSpan duration = new TimeSpan(1, 0, 0, 0); //defaults to 1 day

        private Type cache = typeof(Egelke.EHealth.Client.Sso.MemorySessionCache);

        private XmlDocument config = null;

        public X509Certificate2 Session
        {
            get
            {
                return session;
            }
            set
            {
                session = value;
            }
        }

        public TimeSpan Duration
        {
            get
            {
                return duration;
            }
            set
            {
                duration = value;
            }
        }

        public Type Cache
        {
            get
            {
                return cache;
            }
            set
            {
                cache = value;
            }
        }

        public XmlDocument Config
        {
            get
            {
                return config;
            }
            set
            {
                config = value;
            }
        }

        public SsoClientCredentials()
            : base()
        {
            // Set SupportInteractive to false to suppress Cardspace UI
            base.SupportInteractive = false;
        }

        protected SsoClientCredentials(SsoClientCredentials other)
            : base(other)
        {

            
        }

        protected override ClientCredentials CloneCore()
        {
            return new SsoClientCredentials(this);
        }

        public override SecurityTokenManager CreateSecurityTokenManager()
        {
            // return custom security token manager
            return new SsoSecurityTokenManager(this);
        }
    }
}
