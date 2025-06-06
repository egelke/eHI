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
using System.ServiceModel.Configuration;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;

namespace Egelke.EHealth.Client.Sso.Configuration
{
    public class SessionBehaviorElement : BehaviorExtensionElement
    {
        [ConfigurationProperty("duration")]
        public TimeSpan Duration
        {
            get { return (TimeSpan)base["duration"]; }
            set { base["duration"] = value; }
        }

        [ConfigurationProperty("sessionCertificate")]
        public SessionCertificateElement SessionCertificate
        {
            get { return (SessionCertificateElement)base["sessionCertificate"]; }
            set { base["sessionCertificate"] = value; }
        }

        [ConfigurationProperty("cache")]
        public CacheElement Cache
        {
            get { return (CacheElement)base["cache"]; }
            set { base["cache"] = value; }
        }

        public override Type BehaviorType
        {
            get { return typeof(SessionBehavior); }
        }

        protected override object CreateBehavior()
        {
            X509Certificate2 session;
            if (SessionCertificate.SelfSigned)
            {
                session = CertGenerator.GenerateSelfSigned(new TimeSpan(1, 0, 0, 0).Add(new TimeSpan(1, 0, 0)));
            }
            else
            {
                X509Store store = new X509Store(SessionCertificate.StoreName, SessionCertificate.StoreLocation);
                store.Open(OpenFlags.IncludeArchived | OpenFlags.MaxAllowed);
                try
                {
                    X509Certificate2Collection found = store.Certificates.Find(SessionCertificate.X509FindType, SessionCertificate.FindValue, false);
                    if (found == null || found.Count != 1)
                    {
                        throw new ConfigurationErrorsException("The Session Certificate was not found");
                    }
                    session = found[0];
                }
                finally
                {
                    store.Close();
                }
            }
            TimeSpan duration = Duration;
            if (duration == TimeSpan.Zero)
            {
                duration = new TimeSpan(1, 0, 0, 0);
            }
            Type cacheType;
            try
            {
                cacheType = Type.GetType(Cache.Type);
            }
            catch (Exception e)
            {
                throw new ConfigurationErrorsException("Invalid cache type", e);
            }
            if (!(typeof(ISessionCache).IsAssignableFrom(cacheType)))
            {
                throw new ConfigurationErrorsException("The cache type must implement ISessionCache");
            }

            return new SessionBehavior(session, duration, cacheType, Cache.Content);
        }
    }
}
