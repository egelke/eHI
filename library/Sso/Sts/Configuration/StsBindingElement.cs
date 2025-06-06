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
using System.ServiceModel.Channels;
using System.Configuration;

namespace Egelke.EHealth.Client.Sso.Sts.Configuration
{
    public class StsBindingElement : StandardBindingElement
    {
        //private ConfigurationPropertyCollection properties;

        public StsBindingElement()
            : base()
        {
        }

        public StsBindingElement(string name)
            : base(name)
        {

        }

        protected override Type BindingElementType
        {
            get { return typeof(StsBinding); }
        }



        protected override void OnApplyConfiguration(Binding binding)
        {

        }


        
    }
}
