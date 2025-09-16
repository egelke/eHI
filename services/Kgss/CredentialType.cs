using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace Egelke.EHealth.Client.Services.Kgss
{
    public class CredentialType
    {
        internal const string ROOTNAME_ALLOWED = "AllowedReader";

        internal const string ROOTNAME_EXCLUDED = "ExcludedReader";


        public string Namespace { get; set; }
        public string Name { get; set; }
        public List<string> Values { get; set; } = new List<string>();

        internal XElement ToXElement(string rootName)
        {
            List<XElement> children = new List<XElement>
            {
                new XElement(KgssClient.NS_KGSS + "Namespace", Namespace),
                new XElement(KgssClient.NS_KGSS + "Name", Name)
            };
            children.AddRange(Values.Select(v => new XElement(KgssClient.NS_KGSS + "Value", v)));

            return new XElement(KgssClient.NS_KGSS + rootName, children);
        }
    }
}
