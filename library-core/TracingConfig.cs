using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Egelke.EHealth.Client
{
    /// <summary>
    /// Simplified Assembly info.
    /// </summary>
    public class SoftwareInfo
    {
        /// <summary>
        /// Name of the assembly.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Version of the assembly.
        /// </summary>
        public Version Version { get; set; }

    }

    /// <summary>
    /// eHealth tracing config, use for the "User-Agent" and "From" http-headers.
    /// </summary>
    public class TracingConfig
    {

        /// <summary>
        /// Information about your (client) product, defaults to Entry Assembly.
        /// </summary>
        public SoftwareInfo Product { get; set; } = new SoftwareInfo()
        {
            Name = Assembly.GetEntryAssembly().GetName().Name,
            Version = Assembly.GetEntryAssembly().GetName().Version,
        };

        /// <summary>
        /// Information about this library, default so to Executing Assembly.
        /// </summary>
        public SoftwareInfo Connector { get; set; } = new SoftwareInfo()
        {
            Name = Assembly.GetExecutingAssembly().GetName().Name,
            Version = Assembly.GetExecutingAssembly().GetName().Version,
        };

        /// <summary>
        /// Contact e-mail, default to null.
        /// </summary>
        public string Contact { get; set; }


        public string ToAgent()
        {
            return new StringBuilder()
                .Append(Product.Name)
                .Append('/')
                .Append(Product.Version.ToString())
                .Append(' ')
                .Append(Connector.Name)
                .Append('/')
                .Append(Connector.Version.ToString())
                .ToString();
        }

    }


}
