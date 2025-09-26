using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Egelke.EHealth.Client;
using Xunit;

namespace library_core_tests
{
    public class TracingConfigTest
    {
        [Fact]
        public void Check()
        {
            var target = new TracingConfig();

            Assert.Null(target.Contact);

            Assert.Equal("Egelke.EHealth.Client", target.Connector.Name);
            Assert.Equal("3.0.0.2", target.Connector.Version.ToString());

            Assert.Equal("testhost", target.Product.Name);
            Assert.Equal("15.0.0.0", target.Product.Version.ToString());

            Assert.Equal("testhost/15.0.0.0 Egelke.EHealth.Client/3.0.0.2", target.ToAgent());
        }
    }
}
