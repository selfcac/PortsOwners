using Microsoft.VisualStudio.TestTools.UnitTesting;
using PortsOwners;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PortOwnersDLL.Tests
{
    [TestClass()]
    public class ProxyDetectionTests
    {
        [TestMethod()]
        public void ContainsPrivateIpv4AddressTest()
        {
            string[] badIps = new[]
            {
                "127.0.0.1",
                "127.2.3.1",

                //10.0.0.0 – 10.255.255.255
                "10.0.0.0",
                "10.0.0.1",
                "10.0.0.4",
                "10.5.0.4",
                "10.255.255.255",

                //192.168.0.0 – 192.168.255.255
                "192.168.0.0",
                "192.168.0.1",
                "192.168.0.66",
                "192.168.1.77",
                "192.168.255.255",

                //172.16.0.0 – 172.31.255.255
                "172.16.0.0",
                "172.16.1.20",
                "172.20.0.0",
                "172.31.255.255",
                "172.31.255.255",
            };

            foreach (string ip in badIps)
            {
                Assert.AreEqual(true, ProxyDetection.ContainsPrivateIpv4Address(ip), "Failed with ip: " + ip);
            }


            string[] okIPS = new[] {
                "103.80.238.97", "202.162.222.154", "87.249.205.157", "131.108.62.139", "151.106.8.228",
                "78.37.27.139", "181.49.24.126", "173.16.251.102", "45.166.86.6", "189.3.226.180",
                "110.74.213.246", "151.106.10.62", "117.196.236.235", "94.74.166.89", "134.209.170.22",
                "134.209.170.59", "37.182.199.214", "1.20.103.252", "191.7.200.218", "138.219.229.252" };

            foreach (string ip in okIPS)
            {
                Assert.AreEqual(false, ProxyDetection.ContainsPrivateIpv4Address(ip), "Failed with ip: " + ip);
            }
        }

        [TestMethod()]
        public void IsHttpsConnectTest()
        {
            Assert.AreEqual(true, ProxyDetection.IsHttpsConnect(Encoding.ASCII.GetBytes("CONNECT www.google.com:443 ")));
            Assert.AreEqual(false, ProxyDetection.IsHttpsConnect(Encoding.ASCII.GetBytes("GET / HTTP1.1 ")));

            // junk bytes:
            Assert.AreEqual(false, ProxyDetection.IsHttpsConnect(new byte[] { 0,5,55,66}));
        }
    }
}