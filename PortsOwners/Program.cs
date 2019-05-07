using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PortsOwners
{
    class Program
    {
        static void Main(string[] args)
        {
            var logError = new Action<string>((c) => Console.WriteLine("[ERROR] " + c));
            foreach (var row in PortUtitlities.GetIP6(logError).OrderBy((s) => s.LocalAddress.ToString()))
            {
                Console.WriteLine("v6 [{0}]:{1}->[{2}]:{3} @ {4} Mode: {5}",
                    row.LocalAddress, row.LocalPort, row.RemoteAddress, row.RemotePort, row.OwnerPid, row.State);
            }
            foreach (var row in PortUtitlities.GetIP4(logError).OrderBy((s)=>s.LocalAddress.ToString()))
            {
                Console.WriteLine("v4 {0}:{1}->{2}:{3} @ {4} Mode: {5}",
                    row.LocalAddress, row.LocalPort, row.RemoteAddress, row.RemotePort, row.OwnerPid, row.State);
            }
        }
    }
}
