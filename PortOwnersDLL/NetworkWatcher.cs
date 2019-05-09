using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace PortsOwners
{
    public class NetworkWatcher
    {
        public class UserInfo
        {
            public string UserName;
            public string SID;
        }

        public class AddressInfo
        {
            public string LocalAddress = ":";
            public uint OwnerPID = 0;
            public string OwnerSID = "";
            public string FullExePath = "";
        }

        Dictionary<string, AddressInfo> addrToSid = new Dictionary<string, AddressInfo>();
        Dictionary<string, UserInfo> sidToUser = new Dictionary<string, UserInfo>();


        Timer timerThread = null;
        public void Start(uint updateSecondsInterval)
        {


            PrincipalUtils.getLimitedUsers((name, sid) =>
            {
                sidToUser.Add(sid, new UserInfo()
                {
                    UserName = name,
                    SID = sid
                });
                //Console.WriteLine("Name: {0}, SID: {1}", name, sid);
            });

            UpdateTables(null);

            timerThread = new Timer(UpdateTables, null, 0, (int)TimeSpan.FromSeconds(updateSecondsInterval).TotalMilliseconds);
        }

        public void Stop()
        {
            timerThread?.Dispose();
        }

        private void AddAddresses(IEnumerable<PortUtitlities.TcpConnectionInfo> connArray)
        {
            foreach (var conn in connArray)
            {
                AddressInfo addr = new AddressInfo();
                addr.OwnerPID = conn.OwnerPid;

                // Try to get info about process:
                ProcessUtilities.usingHandle(addr.OwnerPID, (phandle) =>
                {
                    addr.OwnerSID = ProcessUtilities.sidFromProcess(phandle);
                    addr.FullExePath = ProcessUtilities.GetProcessPath(phandle);
                });

                if (addr.OwnerSID != "")
                {
                    // Ip4 and Ip6 Handling:
                    addr.LocalAddress = conn.LocalAddress.ToString();
                    if (addr.LocalAddress.IndexOf(":") > -1)
                        addr.LocalAddress = string.Format("[{0}]:{1}", addr.LocalAddress, conn.LocalPort);
                    else
                        addr.LocalAddress += ":" + conn.LocalPort;

                    // Finally add to array:
                    //Console.WriteLine("{0}, SID: {1}", addr.LocalAddress, addr.OwnerSID);
                    // Might exist because multithreadin
                    if (!addrToSid.ContainsKey(addr.LocalAddress))
                        addrToSid.Add(addr.LocalAddress, addr);
                }
            }
        }

        private Action<string> errorLog = new Action<string>((c) =>
        {
            Console.WriteLine("[PORT-ERR] " + c);
        });

        private void UpdateTables(object timerState)
        {
            lock (addrToSid)
            {
                addrToSid.Clear();
                AddAddresses(PortUtitlities.GetIP4(errorLog).Select((ip) => (ip as PortUtitlities.TcpConnectionInfo)));
                AddAddresses(PortUtitlities.GetIP6(errorLog).Select((ip) => (ip as PortUtitlities.TcpConnectionInfo)));
            }
        }

        public bool isLocalAddressAdmin(string address, bool unkownAddrValue)
        {
            lock (addrToSid)
            {
                if (addrToSid.ContainsKey(address))
                {
                    // We only store list of limited users.

                    AddressInfo addri = addrToSid[address];
                    if (sidToUser.ContainsKey(addri.OwnerSID))
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                else
                {
                    return unkownAddrValue;
                }
            }
        }
    }
}
