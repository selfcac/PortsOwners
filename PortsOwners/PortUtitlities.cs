using PortsOwners.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace PortsOwners
{
    public class PortUtitlities
    {
        public class Tcp6ConnectionInfo
        {
            public ushort LocalPort, RemotePort;
            public IPAddress LocalAddress, RemoteAddress;
            public Iphlpapi.MibTcpState State;
            public Iphlpapi.TcpConnectionOffloadState OffloadState;
            public uint LocalScopeId, OwnerPid;

            public Tcp6ConnectionInfo(Iphlpapi.MIB_TCP6ROW2 tcpRow)
            {
                // We mask the ports in this struct because according to the documentation, the upper
                // bits can be populated arbitrarily, aka undefined state.

                LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)(tcpRow.dwLocalPort & 0xFFFF));
                RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)(tcpRow.dwRemotePort & 0xFFFF));
                LocalAddress = new IPAddress(tcpRow.LocalAddr.u.Byte);
                RemoteAddress = new IPAddress(tcpRow.RemoteAddr.u.Byte);
                State = tcpRow.State;
                OffloadState = tcpRow.dwOffloadState;
                LocalScopeId = tcpRow.dwLocalScopeId;
                OwnerPid = tcpRow.dwOwningPid; // <= 4 is System process
            }
        }

        public class Tcp4ConnectionInfo
        {
            public ushort LocalPort, RemotePort;
            public IPAddress LocalAddress, RemoteAddress;
            public Iphlpapi.MibTcpState State;
            public Iphlpapi.TcpConnectionOffloadState OffloadState;
            public uint OwnerPid;

            public Tcp4ConnectionInfo(Iphlpapi.MIB_TCPROW2 tcpRow)
            {
                // We mask the ports in this struct because according to the documentation, the upper
                // bits can be populated arbitrarily, aka undefined state.

                LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)(tcpRow.dwLocalPort & 0xFFFF));
                RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)(tcpRow.dwRemotePort & 0xFFFF));
                LocalAddress = new IPAddress(tcpRow.dwLocalAddr);
                RemoteAddress = new IPAddress(tcpRow.dwRemoteAddr);
                State = tcpRow.dwState;
                OffloadState = tcpRow.dwOffloadState;
                OwnerPid = tcpRow.dwOwningPid; // <= 4 is System process
            }
        }

        public static List<Tcp6ConnectionInfo> GetIP6(Action<string> log)
        {
            List<Tcp6ConnectionInfo> resultTable = new List<Tcp6ConnectionInfo>();

            try
            {
                // Get size first
                int tableSize = 0;
                int errorCode = Iphlpapi.GetTcp6Table2(IntPtr.Zero, ref tableSize, false);
                if (errorCode != 122) // 122 return when we pass small buffer but output the expected buffer
                    throw new Exception("Can't read table size, error code: " + errorCode);

                IntPtr memoryPointer = IntPtr.Zero; // Where we allocate

                try
                {
                    // Get Table data:
                    memoryPointer = Marshal.AllocHGlobal(tableSize);
                    errorCode = Iphlpapi.GetTcp6Table2(memoryPointer, ref tableSize, false);

                    if (errorCode != 0) throw new Exception("Can't read table data, error code: " + errorCode);

                    var tableInfoStruct = 
                        (Iphlpapi.MIB_TCP6TABLE2)Marshal.PtrToStructure(memoryPointer, typeof(Iphlpapi.MIB_TCP6TABLE2));

                    // The other rows are sequentially after the size:
                    IntPtr tableRowsPointer = 
                        (IntPtr)((long)memoryPointer + Marshal.SizeOf(tableInfoStruct.dwNumEntries));

                    for (int i = 0; i < tableInfoStruct.dwNumEntries; i++)
                    {
                        Iphlpapi.MIB_TCP6ROW2 tcpRow = (Iphlpapi.MIB_TCP6ROW2)
                            Marshal.PtrToStructure(tableRowsPointer, typeof(Iphlpapi.MIB_TCP6ROW2));

                        resultTable.Add(new Tcp6ConnectionInfo(tcpRow));

                        // Advance in memory the size of the row:
                        tableRowsPointer = (IntPtr)((long)tableRowsPointer + Marshal.SizeOf(tcpRow));
                    }

                }
                catch (OutOfMemoryException exMem)
                {
                    log("Can't allocated data, error:\n" + exMem);
                }
                catch (Exception exReadData)
                {
                    log("Error occured while getting data, error:\n" + exReadData);
                    if (memoryPointer != IntPtr.Zero)
                        Marshal.FreeHGlobal(memoryPointer);
                }
            }
            catch (Exception exMain)
            {
                log("Error occured, error:\n" + exMain);
            }

            return resultTable;
        }


        public static List<Tcp4ConnectionInfo> GetIP4(Action<string> log)
        {
            List<Tcp4ConnectionInfo> resultTable = new List<Tcp4ConnectionInfo>();

            try
            {
                // Get size first
                int tableSize = 0;
                int errorCode = Iphlpapi.GetTcpTable2(IntPtr.Zero, ref tableSize, false);
                if (errorCode != 122) // 122 return when we pass small buffer but output the expected buffer
                    throw new Exception("Can't read table size, error code: " + errorCode);

                IntPtr memoryPointer = IntPtr.Zero; // Where we allocate

                try
                {
                    // Get Table data:
                    memoryPointer = Marshal.AllocHGlobal(tableSize);
                    errorCode = Iphlpapi.GetTcpTable2(memoryPointer, ref tableSize, false);

                    if (errorCode != 0) throw new Exception("Can't read table data, error code: " + errorCode);

                    var tableInfoStruct =
                        (Iphlpapi.MIB_TCPTABLE2)Marshal.PtrToStructure(memoryPointer, typeof(Iphlpapi.MIB_TCPTABLE2));

                    // The other rows are sequentially after the size:
                    IntPtr tableRowsPointer =
                        (IntPtr)((long)memoryPointer + Marshal.SizeOf(tableInfoStruct.dwNumEntries));

                    for (int i = 0; i < tableInfoStruct.dwNumEntries; i++)
                    {
                        Iphlpapi.MIB_TCPROW2 tcpRow = (Iphlpapi.MIB_TCPROW2)
                            Marshal.PtrToStructure(tableRowsPointer, typeof(Iphlpapi.MIB_TCPROW2));

                        resultTable.Add(new Tcp4ConnectionInfo(tcpRow));

                        // Advance in memory the size of the row:
                        tableRowsPointer = (IntPtr)((long)tableRowsPointer + Marshal.SizeOf(tcpRow));
                    }

                }
                catch (OutOfMemoryException exMem)
                {
                    log("Can't allocated data, error:\n" + exMem);
                }
                catch (Exception exReadData)
                {
                    log("Error occured while getting data, error:\n" + exReadData);
                    if (memoryPointer != IntPtr.Zero)
                        Marshal.FreeHGlobal(memoryPointer);
                }
            }
            catch (Exception exMain)
            {
                log("Error occured, error:\n" + exMain);
            }

            return resultTable;
        }
    }
}
