using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace PortsOwners.Win32
{
    public static class Iphlpapi
    {
        // Credit to CitadelCore.Windows project.

        [DllImport("Iphlpapi.dll", EntryPoint = "GetTcp6Table2")]
        public static extern int GetTcp6Table2(IntPtr TcpTable, ref int SizePointer, [MarshalAs(UnmanagedType.Bool)] bool Order);

        [DllImport("Iphlpapi.dll", EntryPoint = "GetTcpTable2")]
        public static extern int GetTcpTable2(IntPtr TcpTable, ref int SizePointer, [MarshalAs(UnmanagedType.Bool)] bool Order);

        public enum TcpConnectionOffloadState : uint
        {
            TcpConnectionOffloadStateInHost = 0,
            TcpConnectionOffloadStateOffloading = 1,
            TcpConnectionOffloadStateOffloaded = 2,
            TcpConnectionOffloadStateUploading = 3,
            TcpConnectionOffloadStateMax = 4,
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct in6_addr_union
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8, ArraySubType = UnmanagedType.U2)]
            [FieldOffset(0)]
            public ushort[] Word;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = UnmanagedType.U1)]
            [FieldOffset(0)]
            public byte[] Byte;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct in6_addr
        {
            public in6_addr_union u;
        }

        public enum MibTcpState : uint
        {
            CLOSED = 1,
            LISTENING = 2,
            SYN_SENT = 3,
            SYN_RCVD = 4,
            ESTABLISHED = 5,
            FIN_WAIT1 = 6,
            FIN_WAIT2 = 7,
            CLOSE_WAIT = 8,
            CLOSING = 9,
            LAST_ACK = 10,
            TIME_WAIT = 11,
            DELETE_TCB = 12,
            NONE = 0
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW2
        {
            public in6_addr LocalAddr;
            public uint dwLocalScopeId;
            public uint dwLocalPort;
            public in6_addr RemoteAddr;
            public uint dwRemoteScopeId;
            public uint dwRemotePort;
            public MibTcpState State;
            public uint dwOwningPid;
            public TcpConnectionOffloadState dwOffloadState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW2
        {
            public MibTcpState dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
            public TcpConnectionOffloadState dwOffloadState;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPTABLE2
        {
            public uint dwNumEntries;
            public IntPtr table;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6TABLE2
        {
            public uint dwNumEntries;
            public IntPtr table;
        }
    }
}
