using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace PortsOwners.Win32
{
    public class advapi32
    {
        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {

            public IntPtr Sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("advapi32")]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle, // handle to process
            int DesiredAccess, // desired access to process
            ref IntPtr TokenHandle // handle to open access token
        );

        [DllImport("advapi32", CharSet = CharSet.Auto)]
        public static extern bool GetTokenInformation(
            IntPtr hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr TokenInformation,
            int tokeInfoLength,
            ref int reqLength
        );

        [DllImport("advapi32", CharSet = CharSet.Auto)]
        public static extern bool ConvertSidToStringSid(
            IntPtr pSID,
            [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid
        );

        [DllImport("advapi32", CharSet = CharSet.Auto)]
        public static extern bool ConvertStringSidToSid(
            [In, MarshalAs(UnmanagedType.LPTStr)] string pStringSid,
            ref IntPtr pSID
        );


    }
}
