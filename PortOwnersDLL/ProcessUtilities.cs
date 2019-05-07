using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using PortsOwners.Win32;

namespace PortsOwners
{
    public class ProcessUtilities
    {
        public const int TOKEN_QUERY = 0X00000008;
        public const int ERROR_NO_MORE_ITEMS = 259;

        public static bool DumpUserInfo(IntPtr pToken, out IntPtr SID)
        {
            bool result = false;
            int Access = TOKEN_QUERY;

            IntPtr procToken = IntPtr.Zero;
            SID = IntPtr.Zero;

            try
            {
                if (advapi32.OpenProcessToken(pToken, Access, ref procToken))
                {
                    result = ProcessTokenToSidStruct(procToken, out SID);
                    kernel32.CloseHandle(procToken);
                }
                return result;
            }
            catch (Exception err)
            {
                return false;
            }
        }

        private static bool ProcessTokenToSidStruct(IntPtr token, out IntPtr SID)
        {
            bool result = false;
            const int bufLength = 256;

            advapi32.TOKEN_USER tokUser;
            IntPtr tokenInformation = IntPtr.Zero;
            SID = IntPtr.Zero;

            try
            {
                tokenInformation = Marshal.AllocHGlobal(bufLength);
                int dataLength = bufLength;
                result = advapi32.GetTokenInformation(token,
                        advapi32.TOKEN_INFORMATION_CLASS.TokenUser, tokenInformation, dataLength, ref dataLength);
                if (result)
                {
                    tokUser = (advapi32.TOKEN_USER)Marshal.PtrToStructure(tokenInformation, typeof(advapi32.TOKEN_USER));
                    SID = tokUser.User.Sid;
                }
                return result;
            }
            catch (Exception err)
            {
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(tokenInformation);
            }
        }

        public static string sidFromProcess(IntPtr processHandle)
        {
            string resultSID = "";

            IntPtr _SID = IntPtr.Zero;
            try
            {
                if (DumpUserInfo(processHandle, out _SID))
                {
                    advapi32.ConvertSidToStringSid(_SID, ref resultSID);
                }
            }
            catch (Exception){}

            return resultSID;
        }

        public static string sidFromProcess(uint PID)
        {
            string result = "";
            Process process = Process.GetProcessById((int)PID);
            try
            {
                sidFromProcess(process.Handle);
            }
            catch (Exception) {}
            return result;
        }

        public static string GetProcessPath(IntPtr processHandle)
        {
            try
            {
                StringBuilder buffer = new StringBuilder(1024);
                if (processHandle != IntPtr.Zero)
                {
                    int size = buffer.Capacity;
                    if (kernel32.QueryFullProcessImageName(processHandle, 0, buffer, ref size))
                    {
                        return buffer.ToString();
                    }
                }
            }
            catch (Exception){}

            return "";
        }

        public static string GetProcessPath(uint processId)
        {
            IntPtr hprocess = kernel32.OpenProcess(kernel32.ProcessAccessFlags.QueryLimitedInformation, false, processId);

            try
            {
                GetProcessPath(hprocess);
            }
            finally
            {
                kernel32.CloseHandle(hprocess);
            }

            return "";
        }

        public static bool usingHandle(uint targetProcess, Action<IntPtr> handleAction)
        {
            bool result = false;
            IntPtr hprocess = kernel32.OpenProcess(kernel32.ProcessAccessFlags.QueryLimitedInformation, false, targetProcess);
            try
            {
                handleAction(hprocess);
                result = true;
            }
            finally
            {
                kernel32.CloseHandle(hprocess);
            }
            return result;
        }
    }
}
