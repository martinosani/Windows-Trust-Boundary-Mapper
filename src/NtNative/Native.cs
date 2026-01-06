using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WTBM.NtNative
{
    internal static class Native
    {
        internal const uint PROCESS_DUP_HANDLE = 0x0040;
        internal const uint DUPLICATE_SAME_ACCESS = 0x00000002;

        internal enum OBJECT_INFORMATION_CLASS : int
        {
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        internal static extern bool CloseHandle(IntPtr h);

        [DllImport("ntdll.dll")]
        internal static extern int NtQueryObject(
            IntPtr Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            int ObjectInformationLength,
            out int ReturnLength);
    }
}
