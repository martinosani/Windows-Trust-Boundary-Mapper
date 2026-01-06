using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WTBM.NtNative
{
    internal static class NtQuery
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }



        public static string GetObjectName(IntPtr handle)
            => QueryUnicodeString(handle, Native.OBJECT_INFORMATION_CLASS.ObjectNameInformation);

        private static string QueryUnicodeString(IntPtr handle, Native.OBJECT_INFORMATION_CLASS klass)
        {
            int len = 0x1000;
            IntPtr buffer = IntPtr.Zero;

            try
            {
                while (true)
                {
                    buffer = Marshal.AllocHGlobal(len);
                    int status = Native.NtQueryObject(handle, klass, buffer, len, out int retLen);

                    const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
                    if (status == 0)
                    {
                        var us = Marshal.PtrToStructure<UNICODE_STRING>(buffer);
                        if (us.Buffer == IntPtr.Zero || us.Length == 0) return string.Empty;
                        return Marshal.PtrToStringUni(us.Buffer, us.Length / 2) ?? string.Empty;
                    }

                    Marshal.FreeHGlobal(buffer);
                    buffer = IntPtr.Zero;

                    if (status != STATUS_INFO_LENGTH_MISMATCH)
                        return string.Empty;

                    len = Math.Max(len * 2, retLen);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
