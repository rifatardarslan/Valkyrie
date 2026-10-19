using System;
using System.Runtime.InteropServices;
class Program {
    [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
    static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);
    
    [DllImport("kernel32.dll")]
    static extern void OutputDebugStringW(string lpOutputString);

    static void Main() {
        bool isDebuggerPresent = false;
        CheckRemoteDebuggerPresent(System.Diagnostics.Process.GetCurrentProcess().Handle, ref isDebuggerPresent);
        OutputDebugStringW("VBoxService.exe");
        Console.WriteLine("Mocking CheckRemoteDebuggerPresent and VBox");
    }
}
