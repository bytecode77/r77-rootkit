#include "Uninstall.h"

int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	InitializeApi(INITIALIZE_API_SRAND | INITIALIZE_API_DEBUG_PRIVILEGE);

	// Delete the stager executable from the 32-bit view of the registry.
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | KEY_WOW64_32KEY, &key) == ERROR_SUCCESS)
	{
		RegDeleteValueW(key, HIDE_PREFIX L"stager");
	}

	// Delete the 32-bit scheduled task that starts the r77 service.
	DeleteScheduledTask(R77_SERVICE_NAME32);

	// Terminate running 32-bit instances of the r77 service.
	TerminateR77Service(-1);

	// Detach all injected 32-bit processes.
	DetachAllInjectedProcesses();

	if (Is64BitOperatingSystem())
	{
		// On 64-bit Windows, the above steps need to be repeated from a 64-bit process.
		// Uninstall64.exe is extracted into the temp directory, executed and deleted afterwards.

		LPBYTE uninstall64;
		DWORD uninstall64Size;
		if (GetResource(IDR_UNINSTALL64, "EXE", &uninstall64, &uninstall64Size))
		{
			WCHAR uninstall64Path[MAX_PATH + 1];
			if (CreateTempFile(uninstall64, uninstall64Size, L"exe", uninstall64Path))
			{
				ExecuteFile(uninstall64Path, TRUE);
			}
		}
	}

	// Delete all r77 configuration keys from the registry:
	//  - HKEY_LOCAL_MACHINE\$77config
	//  - HKEY_CURRENT_USER\$77config (for each user)
	UninstallR77Config();

	return 0;
}