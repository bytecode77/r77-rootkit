#define CUSTOM_ENTRY
#include "r77def.h"
#include "r77win.h"
#include "r77process.h"

// Uninstall64.exe is extracted and executed by Uninstall.exe

int main()
{
	EnabledDebugPrivilege();

	// Delete the stager executable from the 64-bit view of the registry.
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
	{
		RegDeleteValueW(key, HIDE_PREFIX L"stager");
	}

	// Delete the 64-bit scheduled task that starts the r77 service.
	DeleteScheduledTask(R77_SERVICE_NAME64);

	// Terminate running 64-bit instances of the r77 service.
	TerminateR77Service(-1);

	// Detach all injected 64-bit processes.
	DetachAllInjectedProcesses();

	return 0;
}