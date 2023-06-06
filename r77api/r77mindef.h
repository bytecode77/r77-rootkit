#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#ifndef _R77MINDEF_H
#define _R77MINDEF_H

#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up.

#define NEW(type) (type*)HeapAlloc(GetProcessHeap(), 0, sizeof(type))
#define NEW_ARRAY(type, length) (type*)HeapAlloc(GetProcessHeap(), 0, sizeof(type) * (length))
#define FREE(buffer) HeapFree(GetProcessHeap(), 0, buffer);

#define i_memcpy(dest, src, count) __movsb((LPBYTE)(dest), (LPCBYTE)(src), (SIZE_T)(count))
#define i_wmemcpy(dest, src, count) __movsw((LPWORD)(dest), (const LPWORD)(src), (SIZE_T)(count))
#define i_memset(dest, value, count) __stosb((LPBYTE)(dest), (BYTE)(value), (SIZE_T)(count))
#define i_wmemset(dest, value, count) __stosw((LPWORD)(dest), (WORD)(value), (SIZE_T)(count))

/// <summary>
/// Returns TRUE, if the bitness of the current process is equal to bits.
/// </summary>
#define BITNESS(bits) (sizeof(LPVOID) * 8 == (bits))
/// <summary>
/// Returns either if32 or if64 depending on the bitness of the current process.
/// </summary>
#define COALESCE_BITNESS(if32, if64) (sizeof(LPVOID) == 4 ? (if32) : (if64))

#ifdef CUSTOM_ENTRY
int main();
int __stdcall EntryPoint()
{
	// Define CUSTOM_ENTRY, if compiling with /ENTRY
	// ExitProcess is required, if entry point is defined manually.

	ExitProcess(main());
}
#endif

#endif