#include <Windows.h>
#include <winternl.h>
#ifndef _R77MINDEF_H
#define _R77MINDEF_H

#pragma warning(disable: 6258) // Using TerminateThread does not allow proper thread clean up.

#define NEW(type) (type*)HeapAlloc(GetProcessHeap(), 0, sizeof(type))
#define NEW_ARRAY(type, length) (type*)HeapAlloc(GetProcessHeap(), 0, sizeof(type) * (length))
#define FREE(buffer) HeapFree(GetProcessHeap(), 0, buffer);

/// <summary>
/// Returns TRUE, if the bitness of the current process is equal to bits.
/// </summary>
#define BITNESS(bits) (sizeof(LPVOID) * 8 == (bits))
/// <summary>
/// Returns either if32 or if64 depending on the bitness of the current process.
/// </summary>
#define COALESCE_BITNESS(if32, if64) (sizeof(LPVOID) == 4 ? (if32) : (if64))
/// <summary>
/// Rotates a value right by a defined number of bits.
/// </summary>
#define ROTR(value, bits) ((DWORD)(value) >> (bits) | (DWORD)(value) << (32 - (bits)))

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