#include "r77mindef.h"
#ifndef _REFLECTIVEDLLMAIN_H
#define _REFLECTIVEDLLMAIN_H

/// <summary>
/// Position independent shellcode that loads the DLL after it was written to the remote process memory.
/// <para>This is the main entry point for reflective DLL injection.</para>
/// </summary>
/// <param name="dllBase">A pointer to the beginning of the DLL file.</param>
/// <returns>
/// If this function succeeds, the return value of DllMain;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL WINAPI ReflectiveDllMain(LPBYTE dllBase);
/// <summary>
/// Retrieves a function pointer from the PEB.
/// </summary>
/// <param name="moduleHash">The hash of the module name. The module must be loaded.</param>
/// <param name="functionHash">The hash of the function name.</param>
/// <returns>
/// A pointer to the function, or NULL, if the function could not be found.
/// </returns>
static LPVOID PebGetProcAddress(DWORD moduleHash, DWORD functionHash);

#endif