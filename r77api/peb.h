#include "r77mindef.h"
#ifndef _PEB_H
#define _PEB_H

/// <summary>
/// Retrieves the DLL base address of a module from the PEB.
/// </summary>
/// <param name="moduleHash">The hash of the module name. The module must be loaded.</param>
/// <returns>
/// The DLL base address, or NULL, if the module could not be found.
/// </returns>
LPVOID PebGetModuleHandle(DWORD moduleHash);
/// <summary>
/// Retrieves a function pointer from the PEB.
/// </summary>
/// <param name="moduleHash">The hash of the module name. The module must be loaded.</param>
/// <param name="functionHash">The hash of the function name.</param>
/// <returns>
/// A pointer to the function, or NULL, if the function could not be found.
/// </returns>
LPVOID PebGetProcAddress(DWORD moduleHash, DWORD functionHash);

#endif