#include "r77mindef.h"
#ifndef _PROCESSLISTENER_H
#define _PROCESSLISTENER_H

/// <summary>
/// A callback that notifies about a process ID.
/// </summary>
typedef VOID(*PROCESSIDCALLBACK)(DWORD processId);

/// <summary>
/// Creates a new process listener, that checks for new processes every 100 ms.
/// </summary>
/// <param name="callback">The function that is called, when a process is found that was not present in the previous enumeration.</param>
/// <returns>
/// A handle to the newly created process listener thread.
/// </returns>
HANDLE NewProcessListener(PROCESSIDCALLBACK callback);
static DWORD WINAPI NewProcessListenerThreadFunction(LPVOID parameter);

/// <summary>
/// Creates a named pipe that listens for notifications about created child processes.
/// </summary>
/// <param name="callback">The function that is called, when the named pipe received a process ID.</param>
/// <returns>
/// A handle to the newly created child process listener thread.
/// </returns>
HANDLE ChildProcessListener(PROCESSIDCALLBACK callback);
static DWORD WINAPI ChildProcessListenerThreadFunction(LPVOID parameter);

#endif