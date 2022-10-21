#include "r77mindef.h"
#ifndef _CONTROLPIPELISTENER_H
#define _CONTROLPIPELISTENER_H

/// <summary>
/// A callback that notifies the r77 service about a command.
/// </summary>
typedef VOID(*CONTROLCALLBACK)(DWORD controlCode, HANDLE pipe);

/// <summary>
/// Creates a new listener for the control pipe that receives commands from any process.
/// </summary>
/// <param name="callback">The function that is called, when a command is received by another process.</param>
VOID ControlPipeListener(CONTROLCALLBACK callback);
static DWORD WINAPI ControlPipeListenerThread(LPVOID parameter);

#endif