#pragma comment(linker, "/subsystem:windows")

#include "../r77api.h"
#include <tlhelp32.h>

/// <summary>
/// Helper32.exe and Helper64.exe are used by TestConsole.exe to retrieve a process list.
/// Some of the code only works, if the bitness of the process matches that of the enumerated process.
/// Therefore, two executables are required.
/// TestConsole.exe reads the console output to display a process list.
/// </summary>
/// <returns>
/// The return value to be returned by the main entry point.
/// </returns>
int ProcessList();
/// <summary>
/// Creates the configuration system under HKEY_LOCAL_MACHINE\SOFTWARE\$77config.
/// Creating this key requires elevated privileges only once. After creation, the DACL is set to allow full access by any user.
/// Normally, the r77 installer creates this key. When using the Test Console without installing r77, this step is performed by TestConsole.exe invoking "Helper32.exe -config".
/// </summary>
/// <returns>
/// The return value to be returned by the main entry point.
/// </returns>
int CreateConfig();
/// <summary>
/// Injects r77 into a specific process, or all processes.
/// </summary>
/// <param name="processId">The process ID to be injected, or -1, to inject all processes.</param>
/// <param name="dllPath">The path to r77-x86.dll or r77-x64.dll.</param>
/// <returns>
/// The return value to be returned by the main entry point.
/// </returns>
int Inject(DWORD processId, LPCWSTR dllPath);
/// <summary>
/// Detaches r77 from a specific process, or all processes.
/// </summary>
/// <param name="processId">The process ID to be detached, or -1, to detach all processes.</param>
/// <returns>
/// The return value to be returned by the main entry point.
/// </returns>
int Detach(DWORD processId);