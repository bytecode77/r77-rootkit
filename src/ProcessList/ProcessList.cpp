#include "ProcessList.h"

// ProcessList32.exe and ProcessList64.exe are used by TestConsole.exe to retrieve a process list.
// Some of the code only works, if the bitness of the process matches that of the enumerated process.
// Therefore, two executables are required.
// TestConsole.exe reads the console output to display a process list.

int main(int argc, char *argv[])
{
	InitializeApi(INITIALIZE_API_SRAND | INITIALIZE_API_DEBUG_PRIVILEGE);

	// Get r77 configuration to determine which processes are hidden by ID.
	PR77_CONFIG r77Config = LoadR77Config();

	// Get all processes with an r77 signature. The signature indicates either,
	//  - that a process is injected with the rootkit,
	//  - or that it's the r77 service,
	//  - or that it's an r77 helper file.

	PR77_PROCESS r77Processes = new R77_PROCESS[1000];
	DWORD r77ProcessCount = 1000;
	if (!GetR77Processes(r77Processes, &r77ProcessCount)) r77ProcessCount = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) return 1;

	PROCESSENTRY32W processEntry;
	processEntry.dwSize = sizeof(processEntry);

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

			if (!GetProcessUserName(process, userName, &userNameLength))userName[0] = L'\0';

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

		for (DWORD i = 0; i < r77Config->HiddenProcessIdCount; i++)
		{
			if (r77Config->HiddenProcessIds[i] == processEntry.th32ProcessID)
			{
				isHiddenById = 1;
				break;
			}
		}

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