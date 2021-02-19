#include "Inject.h"

int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	InitializeApi(INITIALIZE_API_SRAND | INITIALIZE_API_DEBUG_PRIVILEGE);

	int argCount;
	LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &argCount);
	if (!args || argCount != 3) return 1;

	if (!PathFileExistsW(args[2]) || PathIsDirectoryW(args[2])) return 1;

	// Read r77-x86.dll or r77-x64.dll into memory for reflective DLL injection.
	LPBYTE dll;
	DWORD dllSize;
	if (!ReadFileContent(args[2], &dll, &dllSize)) return 1;

	if (!lstrcmpiW(args[1], L"-all"))
	{
		// "Inject32|64.exe -all C:\path\to\r77.dll" injects r77 into all processes.
		LPDWORD processes = new DWORD[10000];
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
		// "Inject32|64.exe 1234 C:\path\to\r77.dll" injects r77 into the given PID.
		DWORD processId = _wtol(args[1]);
		return processId > 0 && InjectDll(processId, dll, dllSize, FALSE) ? 0 : 1;
	}
}