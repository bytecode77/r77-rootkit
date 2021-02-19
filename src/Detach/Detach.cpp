#include "Detach.h"

int CALLBACK WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow)
{
	InitializeApi(INITIALIZE_API_SRAND | INITIALIZE_API_DEBUG_PRIVILEGE);

	int argCount;
	LPWSTR *args = CommandLineToArgvW(GetCommandLineW(), &argCount);
	if (!args || argCount != 2) return 1;

	if (!lstrcmpiW(args[1], L"-all"))
	{
		// "Detach32|64.exe -all" detaches r77 from all processes.
		DetachAllInjectedProcesses();
		return 0;
	}
	else
	{
		// "Detach32|64.exe 1234" detaches r77 from the given PID.
		DWORD processId = _wtol(args[1]);
		return processId > 0 && DetachInjectedProcess(processId) ? 0 : 1;
	}
}