#define CUSTOM_ENTRY
#include "r77win.h"
#include <Shlwapi.h>

int main()
{
	// TestConsole is written in WPF .net 9.0 and deployed as a self-contained application, instead of AnyCPU.
	// The launcher simply decides which version to launch based on the OS bitness.

	WCHAR applicationDirectory[MAX_PATH + 1];
	GetModuleFileNameW(NULL, applicationDirectory, MAX_PATH);

	WCHAR targetPath[MAX_PATH + 1];
	LPCWSTR targetFileName = Is64BitOperatingSystem() ? L"TestConsole\\x64\\TestConsole.exe" : L"TestConsole\\x86\\TestConsole.exe";

	if (!PathRemoveFileSpecW(applicationDirectory) ||
		!PathCombineW(targetPath, applicationDirectory, targetFileName))
	{
		MessageBoxW(NULL, L"Error", L"Test Console", MB_OK | MB_ICONHAND);
		return 0;
	}

	if (!PathFileExistsW(targetPath))
	{
		WCHAR message[1000];
		StrCpyW(message, L"File '");
		StrCatW(message, targetFileName);
		StrCatW(message, L"' not found.\r\n\r\nIf you built the Solution, remember to run the publish profile of the TestConsole project.");

		MessageBoxW(NULL, message, L"Test Console", MB_OK | MB_ICONHAND);
		return 0;
	}

	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
	i_memset(&startupInfo, 0, sizeof(STARTUPINFOW));
	i_memset(&processInformation, 0, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(startupInfo);

	if (!CreateProcessW(targetPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInformation))
	{
		MessageBoxW(NULL, L"Error", L"Test Console", MB_OK | MB_ICONHAND);
		return 0;
	}

	CloseHandle(processInformation.hThread);
	CloseHandle(processInformation.hProcess);

	return 0;
}