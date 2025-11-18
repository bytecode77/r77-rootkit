#define CUSTOM_ENTRY
#include "r77win.h"
#include <Shlwapi.h>
#include <PathCch.h>

int main()
{
	// TestConsole is written in WPF .net 9.0 and deployed as a self-contained application, instead of AnyCPU.
	// The launcher simply decides which version to launch based on the OS bitness.

	WCHAR applicationDirectory[MAX_PATH + 1];
	WCHAR targetPath[MAX_PATH + 1];

	if (FAILED(GetModuleFileNameW(NULL, applicationDirectory, MAX_PATH))) return 1;
	if (!PathRemoveFileSpecW(applicationDirectory)) return 1;

	LPCWSTR targetFileName = Is64BitOperatingSystem() ? L"TestConsole\\x64\\TestConsole.exe" : L"TestConsole\\x86\\TestConsole.exe";
	PathCombineW(targetPath, applicationDirectory, targetFileName);

	if (!PathFileExistsW(targetPath))
	{
		WCHAR message[1000];
		StrCpyW(message, L"File '");
		StrCatW(message, targetFileName);
		StrCatW(message, L"' not found.");

		MessageBoxW(NULL, message, L"Test Console", MB_OK | MB_ICONHAND);
		return 1;
	}

	STARTUPINFOW startupInfo;
	PROCESS_INFORMATION processInformation;
	i_memset(&startupInfo, 0, sizeof(STARTUPINFOW));
	i_memset(&processInformation, 0, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(startupInfo);

	if (!CreateProcessW(targetPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInformation)) return 1;

	return 0;
}