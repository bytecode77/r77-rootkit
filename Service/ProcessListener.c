#include "ProcessListener.h"
#include "r77def.h"
#include "r77win.h"
#include <Psapi.h>

HANDLE NewProcessListener(PROCESSIDCALLBACK callback)
{
	return CreateThread(NULL, 0, NewProcessListenerThreadFunction, callback, 0, NULL);
}
static DWORD WINAPI NewProcessListenerThreadFunction(LPVOID parameter)
{
	LPDWORD currendProcesses = NEW_ARRAY(DWORD, 10000);
	LPDWORD previousProcesses = NEW_ARRAY(DWORD, 10000);
	DWORD currendProcessCount = 0;
	DWORD previousProcessCount = 0;

	while (TRUE)
	{
		if (EnumProcesses(currendProcesses, sizeof(DWORD) * 10000, &currendProcessCount))
		{
			currendProcessCount /= sizeof(DWORD);

			for (DWORD i = 0; i < currendProcessCount; i++)
			{
				// Compare the result of EnumProcesses with the previous list and invoke the callback for new processes.
				BOOL isNew = TRUE;

				for (DWORD j = 0; j < previousProcessCount; j++)
				{
					if (currendProcesses[i] == previousProcesses[j])
					{
						isNew = FALSE;
						break;
					}
				}

				if (isNew)
				{
					((PROCESSIDCALLBACK)parameter)(currendProcesses[i]);
				}
			}

			i_memcpy(previousProcesses, currendProcesses, sizeof(DWORD) * 10000);
			previousProcessCount = currendProcessCount;
		}

		Sleep(100);
	}

	return 0;
}

HANDLE ChildProcessListener(PROCESSIDCALLBACK callback)
{
	return CreateThread(NULL, 0, ChildProcessListenerThreadFunction, callback, 0, NULL);
}
static DWORD WINAPI ChildProcessListenerThreadFunction(LPVOID parameter)
{
	while (TRUE)
	{
		HANDLE pipe = CreatePublicNamedPipe(CHILD_PROCESS_PIPE_NAME);
		while (pipe != INVALID_HANDLE_VALUE)
		{
			if (ConnectNamedPipe(pipe, NULL))
			{
				DWORD processId;
				DWORD bytesRead;
				if (ReadFile(pipe, &processId, 4, &bytesRead, NULL))
				{
					// Invoke the callback. The callback should inject r77 into the process.
					((PROCESSIDCALLBACK)parameter)(processId);

					// Notify the callee that the callback completed (r77 is injected) and NtResumeThread can be called.
					BYTE returnValue = 77;
					DWORD bytesWritten;
					WriteFile(pipe, &returnValue, sizeof(BYTE), &bytesWritten, NULL);
				}
			}
			else
			{
				Sleep(1);
			}

			DisconnectNamedPipe(pipe);
		}

		Sleep(1);
	}

	return 0;
}