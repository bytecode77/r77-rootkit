#include "ControlPipeListener.h"
#include "r77def.h"
#include "r77win.h"

HANDLE ControlPipeListener(CONTROLCALLBACK callback)
{
	return CreateThread(NULL, 0, ControlPipeListenerThreadFunction, callback, 0, NULL);
}
static DWORD WINAPI ControlPipeListenerThreadFunction(LPVOID parameter)
{
	while (TRUE)
	{
		HANDLE pipe = CreatePublicNamedPipe(CONTROL_PIPE_NAME);
		while (pipe != INVALID_HANDLE_VALUE)
		{
			if (ConnectNamedPipe(pipe, NULL))
			{
				DWORD controlCode;
				DWORD bytesRead;
				if (ReadFile(pipe, &controlCode, 4, &bytesRead, NULL) && bytesRead == sizeof(DWORD))
				{
					((CONTROLCALLBACK)parameter)(controlCode, pipe);
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