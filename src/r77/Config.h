/// <summary>
/// Global configuration system for r77.
/// </summary>
class Config
{
private:
	static HANDLE Thread;
	static PR77_CONFIG Configuration;

	static DWORD WINAPI UpdateThread(LPVOID parameter);
public:
	/// <summary>
	/// Initializes the configuration system.
	/// </summary>
	static void Initialize();
	/// <summary>
	/// Uninitializes the configuration system.
	/// </summary>
	static void Shutdown();

	/// <summary>
	/// Determines whether a process should be hidden based on a specific process ID.
	/// </summary>
	/// <param name="processId">The process ID to check.</param>
	/// <returns>
	/// true, if the process with the specified ID should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsProcessIdHidden(DWORD processId);
	/// <summary>
	/// Determines whether a process should be hidden based on a specific name.
	/// </summary>
	/// <param name="processName">The process name to check.</param>
	/// <returns>
	/// true, if the process with the specified name should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsProcessNameHidden(LPCWSTR processName);
	/// <summary>
	/// Determines whether a process should be hidden based on a specific name.
	/// </summary>
	/// <param name="processName">The process name to check.</param>
	/// <returns>
	/// true, if the process with the specified name should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsProcessNameHidden(UNICODE_STRING processName);
	/// <summary>
	/// Determines whether a file or directory should be hidden based on its full path.
	/// </summary>
	/// <param name="path">The full path to check.</param>
	/// <returns>
	/// true, if the file or directory with the specified full path should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsPathHidden(LPCWSTR path);
	/// <summary>
	/// Determines whether a service should be hidden based on a specific name.
	/// </summary>
	/// <param name="serviceName">The service name to check.</param>
	/// <returns>
	/// true, if the service with the specified name should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsServiceNameHidden(LPCWSTR serviceName);
	/// <summary>
	/// Determines whether a local TCP port should be hidden.
	/// </summary>
	/// <param name="port">The TCP port to check.</param>
	/// <returns>
	/// true, if the local TCP port should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsTcpLocalPortHidden(USHORT port);
	/// <summary>
	/// Determines whether a remote TCP port should be hidden.
	/// </summary>
	/// <param name="port">The TCP port to check.</param>
	/// <returns>
	/// true, if the remote TCP port should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsTcpRemotePortHidden(USHORT port);
	/// <summary>
	/// Determines whether a UDP port should be hidden.
	/// </summary>
	/// <param name="port">The UDP port to check.</param>
	/// <returns>
	/// true, if the UDP port should be hidden;
	/// otherwise, false.
	/// </returns>
	static bool IsUdpPortHidden(USHORT port);
};