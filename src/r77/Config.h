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