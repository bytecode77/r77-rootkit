namespace TestConsole.Model;

/// <summary>
/// Defines the status of a process.
/// </summary>
public enum ProcessStatus
{
	/// <summary>
	/// The process is running and has no special status.
	/// </summary>
	Running,
	/// <summary>
	/// The process was created since the last update of the process list.
	/// </summary>
	New,
	/// <summary>
	/// The process was terminated after the last update of the process list.
	/// </summary>
	Terminated
}