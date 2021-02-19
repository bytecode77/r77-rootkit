using BytecodeApi;
using System.Diagnostics;

namespace TestConsole
{
	/// <summary>
	/// Helper class for Win32 interop.
	/// </summary>
	public static class Win32
	{
		/// <summary>
		/// Determines whether a process with the specified ID is running.
		/// </summary>
		/// <param name="processId">The process ID to check</param>
		/// <returns>
		/// <see langword="true" />, if a process with this process ID is running;
		/// otherwise, <see langword="false" />.
		/// </returns>
		public static bool IsProcessRunning(int processId)
		{
			return CSharp.Try(() => Process.GetProcessById(processId)) != null;
		}
	}
}