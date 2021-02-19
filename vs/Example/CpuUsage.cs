using System;
using System.Diagnostics;
using System.Threading;

namespace Example
{
	/// <summary>
	/// Helper class that simulates CPU usage.
	/// </summary>
	public static class CpuUsage
	{
		private static object CurrentCpuUsage;

		static CpuUsage()
		{
			CurrentCpuUsage = 0;

			// The current process needs to be set to idle priority to not interrupt other tasks on the system.
			using (Process process = Process.GetCurrentProcess())
			{
				process.PriorityClass = ProcessPriorityClass.Idle;
			}

			for (int i = 0; i < Environment.ProcessorCount; i++)
			{
				new Thread(() =>
				{
					try
					{
						Stopwatch stopwatch = new Stopwatch();

						while (true)
						{
							int activeTime;
							lock (CurrentCpuUsage) activeTime = (int)CurrentCpuUsage * 10;

							// CPU usage during active time
							stopwatch.Restart();
							while (stopwatch.ElapsedMilliseconds < activeTime)
							{
							}

							// No CPU usage during inactive time
							stopwatch.Restart();
							while (stopwatch.ElapsedMilliseconds < 1000 - activeTime)
							{
								Thread.Sleep(1);
							}
						}
					}
					catch (ThreadAbortException)
					{
					}
				})
				{
					// The current thread needs to be set to lowest priority to not interrupt the UI of this process.
					IsBackground = true,
					Priority = ThreadPriority.Lowest
				}.Start();
			}
		}

		/// <summary>
		/// Changes the CPU usage that should be simulated.
		/// </summary>
		/// <param name="cpuUsage">The CPU usage to be simulated in percent. This value should fall between 0 and 100.</param>
		public static void SetCpuUsage(int cpuUsage)
		{
			lock (CurrentCpuUsage) CurrentCpuUsage = cpuUsage;
		}
	}
}