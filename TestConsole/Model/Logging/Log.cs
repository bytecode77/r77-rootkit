using System;

namespace TestConsole
{
	public static class Log
	{
		public static event EventHandler<LogMessage> LogWritten;

		public static void Write(params LogMessage[] messages)
		{
			foreach (LogMessage logMessage in messages)
			{
				LogWritten?.Invoke(null, logMessage);
			}
		}
	}
}