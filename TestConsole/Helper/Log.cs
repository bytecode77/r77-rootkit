using BytecodeApi.Win32;
using TestConsole.Model;

namespace TestConsole.Helper;

public static class Log
{
	/// <summary>
	/// An event that is raised when a log message is written.
	/// </summary>
	public static event EventHandler<LogMessage>? LogWritten;

	/// <summary>
	/// Writes an information log message.
	/// </summary>
	/// <param name="items">A collection of items that make up the log message.</param>
	public static void Information(params LogItem?[] items)
	{
		OnLogWritten(new(LogMessageType.Information, items));
	}
	/// <summary>
	/// Writes a warning log message and plays a beep sound.
	/// </summary>
	/// <param name="items">A collection of items that make up the log message.</param>
	public static void Warning(params LogItem?[] items)
	{
		Warning(items, false);
	}
	/// <summary>
	/// Writes a warning log message.
	/// </summary>
	/// <param name="items">A collection of items that make up the log message.</param>
	/// <param name="silent"><see langword="true" /> to play a beep sound.</param>
	public static void Warning(LogItem?[] items, bool silent)
	{
		OnLogWritten(new(LogMessageType.Warning, items));

		if (!silent)
		{
			Desktop.Beep(false);
		}
	}
	/// <summary>
	/// Writes an error log message and plays a beep sound.
	/// </summary>
	/// <param name="items">A collection of items that make up the log message.</param>
	public static void Error(params LogItem?[] items)
	{
		Error(items, false);
	}
	/// <summary>
	/// Writes an error log message.
	/// </summary>
	/// <param name="items">A collection of items that make up the log message.</param>
	/// <param name="silent"><see langword="true" /> to play a beep sound.</param>
	public static void Error(LogItem?[] items, bool silent)
	{
		OnLogWritten(new(LogMessageType.Error, items));

		if (!silent)
		{
			Desktop.Beep(false);
		}
	}

	private static void OnLogWritten(LogMessage message)
	{
		LogWritten?.Invoke(null, message);
	}
}