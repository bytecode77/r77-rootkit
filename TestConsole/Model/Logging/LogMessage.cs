namespace TestConsole
{
	public sealed class LogMessage
	{
		public LogMessageType Type { get; private set; }
		public LogItem[] Items { get; private set; }
		public bool Silent { get; private set; }

		public LogMessage(LogMessageType type, params LogItem[] items)
		{
			Type = type;
			Items = items;
		}
		public LogMessage(LogMessageType type, LogItem[] items, bool silent) : this(type, items)
		{
			Silent = silent;
		}
	}
}