using BytecodeApi.Extensions;

namespace TestConsole.Model;

public sealed class LogMessage
{
	public DateTime TimeStamp { get; private init; }
	public LogMessageType Type { get; private init; }
	public LogItem[] Items { get; private init; }
	public string Text { get; private init; }

	public LogMessage(LogMessageType type, LogItem?[] items)
	{
		TimeStamp = DateTime.Now;
		Type = type;
		Items = items.ExceptNull().ToArray();
		Text = Items.Select(item => item.ToString() + (item.NoSpacing ? null : " ")).AsString();
	}
}