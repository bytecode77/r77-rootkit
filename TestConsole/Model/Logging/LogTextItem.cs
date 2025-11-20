namespace TestConsole.Model;

public sealed class LogTextItem : LogItem
{
	public string Text { get; private init; }

	public LogTextItem(string text)
	{
		Text = text;
	}

	public override string ToString()
	{
		return Text;
	}
}