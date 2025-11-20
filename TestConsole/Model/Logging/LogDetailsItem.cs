namespace TestConsole.Model;

public sealed class LogDetailsItem : LogItem
{
	public string Text { get; private init; }

	public LogDetailsItem(string text)
	{
		Text = text;
	}

	public override string ToString()
	{
		return Text;
	}
}