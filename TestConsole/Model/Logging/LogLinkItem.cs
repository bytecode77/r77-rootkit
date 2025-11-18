namespace TestConsole.Model;

public sealed class LogLinkItem : LogItem
{
	public string Text { get; private init; }
	public Action Action { get; private init; }

	public LogLinkItem(string text, Action action)
	{
		Text = text;
		Action = action;
	}

	public override string ToString()
	{
		return Text;
	}
}