namespace TestConsole
{
	public sealed class LogTextItem : LogItem
	{
		public string Text { get; set; }

		public LogTextItem(string text)
		{
			Text = text;
		}
	}
}