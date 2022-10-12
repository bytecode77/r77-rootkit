namespace TestConsole
{
	public sealed class LogDetailsItem : LogItem
	{
		public string Text { get; set; }

		public LogDetailsItem(string text)
		{
			Text = text;
		}
	}
}