using System;

namespace TestConsole
{
	public sealed class LogLinkItem : LogItem
	{
		public string Text { get; set; }
		public Action Action { get; set; }

		public LogLinkItem(string text, Action action)
		{
			Text = text;
			Action = action;
		}
	}
}