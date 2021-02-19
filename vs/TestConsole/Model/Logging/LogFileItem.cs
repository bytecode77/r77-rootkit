namespace TestConsole
{
	public sealed class LogFileItem : LogItem
	{
		public string FileName { get; set; }

		public LogFileItem(string fileName)
		{
			FileName = fileName;
		}
	}
}