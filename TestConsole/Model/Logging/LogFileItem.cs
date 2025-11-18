namespace TestConsole.Model;

public sealed class LogFileItem : LogItem
{
	public string FileName { get; private init; }

	public LogFileItem(string fileName)
	{
		FileName = fileName;
	}

	public override string ToString()
	{
		return FileName;
	}
}