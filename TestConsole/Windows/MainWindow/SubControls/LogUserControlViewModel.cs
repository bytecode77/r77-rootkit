using BytecodeApi.Wpf;
using System.Collections.ObjectModel;
using TestConsole.Helper;
using TestConsole.Model;

namespace TestConsole;

public sealed class LogUserControlViewModel : ViewModel
{
	public LogUserControl View { get; set; }

	private DelegateCommand? _ClearCommand;
	public DelegateCommand ClearCommand => _ClearCommand ??= new(ClearCommand_Execute, ClearCommand_CanExecute);

	private ObservableCollection<LogMessage> _LogMessages = [];
	public ObservableCollection<LogMessage> LogMessages
	{
		get => _LogMessages;
		set => Set(ref _LogMessages, value);
	}

	public LogUserControlViewModel(LogUserControl view)
	{
		View = view;

		Log.LogWritten += Log_LogWritten;
	}

	private bool ClearCommand_CanExecute()
	{
		return LogMessages.Any();
	}
	private void ClearCommand_Execute()
	{
		LogMessages.Clear();
	}
	private void Log_LogWritten(object? sender, LogMessage e)
	{
		View.Dispatch(() =>
		{
			LogMessages.Add(e);
			View.lstLogMessages.ScrollIntoView(View.lstLogMessages.Items[^1]);
		});
	}
}