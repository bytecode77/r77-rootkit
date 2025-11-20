using BytecodeApi;
using BytecodeApi.Data;
using BytecodeApi.Wpf;
using System.Diagnostics;
using System.Windows;

namespace TestConsole.Model;

public abstract class ViewModel : ObservableObject
{
	private DelegateCommand<string>? _OpenUrlCommand;
	private DelegateCommand? _ExitCommand;
	private DelegateCommand? _ElevateCommand;
	public DelegateCommand<string> OpenUrlCommand => _OpenUrlCommand ??= new(OpenUrlCommand_Execute!);
	public DelegateCommand ExitCommand => _ExitCommand ??= new(ExitCommand_Execute);
	public DelegateCommand ElevateCommand => _ElevateCommand ??= new(ElevateCommand_Execute, ElevateCommand_CanExecute);

	private bool _ShowBusyIndicator;
	public bool ShowBusyIndicator
	{
		get => _ShowBusyIndicator;
		set => Set(ref _ShowBusyIndicator, value);
	}

	public virtual async Task Async(Task task)
	{
		await WaitPreviousAsync();

		try
		{
			ShowBusyIndicator = true;
			await task;
		}
		finally
		{
			ShowBusyIndicator = false;
		}
	}
	public virtual async Task Async(Func<Task> task)
	{
		await WaitPreviousAsync();

		try
		{
			ShowBusyIndicator = true;
			await task();
		}
		finally
		{
			ShowBusyIndicator = false;
		}
	}
	public virtual async Task<T> Async<T>(Task<T> task)
	{
		await WaitPreviousAsync();

		try
		{
			ShowBusyIndicator = true;
			return await task;
		}
		finally
		{
			ShowBusyIndicator = false;
		}
	}
	public virtual async Task<T> Async<T>(Func<Task<T>> task)
	{
		await WaitPreviousAsync();

		try
		{
			ShowBusyIndicator = true;
			return await task();
		}
		finally
		{
			ShowBusyIndicator = false;
		}
	}
	private async Task WaitPreviousAsync()
	{
		while (ShowBusyIndicator)
		{
			await Task.Delay(100);
		}
	}

	private void OpenUrlCommand_Execute(string url)
	{
		Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
	}
	private void ExitCommand_Execute()
	{
		Application.Current.Shutdown();
	}
	private bool ElevateCommand_CanExecute()
	{
		return !ApplicationBase.Process.IsElevated;
	}
	private void ElevateCommand_Execute()
	{
		ApplicationBase.RestartElevated(null, Application.Current.Shutdown);
	}
}