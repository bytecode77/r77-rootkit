using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO.FileSystem;
using BytecodeApi.IO.Http;
using BytecodeApi.Threading;
using BytecodeApi.UI;
using BytecodeApi.UI.Data;
using Global;
using System;
using System.Collections.ObjectModel;
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
		private DelegateCommand<ProcessView> _InjectCommand;
		private DelegateCommand<ProcessView> _DetachCommand;
		private DelegateCommand<ProcessView> _HideCommand;
		private DelegateCommand<ProcessView> _UnhideCommand;
		private DelegateCommand _InjectAllCommand;
		private DelegateCommand _DetachAllCommand;
		private DelegateCommand<string> _HelpCommand;
		public DelegateCommand ElevateCommand => _ElevateCommand ?? (_ElevateCommand = new DelegateCommand(ElevateCommand_Execute, ElevateCommand_CanExecute));
		public DelegateCommand<string> RunCommand => _RunCommand ?? (_RunCommand = new DelegateCommand<string>(RunCommand_Execute));
		public DelegateCommand<ProcessView> InjectCommand => _InjectCommand ?? (_InjectCommand = new DelegateCommand<ProcessView>(InjectCommand_Execute));
		public DelegateCommand<ProcessView> DetachCommand => _DetachCommand ?? (_DetachCommand = new DelegateCommand<ProcessView>(DetachCommand_Execute));
		public DelegateCommand<ProcessView> HideCommand => _HideCommand ?? (_HideCommand = new DelegateCommand<ProcessView>(HideCommand_Execute));
		public DelegateCommand<ProcessView> UnhideCommand => _UnhideCommand ?? (_UnhideCommand = new DelegateCommand<ProcessView>(UnhideCommand_Execute));
		public DelegateCommand InjectAllCommand => _InjectAllCommand ?? (_InjectAllCommand = new DelegateCommand(InjectAllCommand_Execute));
		public DelegateCommand DetachAllCommand => _DetachAllCommand ?? (_DetachAllCommand = new DelegateCommand(DetachAllCommand_Execute));
		public DelegateCommand<string> HelpCommand => _HelpCommand ?? (_HelpCommand = new DelegateCommand<string>(HelpCommand_Execute));

		private bool UpdateProcessesNow;
		public bool IsInitialized
		{
			get => Get(() => IsInitialized);
			set => Set(() => IsInitialized, value);
		}
		public ObservableCollection<ProcessView> Processes
		{
			get => Get(() => Processes, () => new ObservableCollection<ProcessView>());
			set => Set(() => Processes, value);
		}
		public ProcessView SelectedProcess
		{
			get => Get(() => SelectedProcess);
			set => Set(() => SelectedProcess, value);
		}
		public bool IsAboutVisible
		{
			get => Get(() => IsAboutVisible);
			set => Set(() => IsAboutVisible, value);
		}

		public MainWindowViewModel(MainWindow view)
		{
			Singleton = this;
			View = view;
		}

		public void OnLoaded()
		{
			if (!ApplicationBase.Process.IsElevated)
			{
				Log(new LogMessage
				(
					LogMessageType.Warning,
					new LogTextItem("To inject or detach elevated processes,"),
					new LogLinkItem("run as administrator", () => ElevateCommand.Execute())
				), true);
			}

			if (new[] { "Helper32.exe", "Helper64.exe" }.Any(file => !File.Exists(Path.Combine(ApplicationBase.Path, file))))
			{
				Log(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("Files"),
					new LogFileItem("Helper32.exe"),
					new LogTextItem("and"),
					new LogFileItem("Helper64.exe"),
					new LogTextItem("not found.")
				), true);
			}

			BeginUpdateProcesses();
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
					fileName = Config.HidePrefix + "-Example.exe";
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

					Log(new LogMessage
					(
						LogMessageType.Information,
						new LogTextItem("File"),
						new LogFileItem(fileName),
						new LogTextItem("was executed.")
					));
				}
				catch (Exception ex)
				{
					Log(new LogMessage
					(
						LogMessageType.Error,
						new LogTextItem("Executing"),
						new LogFileItem(fileName),
						new LogTextItem("failed."),
						new LogDetailsItem("Error Details: " + ex.Message)
					));
				}
			}
			else
			{
				Log(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("File"),
					new LogFileItem(fileName),
					new LogTextItem("not found.")
				));
			}
		}
		private void InjectCommand_Execute(ProcessView parameter)
		{
			Log(ProcessList.Inject(parameter).ToArray());
			UpdateProcesses();
		}
		private void DetachCommand_Execute(ProcessView parameter)
		{
			Log(ProcessList.Detach(parameter).ToArray());
			UpdateProcesses();
		}
		private void HideCommand_Execute(ProcessView parameter)
		{
			Log(ProcessList.Hide(parameter).ToArray());
			UpdateProcesses();
		}
		private void UnhideCommand_Execute(ProcessView parameter)
		{
			Log(ProcessList.Unhide(parameter).ToArray());
			UpdateProcesses();
		}
		private void InjectAllCommand_Execute()
		{
			Log(ProcessList.InjectAll().ToArray());
			UpdateProcesses();
		}
		private void DetachAllCommand_Execute()
		{
			Log(ProcessList.DetachAll().ToArray());
			UpdateProcesses();
		}
		private void HelpCommand_Execute(string parameter)
		{
			switch (parameter)
			{
				case "Documentation":
					try
					{
						byte[] pdf = HttpClient.Default.CreateGetRequest("https://bytecode77.com/downloads/r77%20Rootkit%20Technical%20Documentation.pdf").ReadBytes();
						TempDirectory.ExecuteFile("Technical Documentation.pdf", pdf);
					}
					catch (Exception ex)
					{
						Log(new LogMessage
						(
							LogMessageType.Error,
							new LogTextItem("Error downloading"),
							new LogFileItem("Technical Documentation.pdf"),
							new LogTextItem("Please visit"),
							new LogLinkItem("https://bytecode77.com/r77-rootkit", () => Process.Start("https://bytecode77.com/r77-rootkit")),
							new LogDetailsItem("Error Details: " + ex.Message)
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

		public void Log(params LogMessage[] messages)
		{
			foreach (LogMessage message in messages) Log(message, false);
		}
		public void Log(LogMessage message, bool silent)
		{
			View.WriteLog(message, silent);
		}
		public void UpdateProcesses()
		{
			UpdateProcessesNow = true;
		}
		private void BeginUpdateProcesses()
		{
			ThreadFactory.StartThread(() =>
			{
				while (true)
				{
					ObservableCollection<ProcessView> newProcesses = ProcessView.GetProcesses().ToObservableCollection();

					// Only update the list, if it has changed.
					bool updated = false;
					if (newProcesses.Count == Processes.Count)
					{
						for (int i = 0; i < newProcesses.Count; i++)
						{
							if (!newProcesses[i].Equals(Processes[i]))
							{
								updated = true;
								break;
							}
						}
					}
					else
					{
						updated = true;
					}

					if (updated)
					{
						ProcessView newSelectedProcess = newProcesses.FirstOrDefault(process => process.Id == SelectedProcess?.Id);
						int scrollOffset = SelectedProcess != null && newSelectedProcess != null ? newProcesses.IndexOf(newSelectedProcess) - Processes.IndexOf(SelectedProcess) : -1;

						View.Dispatch(() =>
						{
							int oldScrollOffset = View.ProcessListScrollOffset;

							SelectedProcess = null;
							Processes = newProcesses;
							SelectedProcess = newSelectedProcess;

							if (scrollOffset != -1) View.ProcessListScrollOffset = oldScrollOffset + scrollOffset;
						});
					}

					CSharp.Timeout(() => UpdateProcessesNow, TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(10));
					UpdateProcessesNow = false;
				}
			});
		}
	}
}