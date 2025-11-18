using BytecodeApi.Extensions;
using BytecodeApi.Wpf;
using System.Collections.ObjectModel;
using TestConsole.Helper;
using TestConsole.Model;

namespace TestConsole;

public sealed class ProcessListUserControlViewModel : ViewModel
{
	public static ProcessListUserControlViewModel? Singleton { get; private set; }
	public ProcessListUserControl View { get; set; }

	private DelegateCommand<ProcessModel>? _InjectCommand;
	private DelegateCommand<ProcessModel>? _DetachCommand;
	private DelegateCommand<ProcessModel>? _HideCommand;
	private DelegateCommand<ProcessModel>? _UnhideCommand;
	public DelegateCommand<ProcessModel> InjectCommand => _InjectCommand ??= new(InjectCommand_Execute!);
	public DelegateCommand<ProcessModel> DetachCommand => _DetachCommand ??= new(DetachCommand_Execute!);
	public DelegateCommand<ProcessModel> HideCommand => _HideCommand ??= new(HideCommand_Execute!);
	public DelegateCommand<ProcessModel> UnhideCommand => _UnhideCommand ??= new(UnhideCommand_Execute!);

	private ObservableCollection<ProcessModel> _Processes = [];
	private ProcessModel? _SelectedProcess;
	public ObservableCollection<ProcessModel> Processes
	{
		get => _Processes;
		set => Set(ref _Processes, value);
	}
	public ProcessModel? SelectedProcess
	{
		get => _SelectedProcess;
		set => Set(ref _SelectedProcess, value);
	}

	public ProcessListUserControlViewModel(ProcessListUserControl view)
	{
		Singleton = this;
		View = view;

		BeginUpdate();
	}

	private async void BeginUpdate()
	{
		while (true)
		{
			await Update();
			await Task.Delay(1000);
		}
	}
	public async Task Update()
	{
		await Task.Run(() =>
		{
			// Retrieve the new process list and mark processes as newly created or terminated based on the previous list.
			ObservableCollection<ProcessModel> newProcesses = ProcessList
				.GetProcesses()
				.Each(process => process.Status = Processes.Any() && Processes.None(p => p.Id == process.Id) ? ProcessStatus.New : ProcessStatus.Running)
				.ToObservableCollection();

			newProcesses.AddRange(
				Processes
					.Where(process => process.Status != ProcessStatus.Terminated)
					.Where(process => newProcesses.None(p => p.Id == process.Id))
					.Select(process => new ProcessModel(process))
					.Each(process => process.Status = ProcessStatus.Terminated)
			);

			// Only update the list only, if it has changed.
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
				ProcessModel? newSelectedProcess = newProcesses.FirstOrDefault(process => process.Id == SelectedProcess?.Id);

				int oldSelectedIndex = Processes
					.OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
					.ThenBy(process => process.Id)
					.IndexOf(SelectedProcess);

				int newSelectedIndex = newProcesses
					.OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
					.ThenBy(process => process.Id)
					.IndexOf(newSelectedProcess);

				View.Dispatch(() =>
				{
					int oldScrollOffset = View.ProcessListScrollOffset;

					SelectedProcess = null;
					Processes = newProcesses;
					SelectedProcess = newSelectedProcess;

					if (newSelectedProcess != null)
					{
						View.ProcessListScrollOffset = oldScrollOffset + newSelectedIndex - oldSelectedIndex;
					}
				});
			}
		});
	}

	private async void InjectCommand_Execute(ProcessModel process)
	{
		if (await ProcessList.Inject(process))
		{
			process.IsInjected = true;
		}

		await Update();
	}
	private async void DetachCommand_Execute(ProcessModel process)
	{
		if (await ProcessList.Detach(process))
		{
			process.IsInjected = false;
		}

		await Update();
	}
	private async void HideCommand_Execute(ProcessModel process)
	{
		if (await ProcessList.Hide(process))
		{
			process.IsHiddenById = true;
		}

		ConfigSystemUserControlViewModel.Singleton?.Update();
		await Update();
	}
	private async void UnhideCommand_Execute(ProcessModel process)
	{
		if (await ProcessList.Unhide(process))
		{
			process.IsHiddenById = false;
		}

		ConfigSystemUserControlViewModel.Singleton?.Update();
		await Update();
	}
}