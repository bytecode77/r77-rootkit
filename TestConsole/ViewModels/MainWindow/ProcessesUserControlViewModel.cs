using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.Threading;
using BytecodeApi.UI;
using BytecodeApi.UI.Data;
using System;
using System.Collections.ObjectModel;
using System.Linq;

namespace TestConsole
{
	public sealed class ProcessesUserControlViewModel : ObservableObject
	{
		public static ProcessesUserControlViewModel Singleton { get; private set; }
		public ProcessesUserControl View { get; set; }

		private DelegateCommand<ProcessView> _InjectCommand;
		private DelegateCommand<ProcessView> _DetachCommand;
		private DelegateCommand<ProcessView> _HideCommand;
		private DelegateCommand<ProcessView> _UnhideCommand;
		public DelegateCommand<ProcessView> InjectCommand => _InjectCommand ?? (_InjectCommand = new DelegateCommand<ProcessView>(InjectCommand_Execute));
		public DelegateCommand<ProcessView> DetachCommand => _DetachCommand ?? (_DetachCommand = new DelegateCommand<ProcessView>(DetachCommand_Execute));
		public DelegateCommand<ProcessView> HideCommand => _HideCommand ?? (_HideCommand = new DelegateCommand<ProcessView>(HideCommand_Execute));
		public DelegateCommand<ProcessView> UnhideCommand => _UnhideCommand ?? (_UnhideCommand = new DelegateCommand<ProcessView>(UnhideCommand_Execute));

		private bool UpdateNow;
		private ObservableCollection<ProcessView> _Processes;
		private ProcessView _SelectedProcess;
		public ObservableCollection<ProcessView> Processes
		{
			get => _Processes;
			set => Set(ref _Processes, value);
		}
		public ProcessView SelectedProcess
		{
			get => _SelectedProcess;
			set => Set(ref _SelectedProcess, value);
		}

		public ProcessesUserControlViewModel(ProcessesUserControl view)
		{
			Singleton = this;
			View = view;

			Processes = new ObservableCollection<ProcessView>();
		}

		private void InjectCommand_Execute(ProcessView parameter)
		{
			Log.Write(ProcessList.Inject(parameter).ToArray());
			UpdateProcesses();
		}
		private void DetachCommand_Execute(ProcessView parameter)
		{
			Log.Write(ProcessList.Detach(parameter).ToArray());
			UpdateProcesses();
		}
		private void HideCommand_Execute(ProcessView parameter)
		{
			Log.Write(ProcessList.Hide(parameter).ToArray());
			UpdateProcesses();
		}
		private void UnhideCommand_Execute(ProcessView parameter)
		{
			Log.Write(ProcessList.Unhide(parameter).ToArray());
			UpdateProcesses();
		}
		public void BeginUpdateProcesses()
		{
			ThreadFactory.StartThread(() =>
			{
				while (true)
				{
					ObservableCollection<ProcessView> newProcesses = ProcessList.GetProcesses().ToObservableCollection();

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

					CSharp.Timeout(() => UpdateNow, TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(10));
					UpdateNow = false;
				}
			});
		}
		public void UpdateProcesses()
		{
			UpdateNow = true;
		}
	}
}