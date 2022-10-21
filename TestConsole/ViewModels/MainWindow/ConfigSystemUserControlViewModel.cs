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
	public sealed class ConfigSystemUserControlViewModel : ObservableObject
	{
		public static ConfigSystemUserControlViewModel Singleton { get; private set; }
		public ConfigSystemUserControl View { get; set; }

		private DelegateCommand<ConfigSystemDirectory> _CreateEntryCommand;
		private DelegateCommand<ConfigSystemEntry> _EditCommand;
		private DelegateCommand<ConfigSystemEntry> _DeleteCommand;
		public DelegateCommand<ConfigSystemDirectory> CreateEntryCommand => _CreateEntryCommand ?? (_CreateEntryCommand = new DelegateCommand<ConfigSystemDirectory>(CreateEntryCommand_Execute));
		public DelegateCommand<ConfigSystemEntry> EditCommand => _EditCommand ?? (_EditCommand = new DelegateCommand<ConfigSystemEntry>(EditCommand_Execute));
		public DelegateCommand<ConfigSystemEntry> DeleteCommand => _DeleteCommand ?? (_DeleteCommand = new DelegateCommand<ConfigSystemEntry>(DeleteCommand_Execute));

		private bool UpdateNow;
		private ObservableCollection<ConfigSystemDirectory> _ConfigSystem;
		private ConfigSystemDirectory _SelectedConfigSystemDirectory;
		private ConfigSystemEntry _SelectedConfigSystemEntry;
		public ObservableCollection<ConfigSystemDirectory> ConfigSystem
		{
			get => _ConfigSystem;
			set => Set(ref _ConfigSystem, value);
		}
		public ConfigSystemDirectory SelectedConfigSystemDirectory
		{
			get => _SelectedConfigSystemDirectory;
			set => Set(ref _SelectedConfigSystemDirectory, value);
		}
		public ConfigSystemEntry SelectedConfigSystemEntry
		{
			get => _SelectedConfigSystemEntry;
			set => Set(ref _SelectedConfigSystemEntry, value);
		}

		public ConfigSystemUserControlViewModel(ConfigSystemUserControl view)
		{
			Singleton = this;
			View = view;

			ConfigSystem = TestConsole.ConfigSystem.GetConfigSystem().ToObservableCollection();
			SelectedConfigSystemDirectory = ConfigSystem.First(c => c.Name == "pid");
		}

		private void CreateEntryCommand_Execute(ConfigSystemDirectory parameter)
		{
			ConfigSystemValueWindow dialog = new ConfigSystemValueWindow();
			dialog.ViewModel.IsCreate = true;
			dialog.ViewModel.DirectoryName = parameter.Name;
			dialog.ViewModel.Name = GetNewValueName();

			if (dialog.ShowDialog() == true)
			{
				try
				{
					Log.Write(TestConsole.ConfigSystem.CreateEntry(parameter.Name, dialog.ViewModel.Name, dialog.ViewModel.Value).ToArray());
					UpdateConfigSystem();
				}
				catch (Exception ex)
				{
					Log.Write(new LogMessage
					(
						LogMessageType.Error,
						new LogTextItem("Failed to modify config system. Try to"),
						new LogLinkItem("run as administrator", () => MainWindowViewModel.Singleton.ElevateCommand.Execute()),
						new LogDetailsItem($"Error Details: {ex.Message}")
					));
				}
			}

			string GetNewValueName()
			{
				int newNameIndex = 1;
				while (parameter.Entries.Any(v => v.Name.Equals($"New Value #{newNameIndex}", StringComparison.OrdinalIgnoreCase)))
				{
					newNameIndex++;
				}

				return $"New Value #{newNameIndex}";
			}
		}
		private void EditCommand_Execute(ConfigSystemEntry parameter)
		{
			ConfigSystemDirectory directory = ConfigSystem.First(d => d.Entries.Contains(parameter));

			ConfigSystemValueWindow dialog = new ConfigSystemValueWindow();
			dialog.ViewModel.DirectoryName = directory.Name;
			dialog.ViewModel.Name = parameter.Name;
			dialog.ViewModel.Value = parameter.Value;

			if (dialog.ShowDialog() == true)
			{
				try
				{
					Log.Write(TestConsole.ConfigSystem.CreateEntry(directory.Name, parameter.Name, dialog.ViewModel.Value).ToArray());
					UpdateConfigSystem();
				}
				catch (Exception ex)
				{
					Log.Write(new LogMessage
					(
						LogMessageType.Error,
						new LogTextItem("Failed to modify config system. Try to"),
						new LogLinkItem("run as administrator", () => MainWindowViewModel.Singleton.ElevateCommand.Execute()),
						new LogDetailsItem($"Error Details: {ex.Message}")
					));
				}
			}
		}
		private void DeleteCommand_Execute(ConfigSystemEntry parameter)
		{
			ConfigSystemDirectory directory = ConfigSystem.First(d => d.Entries.Contains(parameter));

			try
			{
				Log.Write(TestConsole.ConfigSystem.DeleteEntry(directory.Name, parameter.Name).ToArray());
				UpdateConfigSystem();
			}
			catch (Exception ex)
			{
				Log.Write(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("Failed to modify config system. Try to"),
					new LogLinkItem("run as administrator", () => MainWindowViewModel.Singleton.ElevateCommand.Execute()),
					new LogDetailsItem($"Error Details: {ex.Message}")
				));
			}
		}
		public void BeginUpdate()
		{
			ThreadFactory.StartThread(() =>
			{
				while (true)
				{
					ObservableCollection<ConfigSystemDirectory> newConfigSystem = TestConsole.ConfigSystem.GetConfigSystem().ToObservableCollection();

					// Only update the list, if it has changed.
					bool updated = false;
					foreach (ConfigSystemDirectory newDirectory in newConfigSystem)
					{
						ConfigSystemDirectory directory = ConfigSystem.First(d => d.Name == newDirectory.Name);

						if (directory.Entries.Count == newDirectory.Entries.Count)
						{
							for (int i = 0; i < directory.Entries.Count; i++)
							{
								if (directory.Entries[i].Name != newDirectory.Entries[i].Name ||
									directory.Entries[i].Value != newDirectory.Entries[i].Value)
								{
									updated = true;
									break;
								}
							}

							if (updated) break;
						}
						else
						{
							updated = true;
							break;
						}
					}

					if (updated)
					{
						ConfigSystemDirectory newSelectedConfigSystemDirectory = newConfigSystem.FirstOrDefault(directory => directory.Name == SelectedConfigSystemDirectory?.Name);
						ConfigSystemEntry newSelectedConfigSystemEntry = newSelectedConfigSystemDirectory?.Entries.FirstOrDefault(entry => entry.Name == SelectedConfigSystemEntry?.Name);

						View.Dispatch(() =>
						{
							SelectedConfigSystemDirectory = null;
							SelectedConfigSystemEntry = null;
							ConfigSystem = newConfigSystem;
							SelectedConfigSystemDirectory = newSelectedConfigSystemDirectory;
							SelectedConfigSystemEntry = newSelectedConfigSystemEntry;
						});
					}

					CSharp.Timeout(() => UpdateNow, TimeSpan.FromSeconds(1), TimeSpan.FromMilliseconds(10));
					UpdateNow = false;
				}
			});
		}
		public void UpdateConfigSystem()
		{
			UpdateNow = true;
		}
	}
}