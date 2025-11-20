using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.Wpf;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Windows;
using TestConsole.Helper;
using TestConsole.Model;

namespace TestConsole;

public sealed class ConfigSystemUserControlViewModel : ViewModel
{
	public static ConfigSystemUserControlViewModel? Singleton { get; private set; }
	public ConfigSystemUserControl View { get; set; }

	private DelegateCommand? _ExpandAllCommand;
	private DelegateCommand? _CollapseAllCommand;
	private DelegateCommand? _OpenConfigSystemKeyCommand;
	private DelegateCommand? _EditEntryCommand;
	private DelegateCommand? _CreateEntryCommand;
	private DelegateCommand? _DeleteEntryCommand;
	private DelegateCommand? _DeleteDirectoryCommand;
	public DelegateCommand ExpandAllCommand => _ExpandAllCommand ??= new(ExpandAllCommand_Execute);
	public DelegateCommand CollapseAllCommand => _CollapseAllCommand ??= new(CollapseAllCommand_Execute);
	public DelegateCommand OpenConfigSystemKeyCommand => _OpenConfigSystemKeyCommand ??= new(OpenConfigSystemKeyCommand_Execute, OpenConfigSystemKeyCommand_CanExecute);
	public DelegateCommand EditEntryCommand => _EditEntryCommand ??= new(EditEntryCommand_Execute, EditEntryCommand_CanExecute);
	public DelegateCommand CreateEntryCommand => _CreateEntryCommand ??= new(CreateEntryCommand_Execute, CreateEntryCommand_CanExecute);
	public DelegateCommand DeleteEntryCommand => _DeleteEntryCommand ??= new(DeleteEntryCommand_Execute, DeleteEntryCommand_CanExecute);
	public DelegateCommand DeleteDirectoryCommand => _DeleteDirectoryCommand ??= new(DeleteDirectoryCommand_Execute, DeleteDirectoryCommand_CanExecute);

	private bool _IsConfigSystemAvailable;
	private ObservableCollection<TreeViewNode> _TreeNodes = [];
	private TreeViewNode? _SelectedTreeNode;
	public bool IsConfigSystemAvailable
	{
		get => _IsConfigSystemAvailable;
		set => Set(ref _IsConfigSystemAvailable, value);
	}
	public ObservableCollection<TreeViewNode> TreeNodes
	{
		get => _TreeNodes;
		set => Set(ref _TreeNodes, value);
	}
	public TreeViewNode? SelectedTreeNode
	{
		get => _SelectedTreeNode;
		set => Set(ref _SelectedTreeNode, value);
	}

	public ConfigSystemUserControlViewModel(ConfigSystemUserControl view)
	{
		Singleton = this;
		View = view;

		BeginUpdate();
	}

	private async void BeginUpdate()
	{
		while (true)
		{
			// If the configuration system is not already created, we can create it any time if we have elevted privileges.
			IsConfigSystemAvailable = ApplicationBase.Process.IsElevated || ConfigSystem.IsConfigSystemCreated;

			await Task.Run(Update);
			await Task.Delay(1000);
		}
	}
	public void Update()
	{
		ConfigSystemDirectory[] directories = ConfigSystem.GetConfigSystem();

		if (TreeNodes.None())
		{
			// Populate the TreeView for the first time.
			View.Dispatch(() => TreeNodes.Add(new TreeViewNode("Config System", "/TestConsole;component/Resources/Icons/ConfigSystem.svg", directories.Select(directory => new ConfigSystemDirectoryTreeNode(directory)))));
		}
		else
		{
			foreach (ConfigSystemDirectory directory in directories)
			{
				ConfigSystemDirectoryTreeNode directoryTreeNode = TreeNodes
					.First()
					.Children
					.OfType<ConfigSystemDirectoryTreeNode>()
					.First(node => node.Directory.Name == directory.Name);

				// Add new entries to the TreeView.
				foreach (ConfigSystemEntry entry in directory.Entries)
				{
					if (directoryTreeNode.Children.OfType<ConfigSystemEntryTreeNode>().None(node => node.Entry.Name == entry.Name && node.Entry.Value == entry.Value))
					{
						View.Dispatch(() =>
						{
							int newIndex = directoryTreeNode.Children
								.OfType<ConfigSystemEntryTreeNode>()
								.TakeWhile(node => string.Compare(node.Entry.Value, entry.Value, true) < 0)
								.Count();

							directoryTreeNode.Children.Insert(newIndex, new ConfigSystemEntryTreeNode(entry));
							directoryTreeNode.IsExpanded = true;
						});
					}
				}

				// Remove deleted entries from the TreeView.
				ConfigSystemEntryTreeNode[] removedTreeNodes = directoryTreeNode.Children
					.OfType<ConfigSystemEntryTreeNode>()
					.Where(node => directory.Entries.None(e => e.Name == node.Entry.Name && e.Value == node.Entry.Value))
					.ToArray();

				if (removedTreeNodes.Any())
				{
					View.Dispatch(() =>
					{
						directoryTreeNode.Children.RemoveRange(removedTreeNodes);
						directoryTreeNode.IsExpanded &= directoryTreeNode.Children.Any();
					});
				}
			}
		}
	}

	private void ExpandAllCommand_Execute()
	{
		Expand(TreeNodes.First());

		void Expand(TreeViewNode node)
		{
			node.IsExpanded = true;
			node.Children.ForEach(child => Expand(child));
		}
	}
	private void CollapseAllCommand_Execute()
	{
		TreeNodes.First().IsExpanded = true;
		TreeNodes.First().Children.ForEach(Collapse);

		void Collapse(TreeViewNode node)
		{
			node.IsExpanded = false;
			node.Children.ForEach(child => Collapse(child));
		}
	}
	private bool OpenConfigSystemKeyCommand_CanExecute()
	{
		return IsConfigSystemAvailable;
	}
	private void OpenConfigSystemKeyCommand_Execute()
	{
		if (ConfigSystem.EnsureConfigSystem())
		{
			using RegistryKey? key = ConfigSystem.GetConfigSystemKey();
			key?.OpenInRegedit();
		}
	}
	private bool EditEntryCommand_CanExecute()
	{
		return SelectedTreeNode is ConfigSystemEntryTreeNode;
	}
	private void EditEntryCommand_Execute()
	{
		ConfigSystemEntryTreeNode entry = (ConfigSystemEntryTreeNode)SelectedTreeNode!;

		ConfigSystemEntryDialog dialog = new(Window.GetWindow(View));
		dialog.ViewModel.Name = entry.Entry.Name;
		dialog.ViewModel.Value = entry.Entry.Value;

		if (dialog.ShowDialog() == true)
		{
			ConfigSystem.CreateEntry(entry.Entry.Directory.Name, entry.Entry.Name, dialog.ViewModel.Value!);
			Update();
			ProcessListUserControlViewModel.Singleton?.Update();
		}
	}
	private bool CreateEntryCommand_CanExecute()
	{
		return SelectedTreeNode is ConfigSystemDirectoryTreeNode or ConfigSystemEntryTreeNode;
	}
	private void CreateEntryCommand_Execute()
	{
		string directoryName = SelectedTreeNode switch
		{
			ConfigSystemDirectoryTreeNode directory => directory.Directory.Name,
			ConfigSystemEntryTreeNode entry => entry.Entry.Directory.Name,
			_ => throw new InvalidOperationException()
		};

		int name = 1;
		for (ConfigSystemDirectory directory = ConfigSystem.GetConfigSystem().First(directory => directory.Name == directoryName); directory.Entries.Any(entry => entry.Name == $"New Value #{name}");)
		{
			name++;
		}

		ConfigSystemEntryDialog dialog = new(Window.GetWindow(View));
		dialog.ViewModel.IsCreate = true;
		dialog.ViewModel.Name = $"New Value #{name}";

		if (dialog.ShowDialog() == true)
		{
			ConfigSystem.CreateEntry(directoryName, dialog.ViewModel.Name!, dialog.ViewModel.Value!);
			Update();
			ProcessListUserControlViewModel.Singleton?.Update();
		}
	}
	private bool DeleteEntryCommand_CanExecute()
	{
		return SelectedTreeNode is ConfigSystemEntryTreeNode;
	}
	private void DeleteEntryCommand_Execute()
	{
		ConfigSystemEntryTreeNode entry = (ConfigSystemEntryTreeNode)SelectedTreeNode!;
		ConfigSystem.DeleteEntry(entry.Entry.Directory.Name, entry.Entry.Name);

		Update();
		ProcessListUserControlViewModel.Singleton?.Update();
	}
	private bool DeleteDirectoryCommand_CanExecute()
	{
		return SelectedTreeNode is ConfigSystemDirectoryTreeNode directory && directory.Children.Any();
	}
	private void DeleteDirectoryCommand_Execute()
	{
		ConfigSystemDirectoryTreeNode directory = (ConfigSystemDirectoryTreeNode)SelectedTreeNode!;
		directory.Children.OfType<ConfigSystemEntryTreeNode>().ForEach(entry => ConfigSystem.DeleteEntry(entry.Entry.Directory.Name, entry.Entry.Name));

		Update();
		ProcessListUserControlViewModel.Singleton?.Update();
	}
}