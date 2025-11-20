using BytecodeApi.Wpf;
using BytecodeApi.Wpf.Controls;
using System.Windows.Input;
using TestConsole.Model;

namespace TestConsole;

public partial class ConfigSystemUserControl : ObservableUserControl
{
	public ConfigSystemUserControlViewModel ViewModel { get; set; }

	public ConfigSystemUserControl()
	{
		ViewModel = new(this);
		InitializeComponent();
	}

	private void TreeViewItem_MouseDoubleClick(object sender, MouseButtonEventArgs e)
	{
		if (UIContext.Find<ConfigSystemEntryTreeNode>(e.Source) != null)
		{
			ViewModel.EditEntryCommand.Execute();
		}
	}
	private void TreeViewItem_KeyDown(object sender, KeyEventArgs e)
	{
		if (UIContext.Find<ConfigSystemEntryTreeNode>(e.Source) != null)
		{
			if (e.Key is Key.Return or Key.F2)
			{
				ViewModel.EditEntryCommand.Execute();
				e.Handled = true;
			}
			else if (e.Key == Key.Delete)
			{
				ViewModel.DeleteEntryCommand.Execute();
				e.Handled = true;
			}
		}
	}
}