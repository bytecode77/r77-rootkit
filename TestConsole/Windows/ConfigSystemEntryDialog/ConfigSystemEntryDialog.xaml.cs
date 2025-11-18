using BytecodeApi.Wpf.Cui.Controls;
using System.Windows;

namespace TestConsole;

public partial class ConfigSystemEntryDialog : UiWindow
{
	public ConfigSystemEntryDialogViewModel ViewModel { get; set; }

	public ConfigSystemEntryDialog(Window? owner)
	{
		ViewModel = new(this);
		InitializeComponent();
		Owner = owner;
	}
	private void ConfigSystemEntryDialog_Loaded(object sender, RoutedEventArgs e)
	{
		txtValue.Focus();
		txtValue.SelectAll();
	}
}