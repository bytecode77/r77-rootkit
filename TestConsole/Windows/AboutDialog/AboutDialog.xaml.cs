using BytecodeApi.Wpf.Cui.Controls;
using System.Windows;

namespace TestConsole;

public partial class AboutDialog : UiWindow
{
	public AboutDialogViewModel ViewModel { get; set; }

	public AboutDialog(Window? owner)
	{
		ViewModel = new(this);
		InitializeComponent();
		Owner = owner;
	}
}