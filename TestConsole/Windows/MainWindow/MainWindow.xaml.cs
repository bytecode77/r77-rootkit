using BytecodeApi.Wpf.Cui.Controls;
using System.Windows;

namespace TestConsole;

public partial class MainWindow : UiApplicationWindow
{
	public MainWindowViewModel ViewModel { get; set; }

	public MainWindow()
	{
		ViewModel = new(this);
		InitializeComponent();
	}
	private void MainWindow_Loaded(object sender, RoutedEventArgs e)
	{
		Loaded -= MainWindow_Loaded;

		ProcessesTabPage.Focus();
		ViewModel.WriteInitialLogEntries();
	}

	public void OpenControlPipeTabPage()
	{
		ControlPipeTabPage.IsSelected = true;
	}
}