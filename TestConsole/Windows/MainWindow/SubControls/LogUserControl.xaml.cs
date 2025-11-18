using BytecodeApi.Wpf.Controls;

namespace TestConsole;

public partial class LogUserControl : ObservableUserControl
{
	public LogUserControlViewModel ViewModel { get; set; }

	public LogUserControl()
	{
		ViewModel = new(this);
		InitializeComponent();
	}
}