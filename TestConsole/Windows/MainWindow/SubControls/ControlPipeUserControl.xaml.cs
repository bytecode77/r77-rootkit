using BytecodeApi.Wpf.Controls;

namespace TestConsole;

public partial class ControlPipeUserControl : ObservableUserControl
{
	public ControlPipeUserControlViewModel ViewModel { get; set; }

	public ControlPipeUserControl()
	{
		ViewModel = new(this);
		InitializeComponent();
	}
}