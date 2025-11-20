using BytecodeApi.Wpf.Controls;

namespace TestConsole;

public partial class R77ServiceUserControl : ObservableUserControl
{
	public R77ServiceUserControlViewModel ViewModel { get; set; }

	public R77ServiceUserControl()
	{
		ViewModel = new(this);
		InitializeComponent();
	}
}