using BytecodeApi.Wpf;
using BytecodeApi.Wpf.Controls;
using BytecodeApi.Wpf.Extensions;
using System.Windows.Controls;

namespace TestConsole;

public partial class ProcessListUserControl : ObservableUserControl
{
	public ProcessListUserControlViewModel ViewModel { get; set; }

	public int ProcessListScrollOffset
	{
		get => (int?)lstProcesses?.FindChild<ScrollViewer>(UITreeType.Visual)?.VerticalOffset ?? 0;
		set => lstProcesses?.FindChild<ScrollViewer>(UITreeType.Visual)?.ScrollToVerticalOffset(value);
	}

	public ProcessListUserControl()
	{
		ViewModel = new(this);
		InitializeComponent();
	}
}