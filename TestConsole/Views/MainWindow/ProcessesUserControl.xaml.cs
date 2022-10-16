using BytecodeApi.UI;
using BytecodeApi.UI.Controls;
using BytecodeApi.UI.Extensions;
using System.Windows;
using System.Windows.Controls;

namespace TestConsole
{
	public partial class ProcessesUserControl : ObservableUserControl
	{
		public ProcessesUserControlViewModel ViewModel { get; set; }

		public int ProcessListScrollOffset
		{
			get => (int)lstProcesses.FindChild<ScrollViewer>(UITreeType.Visual, child => true).VerticalOffset;
			set => lstProcesses.FindChild<ScrollViewer>(UITreeType.Visual, child => true).ScrollToVerticalOffset(value);
		}

		public ProcessesUserControl()
		{
			ViewModel = new ProcessesUserControlViewModel(this);
			InitializeComponent();
		}
		private void ProcessesUserControl_LoadedOnce(object sender, RoutedEventArgs e)
		{
			ViewModel.BeginUpdateProcesses();
		}
	}
}