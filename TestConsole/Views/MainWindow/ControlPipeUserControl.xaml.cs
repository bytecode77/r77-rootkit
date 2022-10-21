using BytecodeApi.UI.Controls;
using System.Windows;

namespace TestConsole
{
	public partial class ControlPipeUserControl : ObservableUserControl
	{
		public ControlPipeUserControlViewModel ViewModel { get; set; }

		public ControlPipeUserControl()
		{
			ViewModel = new ControlPipeUserControlViewModel(this);
			InitializeComponent();
		}
		private void ControlPipeUserControl_LoadedOnce(object sender, RoutedEventArgs e)
		{
			ViewModel.BeginUpdate();
		}
	}
}