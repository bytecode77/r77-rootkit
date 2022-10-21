using BytecodeApi.UI.Controls;
using System.Windows;

namespace TestConsole
{
	public partial class ConfigSystemUserControl : ObservableUserControl
	{
		public ConfigSystemUserControlViewModel ViewModel { get; set; }

		public ConfigSystemUserControl()
		{
			ViewModel = new ConfigSystemUserControlViewModel(this);
			InitializeComponent();
		}
		private void ConfigSystemUserControl_LoadedOnce(object sender, RoutedEventArgs e)
		{
			ViewModel.BeginUpdate();
		}
	}
}