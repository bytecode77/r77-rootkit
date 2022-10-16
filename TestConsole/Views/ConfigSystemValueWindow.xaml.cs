using BytecodeApi.UI.Controls;
using System.Windows;

namespace TestConsole
{
	public partial class ConfigSystemValueWindow : ObservableWindow
	{
		public ConfigSystemValueWindowViewModel ViewModel { get; set; }

		public ConfigSystemValueWindow()
		{
			ViewModel = new ConfigSystemValueWindowViewModel(this);
			InitializeComponent();
			Owner = MainWindowViewModel.Singleton.View;
		}
		private void ConfigSystemValueWindow_Loaded(object sender, RoutedEventArgs e)
		{
			txtValue.SelectAll();
			txtValue.Focus();
		}
	}
}