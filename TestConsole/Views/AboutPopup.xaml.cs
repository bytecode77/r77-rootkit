using BytecodeApi.UI.Controls;
using System.Windows.Input;

namespace TestConsole
{
	public partial class AboutPopup : ObservableUserControl
	{
		public AboutPopupViewModel ViewModel { get; set; }

		public AboutPopup()
		{
			ViewModel = new AboutPopupViewModel(this);
			InitializeComponent();
		}

		private void BackgroundBorder_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			MainWindowViewModel.Singleton.IsAboutVisible = false;
		}
	}
}