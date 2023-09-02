using Global;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace Example
{
	public partial class MainWindow : Window
	{
		public string FileName => Path.GetFileName(Assembly.GetEntryAssembly().Location);
		public int ProcessId => Process.GetCurrentProcess().Id;
		public bool HasPrefix => FileName.StartsWith(R77Const.HidePrefix);
		public Visibility Message1Visibility => HasPrefix ? Visibility.Visible : Visibility.Collapsed;
		public Visibility Message2Visibility => HasPrefix ? Visibility.Collapsed : Visibility.Visible;

		public MainWindow()
		{
			DataContext = this;
			InitializeComponent();
		}

		private void btnClose_Click(object sender, RoutedEventArgs e)
		{
			Close();
		}
		private void cmbCpuUsage_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			CpuUsage.SetCpuUsage(Convert.ToInt32(((ComboBoxItem)((ComboBox)sender).SelectedItem).DataContext));
		}
		private void btnCpuUsageHelp_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			MessageBox.Show(this, "CPU usage is hidden by r77. To see the effect, increase CPU usage of this process.\r\n\r\nThis process is running with idle priority to not interrupt other tasks.", "Help", MessageBoxButton.OK, MessageBoxImage.Information);
		}
	}
}