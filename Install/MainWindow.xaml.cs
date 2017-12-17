using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;

namespace Install
{
	public partial class MainWindow : Window
	{
		public MainWindow()
		{
			InitializeComponent();
		}

		private void btnInstall_Click(object sender, RoutedEventArgs e)
		{
			try
			{
				Install(true);
				Install(false);

				MessageBox.Show("r77 is now installed to AppInit_DLLs.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.GetType() + ": " + ex.Message + "\r\n" + ex.StackTrace, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}
		private void btnUninstall_Click(object sender, RoutedEventArgs e)
		{
			try
			{
				bool removed = false;

				foreach (bool is64bit in new[] { true, false })
				{
					using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, is64bit ? RegistryView.Registry64 : RegistryView.Registry32).OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", true))
					{
						if ((key.GetValue("AppInit_DLLs", "") as string).Contains("$77-"))
						{
							key.SetValue("AppInit_DLLs", "");
							removed = true;
						}
					}
				}

				MessageBox.Show(removed ? "r77 was now removed from AppInit_DLLs." : "r77 was not found in AppInit_DLLs.", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
			}
			catch (Exception ex)
			{
				MessageBox.Show(ex.GetType() + ": " + ex.Message + "\r\n" + ex.StackTrace, "Error", MessageBoxButton.OK, MessageBoxImage.Error);
			}
		}

		private void Install(bool is64bit)
		{
			string extension = "x" + (is64bit ? 64 : 86) + ".dll";
			string destPath = Path.Combine(Path.GetTempPath(), "$77-" + Guid.NewGuid().ToString("N") + "-" + extension);
			File.Copy(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "r77-" + extension), destPath);
			new FileInfo(destPath).Attributes |= FileAttributes.Temporary;

			using (RegistryKey key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, is64bit ? RegistryView.Registry64 : RegistryView.Registry32).OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", true))
			{
				key.SetValue("LoadAppInit_DLLs", 1);
				key.SetValue("RequireSignedAppInit_DLLs", 0);
				key.SetValue("AppInit_DLLs", destPath);
			}
		}
	}
}