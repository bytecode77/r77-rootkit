using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.Text;
using BytecodeApi.UI;
using BytecodeApi.UI.Dialogs;
using BytecodeApi.UI.Extensions;
using System;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace TestConsole
{
	public partial class App : Application
	{
		public static Image GetImage(string name, int width, int height, Thickness margin, bool noDisabledEffect)
		{
			BitmapImage imageSource = new BitmapImage();
			imageSource.BeginInit();
			imageSource.UriSource = new Uri($"{Packs.Application}/TestConsole;component/Resources/{name}.png");
			imageSource.EndInit();

			Image image = new Image
			{
				Source = imageSource,
				Width = width,
				Height = height,
				Margin = margin,
				Stretch = Stretch.Uniform
			};

			if (noDisabledEffect)
			{
				image.Style = Current.FindResource<Style>("ImageNoDisabledEffect");
			}

			return image;
		}
		public static string GetFilePath(string filename, out LogMessage message)
		{
			// Gets the path to a file in the application directory.
			// If the file does not exist, return null and a log message.

			// This is a common issue when using the Test Console, because antivirus software may delete some files.
			// However, the installer is fileless and once executed, doesn't have issues with missing files.

			string path = Path.Combine(ApplicationBase.Path, filename);
			if (File.Exists(path))
			{
				message = null;
				return path;
			}
			else
			{
				message = new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem("File"),
					new LogFileItem(Path.GetFileName(path)),
					new LogTextItem("not found."),
					new LogDetailsItem("It might have been removed by antivirus software.")
				);
				return null;
			}
		}

		private void Application_Startup(object sender, StartupEventArgs e)
		{
			if (ApplicationBase.Process.IsElevated)
			{
				Process.EnterDebugMode();
			}
		}
		private void Application_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
		{
			e.Handled = true;
			string stackTrace = e.Exception.GetFullStackTrace();

			if (MainWindowViewModel.Singleton?.IsInitialized == true)
			{
				// If the main window is initialized, display the exception in the log view.
				Log.Write(new LogMessage
				(
					LogMessageType.Error,
					new LogTextItem(stackTrace)
				));
			}
			else
			{
				// If the exception occurred before the main window is initialized, display a MessageBox and exit.
				MessageBoxes.Error(Wording.TrimText(stackTrace, 1000));
				Current.Shutdown();
			}
		}
	}
}