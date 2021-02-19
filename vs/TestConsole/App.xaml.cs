using BytecodeApi.Extensions;
using BytecodeApi.Text;
using BytecodeApi.UI.Dialogs;
using System.Windows;
using System.Windows.Threading;

namespace TestConsole
{
	public partial class App : Application
	{
		private void Application_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
		{
			e.Handled = true;
			string stackTrace = e.Exception.GetFullStackTrace();

			if (MainWindowViewModel.Singleton?.IsInitialized == true)
			{
				// If the main window is initialized, display the exception in the log view.
				MainWindowViewModel.Singleton.Log(new LogMessage
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