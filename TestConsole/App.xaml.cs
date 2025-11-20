using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.Text;
using BytecodeApi.Wpf.Cui;
using BytecodeApi.Wpf.Dialogs;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using TestConsole.Helper;
using TestConsole.Model;

namespace TestConsole;

public partial class App : Application
{
	private void Application_Startup(object sender, StartupEventArgs e)
	{
		SystemParametersEx.SetToolTipDelay(300);
		SystemParametersEx.SetMenuDropAlignment(false);

		if (ApplicationBase.Process.IsElevated)
		{
			Process.EnterDebugMode();
		}
	}
	private void Application_DispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
	{
		if (MainWindowViewModel.Singleton != null)
		{
			Log.Error(new LogTextItem(e.Exception.GetFullStackTrace()));
		}
		else
		{
			Dialog
				.Title(e.Exception.GetType().ToString())
				.Text(e.Exception.Message)
				.Icon(DialogIcon.ShieldErrorRedBar)
				.Expander(Wording.TrimText(e.Exception.GetFullStackTrace(), 1000))
				.Button(DialogResult.OK)
				.Show(null);

			Current.Shutdown();
		}

		e.Handled = true;
	}
}