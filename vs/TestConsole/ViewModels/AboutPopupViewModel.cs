using BytecodeApi.UI;
using BytecodeApi.UI.Data;
using System.Diagnostics;

namespace TestConsole
{
	public sealed class AboutPopupViewModel : ObservableObject
	{
		public AboutPopup View { get; set; }

		private DelegateCommand<string> _WebLinkCommand;
		public DelegateCommand<string> WebLinkCommand => _WebLinkCommand ?? (_WebLinkCommand = new DelegateCommand<string>(WebLinkCommand_Execute));

		public AboutPopupViewModel(AboutPopup view)
		{
			View = view;
		}

		private void WebLinkCommand_Execute(string parameter)
		{
			Process.Start(parameter);
		}
	}
}