using BytecodeApi.Extensions;
using BytecodeApi.IO;
using BytecodeApi.UI;
using BytecodeApi.UI.Controls;
using BytecodeApi.UI.Dialogs;
using System;
using System.ComponentModel;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;

namespace TestConsole
{
	public partial class MainWindow : ObservableWindow
	{
		public MainWindowViewModel ViewModel { get; set; }

		public MainWindow()
		{
			ViewModel = new MainWindowViewModel(this);
			InitializeComponent();

			MessageBoxes.Window = this;
			txtLog.Document.Blocks.Clear();
			ViewModel.IsInitialized = true;
		}
		private void MainWindow_LoadedOnce(object sender, RoutedEventArgs e)
		{
			ViewModel.WriteInitialLogEntries();
		}

		private void lnkLogLink_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
		{
			UIContext.Find<LogLinkItem>(sender).Action();
		}

		public void WriteLog(LogMessage message)
		{
			Paragraph paragraph = new Paragraph();
			Thickness iconMargin = new Thickness(0, 0, 5, -3);

			Brush foreground;
			switch (message.Type)
			{
				case LogMessageType.Default:
					foreground = Brushes.Black;
					paragraph.Inlines.Add(new Border { Width = 16, Height = 16, Margin = iconMargin });
					break;
				case LogMessageType.Information:
					foreground = Brushes.Black;
					paragraph.Inlines.Add(App.GetImage("Information16", 16, 16, iconMargin, true));
					if (!message.Silent) Desktop.Beep();
					break;
				case LogMessageType.Warning:
					foreground = new SolidColorBrush(Color.FromArgb(255, 220, 155, 0));
					paragraph.Inlines.Add(App.GetImage("Warning16", 16, 16, iconMargin, true));
					if (!message.Silent) Desktop.Beep(false);
					break;
				case LogMessageType.Error:
					foreground = new SolidColorBrush(Color.FromArgb(255, 165, 40, 20));
					paragraph.Inlines.Add(App.GetImage("Error16", 16, 16, iconMargin, true));
					if (!message.Silent) Desktop.Beep(false);
					break;
				default:
					throw new InvalidEnumArgumentException();
			}

			paragraph.Inlines.Add(new Run(DateTime.Now.ToStringInvariant("HH:mm:ss")) { TextDecorations = TextDecorations.Underline });
			paragraph.Inlines.Add(new Run(" "));

			foreach (LogItem item in message.Items)
			{
				if (item != message.Items.First()) paragraph.Inlines.Add(new Run(" "));

				if (item is LogTextItem textItem)
				{
					paragraph.Inlines.Add(new Run(textItem.Text));
				}
				else if (item is LogDetailsItem detailsItem)
				{
					paragraph.Inlines.Add(new Run(detailsItem.Text) { FontStyle = FontStyles.Italic });
				}
				else if (item is LogLinkItem linkItem)
				{
					Hyperlink hyperlink = new Hyperlink(new Run(linkItem.Text))
					{
						DataContext = linkItem,
						Cursor = Cursors.Hand
					};
					hyperlink.MouseLeftButtonDown += lnkLogLink_MouseLeftButtonDown;
					paragraph.Inlines.Add(hyperlink);
				}
				else if (item is LogFileItem fileItem)
				{
					paragraph.Inlines.Add(new Run(fileItem.FileName) { FontWeight = FontWeights.Bold });
				}
				else
				{
					throw new NotSupportedException();
				}
			}

			foreach (Inline inline in paragraph.Inlines)
			{
				inline.Foreground = inline is Hyperlink ? new SolidColorBrush(Color.FromArgb(255, 0, 102, 204)) : foreground;
			}

			txtLog.Document.Blocks.Add(paragraph);
			txtLog.ScrollToEnd();
		}
	}
}