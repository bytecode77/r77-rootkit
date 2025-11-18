using BytecodeApi.Wpf;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using TestConsole.Model;

namespace TestConsole.Converters;

public sealed class LogMessageToTextBlockConverter : ConverterBase<LogMessage>
{
	public override object? Convert(LogMessage? message)
	{
		if (message == null)
		{
			return null;
		}
		else
		{
			TextBlock textBlock = new();

			foreach (LogItem item in message.Items)
			{
				if (item is LogTextItem textItem)
				{
					textBlock.Inlines.Add(new Run(textItem.Text));
				}
				else if (item is LogDetailsItem detailsItem)
				{
					textBlock.Inlines.Add(new Run(detailsItem.Text) { FontStyle = FontStyles.Italic });
				}
				else if (item is LogLinkItem linkItem)
				{
					Hyperlink hyperlink = new(new Run(linkItem.Text))
					{
						DataContext = linkItem,
						Cursor = Cursors.Hand
					};

					hyperlink.PreviewMouseLeftButtonDown += (sender, e) => UIContext.Find<LogLinkItem>(sender)?.Action();
					textBlock.Inlines.Add(hyperlink);
				}
				else if (item is LogFileItem fileItem)
				{
					textBlock.Inlines.Add(new Run(fileItem.FileName) { FontWeight = FontWeights.Bold });
				}
				else
				{
					throw new NotImplementedException();
				}

				if (item != message.Items.Last() && !item.NoSpacing)
				{
					textBlock.Inlines.Add(new Run(" "));
				}
			}

			return textBlock;
		}
	}
}