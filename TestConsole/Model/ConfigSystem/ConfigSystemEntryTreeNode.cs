using Microsoft.Win32;

namespace TestConsole.Model;

public sealed class ConfigSystemEntryTreeNode : TreeViewNode
{
	public ConfigSystemEntry Entry { get; private init; }

	public ConfigSystemEntryTreeNode(ConfigSystemEntry entry) : base(entry.Value, entry.Type == RegistryValueKind.DWord ? "/TestConsole;component/Resources/Icons/RegistryIntegerValue.svg" : "/TestConsole;component/Resources/Icons/RegistryStringValue.svg")
	{
		Entry = entry;
	}
}