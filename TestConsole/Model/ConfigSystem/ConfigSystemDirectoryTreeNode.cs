namespace TestConsole.Model;

public sealed class ConfigSystemDirectoryTreeNode : TreeViewNode
{
	public ConfigSystemDirectory Directory { get; private init; }

	public ConfigSystemDirectoryTreeNode(ConfigSystemDirectory directory) : base(directory.Name, "/TestConsole;component/Resources/Icons/FolderClosed.svg", "/TestConsole;component/Resources/Icons/FolderOpened.svg", directory.Entries.OrderBy(entry => entry.Value, StringComparer.OrdinalIgnoreCase).Select(entry => new ConfigSystemEntryTreeNode(entry)))
	{
		Directory = directory;
	}
}