using BytecodeApi.Data;
using System.Collections.ObjectModel;

namespace TestConsole.Model;

public class TreeViewNode : ObservableObject
{
	private string _Header = "";
	private string? _IconCollapsed;
	private string? _IconExpanded;
	private bool _IsSelected;
	private bool _IsExpanded;
	private ObservableCollection<TreeViewNode> _Children = [];
	public string Header
	{
		get => _Header;
		set => Set(ref _Header, value);
	}
	public string? IconCollapsed
	{
		get => _IconCollapsed;
		set => Set(ref _IconCollapsed, value);
	}
	public string? IconExpanded
	{
		get => _IconExpanded;
		set => Set(ref _IconExpanded, value);
	}
	public bool IsSelected
	{
		get => _IsSelected;
		set => Set(ref _IsSelected, value);
	}
	public bool IsExpanded
	{
		get => _IsExpanded;
		set => Set(ref _IsExpanded, value && Children.Any());
	}
	public ObservableCollection<TreeViewNode> Children
	{
		get => _Children;
		set => Set(ref _Children, value);
	}

	public TreeViewNode(string header, string? icon) : this(header, icon, icon)
	{
	}
	public TreeViewNode(string header, string? iconCollapsed, string? iconExpanded)
	{
		Header = header;
		IconCollapsed = iconCollapsed;
		IconExpanded = iconExpanded;
	}
	public TreeViewNode(string header, string? icon, params IEnumerable<TreeViewNode> children) : this(header, icon, icon, children)
	{
	}
	public TreeViewNode(string header, string? iconCollapsed, string? iconExpanded, params IEnumerable<TreeViewNode> children) : this(header, iconCollapsed, iconExpanded)
	{
		Children = new(children);
		IsExpanded = Children.Any();
	}
}