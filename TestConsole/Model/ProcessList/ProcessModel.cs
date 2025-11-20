using BytecodeApi.Data;
using BytecodeApi.IO;
using System.Diagnostics.CodeAnalysis;
using System.Drawing;

namespace TestConsole.Model;

public sealed class ProcessModel : ObservableObject, IEquatable<ProcessModel>
{
	private int _Id;
	private string _Name = "";
	private bool? _Is64Bit;
	private ProcessIntegrityLevel? _IntegrityLevel;
	private string _User = "";
	private Icon? _Icon;
	private bool _CanInject;
	private bool _IsInjected;
	private bool _IsR77Service;
	private bool _IsHelper;
	private bool _IsHiddenById;
	private ProcessStatus _Status = ProcessStatus.Running;
	/// <summary>
	/// The process ID.
	/// </summary>
	public int Id
	{
		get => _Id;
		set => Set(ref _Id, value);
	}
	/// <summary>
	/// The name of the process.
	/// </summary>
	public string Name
	{
		get => _Name;
		set => Set(ref _Name, value);
	}
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the process is 64-bit or 32-bit.
	/// If this value is <see langword="null" />, the bitness could not be determined.
	/// </summary>
	public bool? Is64Bit
	{
		get => _Is64Bit;
		set => Set(ref _Is64Bit, value);
	}
	/// <summary>
	/// The integrity level of the process.
	/// If this value is <see langword="null" />, the integrity level could not be determined.
	/// </summary>
	public ProcessIntegrityLevel? IntegrityLevel
	{
		get => _IntegrityLevel;
		set => Set(ref _IntegrityLevel, value);
	}
	/// <summary>
	/// The username of the process.
	/// If this value is <see langword="null" />, the username could not be determined.
	/// </summary>
	public string User
	{
		get => _User;
		set => Set(ref _User, value);
	}
	/// <summary>
	/// The icon of the executable file.
	/// </summary>
	public Icon? Icon
	{
		get => _Icon;
		set => Set(ref _Icon, value);
	}
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the process can be injected.
	/// </summary>
	public bool CanInject
	{
		get => _CanInject;
		set => Set(ref _CanInject, value);
	}
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the process is injected.
	/// </summary>
	public bool IsInjected
	{
		get => _IsInjected;
		set => Set(ref _IsInjected, value);
	}
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the process is the r77 service process.
	/// </summary>
	public bool IsR77Service
	{
		get => _IsR77Service;
		set => Set(ref _IsR77Service, value);
	}
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the process is an r77 helper process.
	/// </summary>
	public bool IsHelper
	{
		get => _IsHelper;
		set => Set(ref _IsHelper, value);
	}
	/// <summary>
	/// A <see cref="bool" /> value, indicating whether the process is hidden by ID.
	/// </summary>
	public bool IsHiddenById
	{
		get => _IsHiddenById;
		set => Set(ref _IsHiddenById, value);
	}
	/// <summary>
	/// A <see cref="ProcessStatus" /> value, indicating whether the process is recently created, or recently terminated.
	/// </summary>
	public ProcessStatus Status
	{
		get => _Status;
		set => Set(ref _Status, value);
	}
	public string SortKey => $"{Name}_{Id}";

	/// <summary>
	/// Initializes a new instance of the <see cref="ProcessModel" /> class.
	/// </summary>
	public ProcessModel()
	{
	}
	/// <summary>
	/// Initializes a new instance of the <see cref="ProcessModel" /> class, and copies all properties from <paramref name="process" />.
	/// </summary>
	/// <param name="process">The <see cref="ProcessModel" /> to copy.</param>
	public ProcessModel(ProcessModel process) : this()
	{
		Id = process.Id;
		Name = process.Name;
		Is64Bit = process.Is64Bit;
		IntegrityLevel = process.IntegrityLevel;
		User = process.User;
		Icon = process.Icon;
		CanInject = process.CanInject;
		IsInjected = process.IsInjected;
		IsR77Service = process.IsR77Service;
		IsHelper = process.IsHelper;
		IsHiddenById = process.IsHiddenById;
		Status = process.Status;
	}

	public override bool Equals([NotNullWhen(true)] object? obj)
	{
		return obj is ProcessModel process && Equals(process);
	}
	public bool Equals([NotNullWhen(true)] ProcessModel? other)
	{
		return
			other != null &&
			Id == other.Id &&
			Name == other.Name &&
			Is64Bit == other.Is64Bit &&
			IntegrityLevel == other.IntegrityLevel &&
			User == other.User &&
			CanInject == other.CanInject &&
			IsInjected == other.IsInjected &&
			IsR77Service == other.IsR77Service &&
			IsHelper == other.IsHelper &&
			IsHiddenById == other.IsHiddenById &&
			Status == other.Status;
	}
	public override int GetHashCode()
	{
		return HashCode.Combine(Id, Name, Is64Bit, IntegrityLevel, User, CanInject, IsInjected, HashCode.Combine(IsR77Service, IsHelper, IsHiddenById, Status));
	}
}