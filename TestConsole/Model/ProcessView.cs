using BytecodeApi;
using BytecodeApi.IO;
using BytecodeApi.UI.Data;
using System;
using System.Drawing;

namespace TestConsole
{
	/// <summary>
	/// Process object that contains information about a process and r77 specific properties.
	/// </summary>
	public sealed class ProcessView : ObservableObject, IEquatable<ProcessView>
	{
		private int _Id;
		private string _Name;
		private bool? _Is64Bit;
		private ProcessIntegrityLevel? _IntegrityLevel;
		private string _User;
		private Icon _Icon;
		private bool _CanInject;
		private bool _IsInjected;
		private bool _IsR77Service;
		private bool _IsHelper;
		private bool _IsHiddenById;
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
		public Icon Icon
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
		/// Determines whether the specified <see cref="object" /> is equal to this instance.
		/// </summary>
		/// <param name="obj">The <see cref="object" /> to compare with this instance.</param>
		/// <returns>
		/// <see langword="true" />, if the specified <see cref="object" /> is equal to this instance;
		/// otherwise, <see langword="false" />.
		/// </returns>
		public override bool Equals(object obj)
		{
			return obj is ProcessView processView && Equals(processView);
		}
		/// <summary>
		/// Determines whether this instance is equal to another <see cref="ProcessView" />.
		/// </summary>
		/// <param name="other">The <see cref="ProcessView" /> to compare to this instance.</param>
		/// <returns>
		/// <see langword="true" />, if this instance is equal to the <paramref name="other" /> parameter;
		/// otherwise, <see langword="false" />.
		/// </returns>
		public bool Equals(ProcessView other)
		{
			return
				Id == other.Id &&
				Name == other.Name &&
				Is64Bit == other.Is64Bit &&
				IntegrityLevel == other.IntegrityLevel &&
				User == other.User &&
				CanInject == other.CanInject &&
				IsInjected == other.IsInjected &&
				IsR77Service == other.IsR77Service &&
				IsHelper == other.IsHelper &&
				IsHiddenById == other.IsHiddenById;
		}
		/// <summary>
		/// Returns a hash code for this <see cref="ProcessView" />.
		/// </summary>
		/// <returns>
		/// The hash code for this <see cref="ProcessView" /> instance.
		/// </returns>
		public override int GetHashCode()
		{
			return CSharp.GetHashCode(Id, Name, Is64Bit, IntegrityLevel, User, CanInject, IsInjected, IsR77Service, IsHelper, IsHiddenById);
		}
	}
}