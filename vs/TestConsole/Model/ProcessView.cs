using BytecodeApi;
using BytecodeApi.Extensions;
using BytecodeApi.IO;
using BytecodeApi.IO.FileSystem;
using BytecodeApi.UI.Data;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;

namespace TestConsole
{
	/// <summary>
	/// Process object that contains information about a process and r77 specific properties.
	/// </summary>
	public sealed class ProcessView : ObservableObject, IEquatable<ProcessView>
	{
		private static readonly Icon DefaultIcon = FileEx.GetIcon(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe"), false);
		private static readonly Dictionary<string, Icon> IconCache = new Dictionary<string, Icon>();

		/// <summary>
		/// The process ID.
		/// </summary>
		public int Id
		{
			get => Get(() => Id);
			set => Set(() => Id, value);
		}
		/// <summary>
		/// The name of the process.
		/// </summary>
		public string Name
		{
			get => Get(() => Name);
			set => Set(() => Name, value);
		}
		/// <summary>
		/// A <see cref="bool" /> value, indicating whether the process is 64-bit or 32-bit.
		/// If this value is <see langword="null" />, the bitness could not be determined.
		/// </summary>
		public bool? Is64Bit
		{
			get => Get(() => Is64Bit);
			set => Set(() => Is64Bit, value);
		}
		/// <summary>
		/// The integrity level of the process.
		/// If this value is <see langword="null" />, the integrity level could not be determined.
		/// </summary>
		public ProcessIntegrityLevel? IntegrityLevel
		{
			get => Get(() => IntegrityLevel);
			set => Set(() => IntegrityLevel, value);
		}
		/// <summary>
		/// The username of the process.
		/// If this value is <see langword="null" />, the username could not be determined.
		/// </summary>
		public string User
		{
			get => Get(() => User);
			set => Set(() => User, value);
		}
		/// <summary>
		/// The icon of the executable file.
		/// </summary>
		public Icon Icon
		{
			get => Get(() => Icon);
			set => Set(() => Icon, value);
		}
		/// <summary>
		/// A <see cref="bool" /> value, indicating whether the process can be injected.
		/// </summary>
		public bool CanInject
		{
			get => Get(() => CanInject);
			set => Set(() => CanInject, value);
		}
		/// <summary>
		/// A <see cref="bool" /> value, indicating whether the process is injected.
		/// </summary>
		public bool IsInjected
		{
			get => Get(() => IsInjected);
			set => Set(() => IsInjected, value);
		}
		/// <summary>
		/// A <see cref="bool" /> value, indicating whether the process is the r77 service process.
		/// </summary>
		public bool IsR77Service
		{
			get => Get(() => IsR77Service);
			set => Set(() => IsR77Service, value);
		}
		/// <summary>
		/// A <see cref="bool" /> value, indicating whether the process is an r77 helper process.
		/// </summary>
		public bool IsHelper
		{
			get => Get(() => IsHelper);
			set => Set(() => IsHelper, value);
		}
		/// <summary>
		/// A <see cref="bool" /> value, indicating whether the process is hidden by ID.
		/// </summary>
		public bool IsHiddenById
		{
			get => Get(() => IsHiddenById);
			set => Set(() => IsHiddenById, value);
		}

		private ProcessView()
		{
		}
		/// <summary>
		/// Gets a list of all processes.
		/// <para>ProcessList32.exe and ProcessList64.exe need to be invoked to retrieve the process list, because some information can only be accessed by a process of matching bitness.</para>
		/// </summary>
		/// <returns>
		/// A new <see cref="ProcessView" />[] with all running processes.
		/// </returns>
		public static ProcessView[] GetProcesses()
		{
			// Call ProcessList32.exe and ProcessList64.exe to retrieve the process list.
			// Because the process list contains r77 specific information, the bitness of the enumerating process needs to match
			// that of the enumerated process to retrieve this information.

			string[] processListExecutables = Environment.Is64BitOperatingSystem ?
				new[] { "ProcessList32.exe", "ProcessList64.exe" } :
				new[] { "ProcessList32.exe" };

			return processListExecutables
				.Select(fileName => Path.Combine(ApplicationBase.Path, fileName))
				.Where(path => File.Exists(path))
				.Select(path => CSharp.Try(() => ProcessEx.ReadProcessOutput(path, null, false, true))) // Execute and read console output
				.ToArray()
				.Select(str => str?.SplitToLines())
				.ExceptNull()
				.SelectMany()
				.Where(line => !line.IsNullOrWhiteSpace())
				.Select(line => line.Split('|').ToArray())
				.Select(line =>
				{
					// Split console output by lines, then by '|' and parse content.
					ProcessView process = new ProcessView
					{
						Id = line[0].ToInt32OrDefault(),
						Name = line[1],
						Is64Bit = line[3] == "32" ? false : line[3] == "64" ? true : (bool?)null,
						IntegrityLevel = line[4].ToInt32OrNull() is int integrityLevel && integrityLevel != -1 ? (ProcessIntegrityLevel?)integrityLevel : null,
						User = line[5],
						Icon = GetIcon(line[1], line[2]),
						IsInjected = line[6] == "1",
						IsR77Service = line[7] == "1",
						IsHelper = line[8] == "1",
						IsHiddenById = line[9] == "1"
					};

					process.CanInject =
						process.Is64Bit != null &&
						process.IntegrityLevel != null &&
						(ApplicationBase.Process.IsElevated || process.IntegrityLevel <= ProcessIntegrityLevel.Medium);

					return process;
				})
				.Where(process => CSharp.EqualsNone(process.Id, 0, 4)) // Exclude "System" and "System Idle Process"
				.GroupBy(process => process.Id)
				.Where(group => group.Count() == processListExecutables.Length)
				.Select(group => group.OrderByDescending(p => p.IsInjected || p.IsR77Service || p.IsHelper).First())
				.OrderBy(process => process.Name, StringComparer.OrdinalIgnoreCase)
				.ThenBy(process => process.Id)
				.ToArray();

			Icon GetIcon(string fileName, string fullPath)
			{
				// If the full path is unknown, attempt to find the file in C:\Windows and C:\Windows\System32
				if (fullPath.IsNullOrEmpty())
				{
					fullPath = new[]
					{
						Environment.SpecialFolder.System,
						Environment.SpecialFolder.Windows
					}
					.Select(folder => Path.Combine(Environment.GetFolderPath(folder), fileName))
					.FirstOrDefault(newPath => File.Exists(newPath));
				}

				if (fullPath.IsNullOrEmpty())
				{
					// Display the default executable icon
					return DefaultIcon;
				}
				else
				{
					// Once an icon was found, keep the icon in the cache
					if (IconCache.ValueOrDefault(fullPath.ToLower()) is Icon cachedIcon)
					{
						return cachedIcon;
					}
					else
					{
						if (FileEx.GetIcon(fullPath, false) is Icon icon)
						{
							IconCache[fullPath.ToLower()] = icon;
							return icon;
						}
						else
						{
							return DefaultIcon;
						}
					}
				}
			}
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