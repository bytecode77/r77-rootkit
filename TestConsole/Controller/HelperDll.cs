using BytecodeApi.IO;
using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace TestConsole
{
	/// <summary>
	/// Class that wraps Helper32.dll and Helper64.dll.
	/// <para>These native DLL's support the TestConsole by providing functionality from the r77api.</para>
	/// </summary>
	public static class HelperDll
	{
		/// <summary>
		/// Gets a list of all processes.
		/// </summary>
		/// <returns>
		/// A new <see cref="ProcessListEntry" />[] with all running processes, or <see langword="null" />, if this function failed.
		/// </returns>
		public static ProcessListEntry[] GetProcessList()
		{
			ProcessListEntry[] entries = new ProcessListEntry[1000];
			int count;

			bool result = IntPtr.Size == 4
				? Helper32Dll.GetProcessList(entries, out count)
				: Helper64Dll.GetProcessList(entries, out count);

			return result ? entries.Take(count).ToArray() : null;
		}
		/// <summary>
		/// Creates the registry key HKLM\SOFTWARE\$77config, if it does not exist.
		/// </summary>
		/// <returns>
		/// <see langword="true" />, if creation succeeded;
		/// <see langword="false" />, if creation failed.
		/// </returns>
		public static bool CreateConfigSystem()
		{
			return IntPtr.Size == 4
				? Helper32Dll.CreateConfigSystem()
				: Helper64Dll.CreateConfigSystem();
		}
		/// <summary>
		/// Injects r77 into a specific process.
		/// </summary>
		/// <param name="processId">The process ID to inject.</param>
		/// <param name="dll">The r77 DLL file. The bitness of the DLL must match the bitness of the injected process.</param>
		/// <returns>
		/// <see langword="true" />, if injection succeeded;
		/// <see langword="false" />, if injection failed.
		/// </returns>
		public static bool Inject(int processId, byte[] dll)
		{
			return IntPtr.Size == 4
				? Helper32Dll.Inject(processId, dll, dll.Length)
				: Helper64Dll.Inject(processId, dll, dll.Length);
		}
		/// <summary>
		/// Injects all processes with the r77 DLL.
		/// </summary>
		/// <param name="dll32">The r77-x86.dll file.</param>
		/// <param name="dll64">The r77-x64.dll file.</param>
		/// <returns>
		/// <see langword="true" />, if injection succeeded;
		/// <see langword="false" />, if injection failed.
		/// </returns>
		public static bool InjectAll(byte[] dll32, byte[] dll64)
		{
			return IntPtr.Size == 4
				? Helper32Dll.InjectAll(dll32, dll32.Length, dll64, dll64.Length)
				: Helper64Dll.InjectAll(dll32, dll32.Length, dll64, dll64.Length);
		}
		/// <summary>
		/// Detaches r77 from the specific process.
		/// </summary>
		/// <param name="processId">The process ID to detach r77 from.</param>
		/// <returns>
		/// <see langword="true" />, if detaching succeeded;
		/// <see langword="false" />, if detaching failed.
		/// </returns>
		public static bool Detach(int processId)
		{
			return IntPtr.Size == 4
				? Helper32Dll.Detach(processId)
				: Helper64Dll.Detach(processId);
		}
		/// <summary>
		/// Detaches r77 from all running processes.
		/// </summary>
		/// <returns>
		/// <see langword="true" />, if detaching succeeded;
		/// <see langword="false" />, if detaching failed.
		/// </returns>
		public static bool DetachAll()
		{
			return IntPtr.Size == 4
				? Helper32Dll.DetachAll()
				: Helper64Dll.DetachAll();
		}

		private static class Helper32Dll
		{
			[DllImport("Helper32.dll")]
			public static extern bool GetProcessList([Out] ProcessListEntry[] entries, out int count);
			[DllImport("Helper32.dll")]
			public static extern bool CreateConfigSystem();
			[DllImport("Helper32.dll")]
			public static extern bool Inject(int processId, byte[] dll, int dllSize);
			[DllImport("Helper32.dll")]
			public static extern bool InjectAll(byte[] dll32, int dll32Size, byte[] dll64, int dll64Size);
			[DllImport("Helper32.dll")]
			public static extern bool Detach(int processId);
			[DllImport("Helper32.dll")]
			public static extern bool DetachAll();
		}
		private static class Helper64Dll
		{
			[DllImport("Helper64.dll")]
			public static extern bool GetProcessList([Out] ProcessListEntry[] entries, out int count);
			[DllImport("Helper64.dll")]
			public static extern bool CreateConfigSystem();
			[DllImport("Helper64.dll")]
			public static extern bool Inject(int processId, byte[] dll, int dllSize);
			[DllImport("Helper64.dll")]
			public static extern bool InjectAll(byte[] dll32, int dll32Size, byte[] dll64, int dll64Size);
			[DllImport("Helper64.dll")]
			public static extern bool Detach(int processId);
			[DllImport("Helper64.dll")]
			public static extern bool DetachAll();
		}

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		public struct ProcessListEntry
		{
			public int ProcessId;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
			public string Name;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
			public string FullName;
			public int Platform;
			public ProcessIntegrityLevel IntegrityLevel;
			[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
			public string UserName;
			public bool IsInjected;
			public bool IsR77Service;
			public bool IsHelper;
			public bool IsHiddenById;
		}
	}
}