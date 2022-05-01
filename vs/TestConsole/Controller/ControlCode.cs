using System.ComponentModel;

namespace TestConsole
{
	/// <summary>
	/// Defines a control code for the r77 control pipe.
	/// </summary>
	public enum ControlCode
	{
		/// <summary>
		/// The control code that terminates the r77 service.
		/// </summary>
		[Description("CONTROL_R77_TERMINATE_SERVICE")]
		R77TerminateService = 0x1001,
		/// <summary>
		/// The control code that uninstalls r77.
		/// </summary>
		[Description("CONTROL_R77_UNINSTALL")]
		R77Uninstall = 0x1002,
		/// <summary>
		/// The control code that temporarily pauses injection of new processes.
		/// </summary>
		[Description("CONTROL_R77_PAUSE_INJECTION")]
		R77PauseInjection = 0x1003,
		/// <summary>
		/// The control code that resumes injection of new processes.
		/// </summary>
		[Description("CONTROL_R77_RESUME_INJECTION")]
		R77ResumeInjection = 0x1004,
		/// <summary>
		/// The control code that injects r77 into a specific process, if it is not yet injected.
		/// </summary>
		[Description("CONTROL_PROCESSES_INJECT")]
		ProcessesInject = 0x2001,
		/// <summary>
		/// The control code that injects r77 into all processes that are not yet injected.
		/// </summary>
		[Description("CONTROL_PROCESSES_INJECT_ALL")]
		ProcessesInjectAll = 0x2002,
		/// <summary>
		/// The control code that detaches r77 from a specific process.
		/// </summary>
		[Description("CONTROL_PROCESSES_DETACH")]
		ProcessesDetach = 0x2003,
		/// <summary>
		/// The control code that detaches r77 from all processes.
		/// </summary>
		[Description("CONTROL_PROCESSES_DETACH_ALL")]
		ProcessesDetachAll = 0x2004,
		/// <summary>
		/// The control code that executes a file using ShellExecute.
		/// </summary>
		[Description("CONTROL_USER_SHELLEXEC")]
		UserShellExec = 0x3001,
		/// <summary>
		/// The control code that executes an executable using process hollowing.
		/// </summary>
		[Description("CONTROL_USER_RUNPE")]
		UserRunPE = 0x3002,
		/// <summary>
		/// The control code that triggers a BSOD.
		/// </summary>
		[Description("CONTROL_SYSTEM_BSOD")]
		SystemBsod = 0x4001
	}
}