#include "r77.h"

void Debug::Message(LPCWSTR title, LPCWSTR str)
{
	MessageBoxW(NULL, str, title, MB_OK);
}
void Debug::Message(LPCWSTR title, const UNICODE_STRING &str)
{
	PWCHAR chars = NULL;

	if (str.Buffer)
	{
		chars = new WCHAR[str.Length + 1];
		wmemcpy(chars, str.Buffer, str.Length);
		chars[str.Length] = L'\0';
	}

	Message(title, chars);
	delete[] chars;
}
void Debug::Message(LPCWSTR title, ULONG number)
{
	WCHAR hexadecimal[100];
	WCHAR decimal[100];
	_ui64tow_s(number, hexadecimal, 100, 16);
	_ui64tow_s(number, decimal, 100, 10);

	WCHAR str[100] = L"0x00000000";
	lstrcpyW(&str[10 - lstrlenW(hexadecimal)], hexadecimal);
	lstrcatW(str, L" (");
	lstrcatW(str, decimal);
	lstrcatW(str, L" )");

	Message(title, str);
}
void Debug::Message(LPCWSTR title, ULONGLONG number)
{
	WCHAR hexadecimal[100];
	WCHAR decimal[100];
	_ui64tow_s(number, hexadecimal, 100, 16);
	_ui64tow_s(number, decimal, 100, 10);

	WCHAR str[100] = L"0x0000000000000000";
	lstrcpyW(&str[18 - lstrlenW(hexadecimal)], hexadecimal);
	lstrcatW(str, L" (");
	lstrcatW(str, decimal);
	lstrcatW(str, L" )");

	Message(title, str);
}
void Debug::Log(LPCSTR path, LPCSTR text)
{
	int length = lstrlenA(text);

	HANDLE file = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD bytesWritten;
	WriteFile(file, text, length, &bytesWritten, NULL);
	CloseHandle(file);
}