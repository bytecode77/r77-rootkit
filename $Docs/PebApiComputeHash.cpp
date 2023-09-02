#include <Windows.h>

#define ROTR(value, bits) ((DWORD)(value) >> (bits) | (DWORD)(value) << (32 - (bits)))

DWORD ComputeFunctionHash(LPCSTR str)
{
	DWORD hash = 0;

	while (*str)
	{
		hash = ROTR(hash, 13) + *str++;
	}

	return hash;
}

DWORD ComputeModuleNameHash(LPCSTR str, USHORT length)
{
	DWORD hash = 0;

	for (USHORT i = 0; i < length; i++)
	{
		hash = ROTR(hash, 13) + (str[i] >= 'a' ? str[i] - 0x20 : str[i]);
	}

	return hash;
}

int main(int argc, char *argv[])
{
	LPCWSTR moduleName = L"kernel32.dll";
	LPCSTR functionName = "CreateProcessW";
	DWORD moduleHash = ComputeModuleNameHash((LPCSTR)moduleName, lstrlenW(moduleName) * 2);
	DWORD functionHash = ComputeFunctionHash(functionName);
	return 0;
}