#include "clist.h"
#include <Shlwapi.h>

PINTEGER_LIST CreateIntegerList()
{
	PINTEGER_LIST list = NEW(INTEGER_LIST);
	list->Count = 0;
	list->Capacity = 16;
	list->Values = NEW_ARRAY(ULONG, list->Capacity);
	return list;
}
VOID LoadIntegerListFromRegistryKey(PINTEGER_LIST list, HKEY key)
{
	DWORD count;
	if (RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL, &count, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		WCHAR valueName[100];

		for (DWORD i = 0; i < count; i++)
		{
			DWORD valueNameLength = 100;
			DWORD type;
			DWORD value;
			DWORD valueSize = sizeof(DWORD);

			if (RegEnumValueW(key, i, valueName, &valueNameLength, NULL, &type, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS && type == REG_DWORD && !IntegerListContains(list, value))
			{
				IntegerListAdd(list, value);
			}
		}
	}
}
VOID DeleteIntegerList(PINTEGER_LIST list)
{
	FREE(list->Values);
	i_memset(list, 0, sizeof(INTEGER_LIST));
	FREE(list);
}
VOID IntegerListAdd(PINTEGER_LIST list, ULONG value)
{
	if (list->Count == list->Capacity)
	{
		list->Capacity += 16;
		PULONG newValues = NEW_ARRAY(ULONG, list->Capacity);
		i_memcpy(newValues, list->Values, list->Count * sizeof(ULONG));

		PULONG oldValues = list->Values;
		list->Values = newValues;
		FREE(oldValues);
	}

	list->Values[list->Count++] = value;
}
BOOL IntegerListContains(PINTEGER_LIST list, ULONG value)
{
	for (DWORD i = 0; i < list->Count; i++)
	{
		if (list->Values[i] == value) return TRUE;
	}

	return FALSE;
}
BOOL CompareIntegerList(PINTEGER_LIST listA, PINTEGER_LIST listB)
{
	if (listA == listB)
	{
		return TRUE;
	}
	else if (listA == NULL || listB == NULL)
	{
		return FALSE;
	}
	else if (listA->Count != listB->Count)
	{
		return FALSE;
	}
	else
	{
		for (ULONG i = 0; i < listA->Count; i++)
		{
			if (listA->Values[i] != listB->Values[i]) return FALSE;
		}

		return TRUE;
	}
}

PSTRING_LIST CreateStringList(BOOL ignoreCase)
{
	PSTRING_LIST list = NEW(STRING_LIST);
	list->Count = 0;
	list->Capacity = 16;
	list->IgnoreCase = ignoreCase;
	list->Values = NEW_ARRAY(LPWSTR, list->Capacity);
	return list;
}
VOID LoadStringListFromRegistryKey(PSTRING_LIST list, HKEY key, DWORD maxStringLength)
{
	DWORD count;
	if (RegQueryInfoKeyW(key, NULL, NULL, NULL, NULL, NULL, NULL, &count, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
	{
		WCHAR valueName[100];
		PWCHAR value = NEW_ARRAY(WCHAR, maxStringLength + 1);

		for (DWORD i = 0; i < count; i++)
		{
			DWORD valueNameLength = 100;
			DWORD type;
			DWORD valueSize = maxStringLength;

			if (RegEnumValueW(key, i, valueName, &valueNameLength, NULL, &type, (LPBYTE)value, &valueSize) == ERROR_SUCCESS && type == REG_SZ && !StringListContains(list, value))
			{
				StringListAdd(list, value);
			}
		}

		FREE(value);
	}
}
VOID DeleteStringList(PSTRING_LIST list)
{
	for (ULONG i = 0; i < list->Count; i++)
	{
		FREE(list->Values[i]);
	}

	FREE(list->Values);
	i_memset(list, 0, sizeof(STRING_LIST));
	FREE(list);
}
VOID StringListAdd(PSTRING_LIST list, LPCWSTR value)
{
	if (value)
	{
		if (list->Count == list->Capacity)
		{
			list->Capacity += 16;
			LPWSTR *newValues = NEW_ARRAY(LPWSTR, list->Capacity);
			i_memcpy(newValues, list->Values, list->Count * sizeof(LPWSTR));

			LPWSTR *oldValues = list->Values;
			list->Values = newValues;
			FREE(oldValues);
		}

		list->Values[list->Count] = NEW_ARRAY(WCHAR, lstrlenW(value) + 1);
		StrCpyW(list->Values[list->Count++], value);
	}
}
BOOL StringListContains(PSTRING_LIST list, LPCWSTR value)
{
	if (value)
	{
		for (DWORD i = 0; i < list->Count; i++)
		{
			if (list->IgnoreCase ? !StrCmpIW(list->Values[i], value) : !StrCmpW(list->Values[i], value)) return TRUE;
		}
	}

	return FALSE;
}
BOOL CompareStringList(PSTRING_LIST listA, PSTRING_LIST listB)
{
	if (listA == listB)
	{
		return TRUE;
	}
	else if (listA == NULL || listB == NULL)
	{
		return FALSE;
	}
	else if (listA->Count != listB->Count)
	{
		return FALSE;
	}
	else
	{
		for (ULONG i = 0; i < listA->Count; i++)
		{
			if (listA->IgnoreCase && listB->IgnoreCase ? StrCmpIW(listA->Values[i], listB->Values[i]) : StrCmpW(listA->Values[i], listB->Values[i])) return FALSE;
		}

		return TRUE;
	}
}