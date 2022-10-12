#include "r77mindef.h"
#ifndef _CLIST_H
#define _CLIST_H

/// <summary>
/// Defines a collection of ULONG values.
/// </summary>
typedef struct _INTEGER_LIST
{
	/// <summary>
	/// The number of ULONG values in this list.
	/// </summary>
	DWORD Count;
	/// <summary>
	/// The currently allocated capacity of the buffer. The buffer expands automatically when values are added.
	/// </summary>
	DWORD Capacity;
	/// <summary>
	/// A buffer that stores the ULONG values in this list.
	/// </summary>
	PULONG Values;
} INTEGER_LIST, *PINTEGER_LIST;

/// <summary>
/// Defines a collection of strings.
/// </summary>
typedef struct _STRING_LIST
{
	/// <summary>
	/// The number of strings in this list.
	/// </summary>
	DWORD Count;
	/// <summary>
	/// The currently allocated capacity of the buffer. The buffer expands automatically when values are added.
	/// </summary>
	DWORD Capacity;
	/// <summary>
	/// TRUE to treat strings as case insensitive.
	/// </summary>
	BOOL IgnoreCase;
	/// <summary>
	/// A buffer that stores the strings in this list.
	/// </summary>
	LPWSTR *Values;
} STRING_LIST, *PSTRING_LIST;

/// <summary>
/// Creates a new INTEGER_LIST.
/// </summary>
/// <returns>
/// A pointer to the newly created INTEGER_LIST structure.
/// </returns>
PINTEGER_LIST CreateIntegerList();
/// <summary>
/// Loads DWORD values from the specified registry key into the specified INTEGER_LIST structure.
/// <para>Values that are already in the list are not added.</para>
/// </summary>
/// <param name="list">The INTEGER_LIST structure to add the values to.</param>
/// <param name="key">The registry key to read DWORD values from.</param>
VOID LoadIntegerListFromRegistryKey(PINTEGER_LIST list, HKEY key);
/// <summary>
/// Deletes the specified INTEGER_LIST structure.
/// </summary>
/// <param name="list">The INTEGER_LIST structure to delete.</param>
VOID DeleteIntegerList(PINTEGER_LIST list);
/// <summary>
/// Adds a ULONG value to the specified INTEGER_LIST.
/// </summary>
/// <param name="list">The INTEGER_LIST structure to add the ULONG value to.</param>
/// <param name="value">The ULONG value to add to the list.</param>
VOID IntegerListAdd(PINTEGER_LIST list, ULONG value);
/// <summary>
/// Determines whether the ULONG value is in the specified INTEGER_LIST.
/// </summary>
/// <param name="list">The INTEGER_LIST structure to search.</param>
/// <param name="value">The ULONG value to check.</param>
/// <returns>
/// TRUE, if the specified ULONG value is in the specified INTEGER_LIST;
/// otherwise, FALSE.
/// </returns>
BOOL IntegerListContains(PINTEGER_LIST list, ULONG value);
/// <summary>
/// Compares two INTEGER_LIST structures for equality.
/// </summary>
/// <param name="listA">The first INTEGER_LIST structure.</param>
/// <param name="listB">The second INTEGER_LIST structure.</param>
/// <returns>
/// TRUE, if both INTEGER_LIST structures are equal;
/// otherwise, FALSE.
/// </returns>
BOOL CompareIntegerList(PINTEGER_LIST listA, PINTEGER_LIST listB);

/// <summary>
/// Creates a new STRING_LIST.
/// </summary>
/// <param name="ignoreCase">TRUE to treat strings as case insensitive.</param>
/// <returns>
/// A pointer to the newly created STRING_LIST structure.
/// </returns>
PSTRING_LIST CreateStringList(BOOL ignoreCase);
/// <summary>
/// Loads REG_SZ values from the specified registry key into the specified STRING_LIST structure.
/// <para>Strings that are already in the list are not added.</para>
/// </summary>
/// <param name="list">The STRING_LIST structure to add the strings to.</param>
/// <param name="key">The registry key to read REG_SZ values from.</param>
/// <param name="maxStringLength">The maximum length of REG_SZ values that are read from the registry key.</param>
VOID LoadStringListFromRegistryKey(PSTRING_LIST list, HKEY key, DWORD maxStringLength);
/// <summary>
/// Deletes the specified STRING_LIST structure.
/// </summary>
/// <param name="list">The STRING_LIST structure to delete.</param>
VOID DeleteStringList(PSTRING_LIST list);
/// <summary>
/// Adds a string to the specified STRING_LIST.
/// </summary>
/// <param name="list">The STRING_LIST structure to add the string to.</param>
/// <param name="value">The string to add to the list.</param>
VOID StringListAdd(PSTRING_LIST list, LPCWSTR value);
/// <summary>
/// Determines whether the string is in the specified STRING_LIST.
/// </summary>
/// <param name="list">The STRING_LIST structure to search.</param>
/// <param name="value">The string to check.</param>
/// <returns>
/// TRUE, if the specified string is in the specified STRING_LIST;
/// otherwise, FALSE.
/// </returns>
BOOL StringListContains(PSTRING_LIST list, LPCWSTR value);
/// <summary>
/// Compares two STRING_LIST structures for equality.
/// </summary>
/// <param name="listA">The first STRING_LIST structure.</param>
/// <param name="listB">The second STRING_LIST structure.</param>
/// <returns>
/// TRUE, if both STRING_LIST structures are equal;
/// otherwise, FALSE.
/// </returns>
BOOL CompareStringList(PSTRING_LIST listA, PSTRING_LIST listB);

#endif