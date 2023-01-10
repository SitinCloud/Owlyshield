#include "KernelCommon.h"

#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64 // Non paged pool NX

void *__cdecl operator new(size_t size)
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'RW');
}

void __cdecl operator delete(void *data, size_t size)
{
    UNREFERENCED_PARAMETER(size);
    if (data != NULL)
        ExFreePoolWithTag(data, 'RW');
}

void __cdecl operator delete(void *data)
{
    if (data != NULL)
        ExFreePoolWithTag(data, 'RW');
}

// FIXME: add count param for copy length, MAX_FILE_NAME_LENGTH - 1 is default value
NTSTATUS CopyWString(LPWSTR dest, LPCWSTR source, size_t size)
{
    INT err = wcsncpy_s(dest, size, source, MAX_FILE_NAME_LENGTH - 1);
    if (err == 0)
    {
        dest[size - 1] = L'\0';
        return STATUS_SUCCESS;
    }
    else
    {
        return STATUS_INTERNAL_ERROR;
    }
}

WCHAR *stristr(const WCHAR *String, const WCHAR *Pattern)
{
    WCHAR *pptr, *sptr, *start;

    for (start = (WCHAR *)String; *start != L'\0'; ++start)
    {
        while (((*start != L'\0') && (RtlUpcaseUnicodeChar(*start) != RtlUpcaseUnicodeChar(*Pattern))))
        {
            ++start;
        }

        if (L'\0' == *start)
            return NULL;

        pptr = (WCHAR *)Pattern;
        sptr = (WCHAR *)start;

        while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*pptr))
        {
            sptr++;
            pptr++;

            if (L'\0' == *pptr)
                return (start);
        }
    }

    return NULL;
}

BOOLEAN startsWith(PUNICODE_STRING String, PWCHAR Pattern)
{
    if (String == NULL || Pattern == NULL)
        return FALSE;
    PWCHAR buffer = String->Buffer;
    for (ULONG i = 0; i < wcslen(Pattern); i++)
    {
        if (String->Length <= 2 * i)
        {
            // DbgPrint("String ended before pattern, %d\n", i);
            return FALSE;
        }
        if (RtlDowncaseUnicodeChar(Pattern[i]) != RtlDowncaseUnicodeChar(buffer[i]))
        {
            // DbgPrint("Chars not eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]),
            // RtlDowncaseUnicodeChar(buffer[i]));
            return FALSE;
        }
        // DbgPrint("Chars are eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]), RtlDowncaseUnicodeChar(buffer[i]));
    }
    return TRUE;
}