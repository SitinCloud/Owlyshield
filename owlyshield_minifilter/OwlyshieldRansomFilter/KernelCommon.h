#pragma once

#include <fltKernel.h>

#include "../SharedDefs/SharedDefs.h"

// #define DEBUG_IRP
#ifdef DEBUG_IRP
#define IS_DEBUG_IRP 1
#else
#define IS_DEBUG_IRP 0
#endif // DEBUG_IRP

#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64 // Non paged pool NX

// PID_ENTRY - for each process in the system we record, we get its pid and image file, those are stored in thi struct
// the struct is meant to be used in blist (LIST_ENTRY)
typedef struct _PID_ENTRY
{
    LIST_ENTRY entry;
    PUNICODE_STRING Path;
    ULONG Pid;

    _PID_ENTRY()
    {
        Pid = 0;
        Path = nullptr;
        entry.Flink = nullptr;
        entry.Blink = nullptr;
    }

    void *operator new(size_t size)
    {
        void *ptr = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'RW');
        if (size && ptr != nullptr)
            memset(ptr, 0, size);
        return ptr;
    }

    void operator delete(void *ptr)
    {
        ExFreePoolWithTag(ptr, 'RW');
    }

    // fixme needs new and delete operator, dtor
} PID_ENTRY, *PPID_ENTRY;

typedef struct _DIRECTORY_ENTRY
{
    LIST_ENTRY entry;
    WCHAR path[MAX_FILE_NAME_LENGTH];

    _DIRECTORY_ENTRY()
    {
        InitializeListHead(&entry);
        path[0] = L'\0';
    }

} DIRECTORY_ENTRY, *PDIRECTORY_ENTRY;

typedef struct _IRP_ENTRY
{
    LIST_ENTRY entry;
    DRIVER_MESSAGE data;
    UNICODE_STRING
    filePath;                           // keep path to unicode string related to the object, we copy it later to user
    WCHAR Buffer[MAX_FILE_NAME_LENGTH]; // unicode string buffer for file name

    _IRP_ENTRY()
    {
        filePath.Length = 0;
        filePath.MaximumLength = MAX_FILE_NAME_SIZE;
        filePath.Buffer = Buffer;
        RtlZeroBytes(Buffer, MAX_FILE_NAME_SIZE);
        data.next = nullptr;
        data.IRP_OP = IRP_NONE;
        data.MemSizeUsed = 0;
        data.isEntropyCalc = FALSE;
        data.FileChange = FILE_CHANGE_NOT_SET;
        data.FileLocationInfo = FILE_NOT_PROTECTED;
    }

    void *operator new(size_t size)
    {
        void *ptr = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'RW');
        if (size && ptr != nullptr)
            memset(ptr, 0, size);
        return ptr;
    }

    void operator delete(void *ptr)
    {
        ExFreePoolWithTag(ptr, 'RW');
    }

} IRP_ENTRY, *PIRP_ENTRY;

void *__cdecl operator new(size_t size);

void __cdecl operator delete(void *data, size_t size);

void __cdecl operator delete(void *data);

NTSTATUS CopyWString(LPWSTR dest, LPCWSTR source, size_t size);

WCHAR *stristr(const WCHAR *String, const WCHAR *Pattern);

BOOLEAN startsWith(PUNICODE_STRING String, PWCHAR Pattern);

// GID_ENTRY - for each gid in the system we record, holds pids entries (PID_ENTRY)
// the struct is meant to be used in blist (LIST_ENTRY)
struct GID_ENTRY
{
    LIST_ENTRY GidListEntry;
    ULONGLONG gid;
    ULONGLONG pidsSize;
    LIST_ENTRY HeadListPids;

    // gid as input
    GID_ENTRY(ULONGLONG Gid)
    {
        gid = Gid;
        InitializeListHead(&HeadListPids);
        InitializeListHead(&GidListEntry);
        pidsSize = 0;
    }

    // copy
    GID_ENTRY(const GID_ENTRY &a)
    {
        HeadListPids.Flink = a.HeadListPids.Flink;
        HeadListPids.Blink = a.HeadListPids.Blink;
        GidListEntry.Flink = a.GidListEntry.Flink;
        GidListEntry.Blink = a.GidListEntry.Blink;
        gid = a.gid;
        pidsSize = a.pidsSize;
    }

    const GID_ENTRY &operator=(const GID_ENTRY &a)
    {
        HeadListPids.Flink = a.HeadListPids.Flink;
        HeadListPids.Blink = a.HeadListPids.Blink;
        GidListEntry.Flink = a.GidListEntry.Flink;
        GidListEntry.Blink = a.GidListEntry.Blink;
        gid = a.gid;
        pidsSize = a.pidsSize;
        this;
    }
};

typedef GID_ENTRY *PGID_ENTRY;