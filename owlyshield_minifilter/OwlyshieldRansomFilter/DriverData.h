#pragma once

#include <fltKernel.h>

#include "HashTable.h"
#include "KernelCommon.h"
#include "KernelString.h"

/* DriverData: shared class across driver, hold driver D.S. */
class DriverData
{
    BOOLEAN FilterRun; // true if filter currently runs
    PFLT_FILTER Filter;
    PDRIVER_OBJECT DriverObject;                // internal
    WCHAR systemRootPath[MAX_FILE_NAME_LENGTH]; // system root path, help analyze image files loaded
    ULONG
    pid; // pid of the current connected user mode application, set by communication

    ULONG irpOpsSize;      // number of irp ops waiting in entry_list
    LIST_ENTRY irpOps;     // list entry bidirectional list of irp ops
    KSPIN_LOCK irpOpsLock; // lock for irp list ops

    ULONG directoryRootsSize;       // number of protected dirs in list
    LIST_ENTRY rootDirectories;     // list entry bdirectional of protected dirs
    KSPIN_LOCK directoriesSpinLock; // lock for directory list

    /* GID system data members */
    ULONGLONG
    GidCounter;          // internal counter for gid, every new application receives a new gid
    HashMap GidToPids;   // mapping from gid to pids
    HashMap PidToGids;   // mapping from pid to gid
    ULONGLONG gidsSize;  // number of gids currently active
    LIST_ENTRY GidsList; // list entry of gids, used to clear memory
    KSPIN_LOCK GIDSystemLock;

  private:
    // call assumes protected code - high IRQL
    BOOLEAN RemoveProcessRecordAux(ULONG ProcessId, ULONGLONG gid);

    // call assumes protected code - high IRQL
    BOOLEAN RemoveGidRecordAux(PGID_ENTRY gidRecord);

  public:
    // c'tor init D.S.
    explicit DriverData(PDRIVER_OBJECT DriverObject);

    ~DriverData();

    PWCHAR GetSystemRootPath()
    {
        return systemRootPath;
    }

    // sets the system root path, received from user mode application, we copy the systemRootPath sent on the message
    VOID setSystemRootPath(PWCHAR setsystemRootPath)
    {
        RtlZeroBytes(systemRootPath, MAX_FILE_NAME_SIZE);
        RtlCopyBytes(systemRootPath, setsystemRootPath, MAX_FILE_NAME_LENGTH);
        RtlCopyBytes(systemRootPath + wcsnlen(systemRootPath, MAX_FILE_NAME_LENGTH / 2), L"\\Windows",
                     wcsnlen(L"\\Windows", MAX_FILE_NAME_LENGTH / 2));
        DbgPrint("Set system root path %ls\n", systemRootPath);
    }

    // remove a process which ended from the GID system, function raise IRQL
    BOOLEAN RemoveProcess(ULONG ProcessId);

    // record a process which was created to the GID system, function raise IRQL
    _IRQL_raises_(DISPATCH_LEVEL) BOOLEAN
        RecordNewProcess(PUNICODE_STRING ProcessName, ULONG ProcessId, ULONG ParentPid);

    // removed a gid from the system, function raise IRQL
    BOOLEAN RemoveGid(ULONGLONG gid);

    // gets the number of processes in a gid, function raise IRQL
    ULONGLONG GetGidSize(ULONGLONG gid, PBOOLEAN found);

    // help function, receives a buffer and returns an array of pids, returns true only if all pids are restored
    BOOLEAN GetGidPids(ULONGLONG gid, PULONG buffer, ULONGLONG bufferSize, PULONGLONG returnedLength);

    // if found return true on found else return false
    ULONGLONG GetProcessGid(ULONG ProcessId, PBOOLEAN found);

    // clear all data related to Gid system
    VOID ClearGidsPids();

    ULONGLONG GidsSize();

    BOOLEAN setFilterStart()
    {
        return (FilterRun = TRUE);
    }

    BOOLEAN setFilterStop()
    {
        return (FilterRun = FALSE);
    }

    BOOLEAN isFilterClosed()
    {
        return !FilterRun;
    }

    PFLT_FILTER *getFilterAdd()
    {
        return &Filter;
    }

    PFLT_FILTER getFilter()
    {
        return Filter;
    }

    ULONG getPID()
    {
        return pid;
    }

    ULONG setPID(ULONG Pid)
    {
        pid = Pid;
        return Pid;
    }

    // clears all irps waiting to report, function raise IRQL
    VOID ClearIrps();

    ULONG IrpSize();

    BOOLEAN AddIrpMessage(PIRP_ENTRY newEntry);

    BOOLEAN RemIrpMessage(PIRP_ENTRY newEntry);

    PIRP_ENTRY GetFirstIrpMessage();

    // Takes Irps from the driverData and copy them to a buffer, also copies the file names on which the irp occured,
    // function raise IRQL
    VOID DriverGetIrps(PVOID Buffer, ULONG BufferSize, PULONG ReturnOutputBufferLength);

    LIST_ENTRY GetAllEntries();

    BOOLEAN AddDirectoryEntry(PDIRECTORY_ENTRY newEntry);

    PDIRECTORY_ENTRY RemDirectoryEntry(LPCWSTR directory);

    /**
        IsContainingDirectory returns true if one of the directory entries in our LIST_ENTRY of PDIRECTORY_ENTRY is in
       the path passed as param
    */
    BOOLEAN IsContainingDirectory(CONST PUNICODE_STRING path);

    VOID ClearDirectories();

    VOID Clear()
    {
        // clear directories
        ClearDirectories();

        // clear irps
        ClearIrps();

        // clear gid system
        ClearGidsPids();
    }
};

extern DriverData *driverData;