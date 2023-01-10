#include "DriverData.h"

DriverData::DriverData(PDRIVER_OBJECT DriverObject)
    : FilterRun(FALSE), Filter(nullptr), DriverObject(DriverObject), pid(0), irpOpsSize(0), directoryRootsSize(0),
      GidToPids(), PidToGids()
{
    systemRootPath[0] = L'\0';
    InitializeListHead(&irpOps);
    InitializeListHead(&rootDirectories);
    KeInitializeSpinLock(&irpOpsLock);          // init spin lock
    KeInitializeSpinLock(&directoriesSpinLock); // init spin lock

    GidCounter = 0;
    KeInitializeSpinLock(&GIDSystemLock); // init spin lock
    gidsSize = 0;
    InitializeListHead(&GidsList);
}

DriverData::~DriverData()
{
    Clear();
}

DriverData *driverData;

// #######################################################################################
// # Gid system handling
// #######################################################################################

/****************** Private ******************/

// call assumes protected code high irql
BOOLEAN DriverData::RemoveProcessRecordAux(ULONG ProcessId, ULONGLONG gid)
{
    BOOLEAN ret = FALSE;
    PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (gidRecord == nullptr)
    { // shouldn't happen
        return FALSE;
    }
    PLIST_ENTRY header = &(gidRecord->HeadListPids);
    PLIST_ENTRY iterator = header->Flink;
    while (iterator != header)
    {
        PPID_ENTRY pStrct = (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
        if (pStrct->Pid == ProcessId)
        {
            RemoveEntryList(iterator);
            delete pStrct->Path;
            delete pStrct;
            gidRecord->pidsSize--;
            ret = TRUE;
            break;
        }
        iterator = iterator->Flink;
    }
    if (ret)
    {
        if (IsListEmpty(header))
        {
            GidToPids.deleteNode(gid);                   // remove the gidRecord from GidToPids
            RemoveEntryList(&(gidRecord->GidListEntry)); // unlink from list of gids
            gidsSize--;
            delete gidRecord;
        }
        PidToGids.deleteNode(ProcessId);
    }
    return ret;
}

// call assumes protected code high irql
BOOLEAN DriverData::RemoveGidRecordAux(PGID_ENTRY gidRecord)
{
    BOOLEAN ret = FALSE;
    ASSERT(gidRecord != nullptr);
    PLIST_ENTRY headerPids = &(gidRecord->HeadListPids);
    PULONGLONG pidsSize = &(gidRecord->pidsSize);
    PLIST_ENTRY iterator = headerPids->Flink;
    while (iterator != headerPids)
    { // clear list
        PPID_ENTRY pStrct = (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
        PLIST_ENTRY next = iterator->Flink;
        RemoveEntryList(iterator);
        PidToGids.deleteNode(pStrct->Pid);
        pidsSize--;
        delete pStrct->Path; // release PUNICODE_STRING
        delete pStrct;       // release PID_ENTRY
        ret = TRUE;
        iterator = next;
    }
    ASSERT(IsListEmpty(headerPids));
    return ret;
}

/****************** Public ******************/

BOOLEAN DriverData::RemoveProcess(ULONG ProcessId)
{
    BOOLEAN ret = FALSE;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    ULONGLONG gid = (ULONGLONG)PidToGids.get(ProcessId);
    if (gid)
    { // there is Gid
        ret = RemoveProcessRecordAux(ProcessId, gid);
    }

    KeReleaseSpinLock(&GIDSystemLock, irql);
    return ret;
}

_IRQL_raises_(DISPATCH_LEVEL) BOOLEAN DriverData::RecordNewProcess(PUNICODE_STRING ProcessName, ULONG ProcessId,
                                                                   ULONG ParentPid)
{
    BOOLEAN ret = FALSE;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    ULONGLONG gid = (ULONGLONG)PidToGids.get(ParentPid);
    PPID_ENTRY pStrct = new PID_ENTRY;
    pStrct->Pid = ProcessId;
    pStrct->Path = ProcessName;
    if (gid)
    { // there is Gid
        ULONGLONG retInsert;
        if ((retInsert = (ULONGLONG)PidToGids.insertNode(ProcessId, (HANDLE)gid)) != gid)
        { // shouldn't happen
            RemoveProcessRecordAux(ProcessId, retInsert);
        }
        PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
        InsertHeadList(&(gidRecord->HeadListPids), &(pStrct->entry));
        gidRecord->pidsSize++;
        PidToGids.insertNode(ProcessId, (HANDLE)gid);
    }
    else
    {
        PGID_ENTRY newGidRecord = new GID_ENTRY(++GidCounter);
        InsertHeadList(&(newGidRecord->HeadListPids), &(pStrct->entry));
        InsertTailList(&GidsList, &(newGidRecord->GidListEntry));
        GidToPids.insertNode(GidCounter, newGidRecord);
        PidToGids.insertNode(ProcessId, (HANDLE)GidCounter);
        newGidRecord->pidsSize++;
        gidsSize++;
    }
    KeReleaseSpinLock(&GIDSystemLock, irql);
    return ret;
}

BOOLEAN DriverData::RemoveGid(ULONGLONG gid)
{
    BOOLEAN ret = FALSE;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (gidRecord)
    {                                                // there is Gid list
        RemoveGidRecordAux(gidRecord);               // clear process list
        GidToPids.deleteNode(gid);                   // remove the gidRecord from GidToPids
        RemoveEntryList(&(gidRecord->GidListEntry)); // unlink from list of gids
        gidsSize--;
        delete gidRecord;
        ret = TRUE;
    }

    KeReleaseSpinLock(&GIDSystemLock, irql);
    return ret;
}

ULONGLONG DriverData::GetGidSize(ULONGLONG gid, PBOOLEAN found)
{
    ASSERT(found != nullptr);
    *found = FALSE;
    ULONGLONG ret = 0;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    PGID_ENTRY GidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (GidRecord != nullptr)
    { // there is such Gid
        *found = TRUE;
        ret = GidRecord->pidsSize;
    }
    KeReleaseSpinLock(&GIDSystemLock, irql);
    return ret;
}

BOOLEAN DriverData::GetGidPids(ULONGLONG gid, PULONG buffer, ULONGLONG bufferSize, PULONGLONG returnedLength)
{
    ASSERT(buffer != nullptr);
    ASSERT(returnedLength != nullptr);
    *returnedLength = 0;
    if (bufferSize == 0)
        return FALSE;
    ULONGLONG pidsSize = 0;
    ULONGLONG pidsIter = 0;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    PGID_ENTRY GidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (GidRecord != nullptr)
    { // there is such Gid
        pidsSize = GidRecord->pidsSize;
        PLIST_ENTRY PidsListHeader = &(GidRecord->HeadListPids);
        PLIST_ENTRY iterator = PidsListHeader->Flink;
        while (iterator != PidsListHeader && pidsIter < bufferSize)
        {
            PPID_ENTRY pStrct = (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
            ASSERT(pStrct != nullptr);
            if (pStrct != nullptr)
            {
                buffer[pidsIter++] = pStrct->Pid;
                *returnedLength += 1;
            }
            iterator = iterator->Flink;
        }
    }
    KeReleaseSpinLock(&GIDSystemLock, irql);
    if (GidRecord == nullptr)
    {
        return FALSE;
    }
    if (pidsSize == pidsIter)
    {
        return TRUE;
    }
    return FALSE;
}

// if found return true on found else return false
ULONGLONG DriverData::GetProcessGid(ULONG ProcessId, PBOOLEAN found)
{
    ASSERT(found != nullptr);
    *found = FALSE;
    ULONGLONG ret = 0;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    ret = (ULONGLONG)PidToGids.get(ProcessId);
    if (ret)
        *found = TRUE;
    KeReleaseSpinLock(&GIDSystemLock, irql);
    // DbgPrint("Gid: %d %d\n", ret, *found);
    return ret;
}

// clear all data related to Gid system
VOID DriverData::ClearGidsPids()
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    PLIST_ENTRY headGids = &GidsList;
    PLIST_ENTRY iterator = headGids->Flink;
    while (iterator != headGids)
    { // clear list
        PGID_ENTRY pStrct = (PGID_ENTRY)CONTAINING_RECORD(iterator, GID_ENTRY, GidListEntry);
        PLIST_ENTRY next = iterator->Flink;
        RemoveGidRecordAux(pStrct);        // clear process list and processes from PidToGids
        GidToPids.deleteNode(pStrct->gid); // remove gid from GidToPids
        gidsSize--;
        delete pStrct; // release GID_ENTRY
        iterator = next;
    }
    // ASSERT(headGids->Flink == headGids);
    GidCounter = 0;
    KeReleaseSpinLock(&GIDSystemLock, irql);
}

ULONGLONG DriverData::GidsSize()
{
    ULONGLONG ret = 0;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&GIDSystemLock, &irql);
    ret = gidsSize;
    KeReleaseSpinLock(&GIDSystemLock, irql);
    return ret;
}

// #######################################################################################
// # Irp handling
// #######################################################################################

VOID DriverData::ClearIrps()
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);
    PLIST_ENTRY pEntryIrps = irpOps.Flink;
    while (pEntryIrps != &irpOps)
    {
        LIST_ENTRY temp = *pEntryIrps;
        PIRP_ENTRY pStrct = (PIRP_ENTRY)CONTAINING_RECORD(pEntryIrps, IRP_ENTRY, entry);
        delete pStrct;
        // next
        pEntryIrps = temp.Flink;
    }
    irpOpsSize = 0;
    InitializeListHead(&irpOps);
    KeReleaseSpinLock(&irpOpsLock, irql);
}

ULONG DriverData::IrpSize()
{
    ULONG ret = 0;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);
    ret = irpOpsSize;
    KeReleaseSpinLock(&irpOpsLock, irql);
    return ret;
}

BOOLEAN DriverData::AddIrpMessage(PIRP_ENTRY newEntry)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);
    if (irpOpsSize < MAX_OPS_SAVE)
    {
        irpOpsSize++;
        InsertTailList(&irpOps, &newEntry->entry);
    }
    else
    {
        KeReleaseSpinLock(&irpOpsLock, irql);
        return FALSE;
    }
    KeReleaseSpinLock(&irpOpsLock, irql);
    return TRUE;
}

BOOLEAN DriverData::RemIrpMessage(PIRP_ENTRY newEntry)
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);
    RemoveEntryList(&newEntry->entry);
    irpOpsSize--;

    KeReleaseSpinLock(&irpOpsLock, irql);
    return TRUE;
}

PIRP_ENTRY DriverData::GetFirstIrpMessage()
{
    PLIST_ENTRY ret;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);
    ret = RemoveHeadList(&irpOps);
    irpOpsSize--;
    KeReleaseSpinLock(&irpOpsLock, irql);
    if (ret == &irpOps)
    {
        return NULL;
    }
    return (PIRP_ENTRY)CONTAINING_RECORD(ret, IRP_ENTRY, entry);
}

VOID DriverData::DriverGetIrps(PVOID Buffer, ULONG BufferSize, PULONG ReturnOutputBufferLength)
{
    *ReturnOutputBufferLength = sizeof(RWD_REPLY_IRPS);

    PCHAR OutputBuffer = (PCHAR)Buffer;
    ASSERT(OutputBuffer != nullptr);
    OutputBuffer += sizeof(RWD_REPLY_IRPS);

    ULONG BufferSizeRemain = BufferSize - sizeof(RWD_REPLY_IRPS);

    RWD_REPLY_IRPS outHeader;
    PLIST_ENTRY irpEntryList;

    PIRP_ENTRY PrevEntry = nullptr;
    PDRIVER_MESSAGE Prev = nullptr;
    USHORT prevBufferSize = 0;

    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);

    while (irpOpsSize)
    {
        irpEntryList = RemoveHeadList(&irpOps);
        irpOpsSize--;
        PIRP_ENTRY irp = (PIRP_ENTRY)CONTAINING_RECORD(irpEntryList, IRP_ENTRY, entry);
        UNICODE_STRING FilePath = irp->filePath;
        PDRIVER_MESSAGE irpMsg = &(irp->data);
        USHORT nameBufferSize = FilePath.Length;
        irpMsg->next = nullptr;
        irpMsg->filePath.Buffer = nullptr;
        if (FilePath.Length)
        {
            irpMsg->filePath.Length = nameBufferSize;
            irpMsg->filePath.MaximumLength = nameBufferSize;
        }
        else
        {
            irpMsg->filePath.Length = 0;
            irpMsg->filePath.MaximumLength = 0;
        }

        if (sizeof(DRIVER_MESSAGE) + nameBufferSize >= BufferSizeRemain)
        { // return to irps list, not enough space
            InsertHeadList(&irpOps, irpEntryList);
            irpOpsSize++;
            break;
        }
        else
        {
            if (Prev != nullptr)
            {
                Prev->next = PDRIVER_MESSAGE(OutputBuffer + sizeof(DRIVER_MESSAGE) +
                                             prevBufferSize); // PrevFilePath might be 0 size
                if (prevBufferSize)
                {
                    Prev->filePath.Buffer = PWCH(OutputBuffer + sizeof(DRIVER_MESSAGE)); // filePath buffer is after irp
                }
                RtlCopyMemory(OutputBuffer, Prev,
                              sizeof(DRIVER_MESSAGE)); // copy previous irp
                OutputBuffer += sizeof(DRIVER_MESSAGE);
                outHeader.addSize(sizeof(DRIVER_MESSAGE));
                *ReturnOutputBufferLength += sizeof(DRIVER_MESSAGE);
                if (prevBufferSize)
                {
                    RtlCopyMemory(OutputBuffer, PrevEntry->Buffer,
                                  prevBufferSize); // copy previous filePath
                    OutputBuffer += prevBufferSize;
                    outHeader.addSize(prevBufferSize);
                    *ReturnOutputBufferLength += prevBufferSize;
                }
                delete PrevEntry;
            }
        }

        PrevEntry = irp;
        Prev = irpMsg;
        prevBufferSize = nameBufferSize;
        if (prevBufferSize > MAX_FILE_NAME_SIZE)
            prevBufferSize = MAX_FILE_NAME_SIZE;
        BufferSizeRemain -= (sizeof(DRIVER_MESSAGE) + prevBufferSize);
        outHeader.addOp();
    }
    KeReleaseSpinLock(&irpOpsLock, irql);
    if (prevBufferSize > MAX_FILE_NAME_SIZE)
        prevBufferSize = MAX_FILE_NAME_SIZE;
    if (Prev != nullptr && PrevEntry != nullptr)
    {
        Prev->next = nullptr;
        if (prevBufferSize)
        {
            Prev->filePath.Buffer = PWCH(OutputBuffer + sizeof(DRIVER_MESSAGE)); // filePath buffer is after irp
        }
        RtlCopyMemory(OutputBuffer, Prev,
                      sizeof(DRIVER_MESSAGE)); // copy previous irp
        OutputBuffer += sizeof(DRIVER_MESSAGE);
        outHeader.addSize(sizeof(DRIVER_MESSAGE));
        *ReturnOutputBufferLength += sizeof(DRIVER_MESSAGE);
        if (prevBufferSize)
        {
            RtlCopyMemory(OutputBuffer, PrevEntry->Buffer,
                          prevBufferSize); // copy previous filePath
            OutputBuffer += prevBufferSize;
            outHeader.addSize(prevBufferSize);
            *ReturnOutputBufferLength += prevBufferSize;
        }
        delete PrevEntry;
    }

    if (outHeader.numOps())
    {
        outHeader.data = PDRIVER_MESSAGE((PCHAR)Buffer + sizeof(RWD_REPLY_IRPS));
    }

    RtlCopyMemory((PCHAR)Buffer, &(outHeader), sizeof(RWD_REPLY_IRPS));
}

LIST_ENTRY DriverData::GetAllEntries()
{
    LIST_ENTRY newList;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&irpOpsLock, &irql);
    irpOpsSize = 0;
    newList = irpOps;
    InitializeListHead(&irpOps);

    KeReleaseSpinLock(&irpOpsLock, irql);
    return newList;
}

// #######################################################################################
// # Directory handling
// #######################################################################################

BOOLEAN DriverData::AddDirectoryEntry(PDIRECTORY_ENTRY newEntry)
{
    BOOLEAN ret = FALSE;
    BOOLEAN foundMatch = FALSE;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&directoriesSpinLock, &irql);

    PLIST_ENTRY pEntry = rootDirectories.Flink;
    while (pEntry != &rootDirectories)
    {
        PDIRECTORY_ENTRY pStrct;
        //
        // Do some processing.
        //
        pStrct = (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);

        if (!wcsncmp(newEntry->path, pStrct->path, wcsnlen_s(newEntry->path, MAX_FILE_NAME_LENGTH)))
        {
            foundMatch = TRUE;
            break;
        }
        //
        // Move to next Entry in list.
        //
        pEntry = pEntry->Flink;
    }
    if (foundMatch == FALSE)
    {
        InsertHeadList(&rootDirectories, &newEntry->entry);
        directoryRootsSize++;
        ret = TRUE;
    }
    KeReleaseSpinLock(&directoriesSpinLock, irql);
    return ret;
}

PDIRECTORY_ENTRY DriverData::RemDirectoryEntry(LPCWSTR directory)
{
    PDIRECTORY_ENTRY ret = NULL;
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&directoriesSpinLock, &irql);

    PLIST_ENTRY pEntry = rootDirectories.Flink;

    while (pEntry != &rootDirectories)
    {
        PDIRECTORY_ENTRY pStrct;
        //
        // Do some processing.
        //
        pStrct = (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);

        if (!wcsncmp(directory, pStrct->path, wcsnlen_s(directory, MAX_FILE_NAME_LENGTH)))
        {
            if (RemoveEntryList(pEntry))
            {
                ret = pStrct;
                directoryRootsSize--;
                break;
            }
        }
        //
        // Move to next Entry in list.
        //
        pEntry = pEntry->Flink;
    }
    KeReleaseSpinLock(&directoriesSpinLock, irql);
    return ret;
}

/**
 IsContainingDirectory returns true if one of the directory entries in our
 LIST_ENTRY of PDIRECTORY_ENTRY is in the path passed as param
*/
BOOLEAN DriverData::IsContainingDirectory(CONST PUNICODE_STRING path)
{
    if (path == NULL || path->Buffer == NULL)
        return FALSE;
    BOOLEAN ret = FALSE;
    KIRQL irql = KeGetCurrentIrql();
    // DbgPrint("Looking for path: %ls in lookup dirs", path);
    KeAcquireSpinLock(&directoriesSpinLock, &irql);
    if (directoryRootsSize != 0)
    {
        PLIST_ENTRY pEntry = rootDirectories.Flink;
        while (pEntry != &rootDirectories)
        {
            PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);
            for (ULONG i = 0; i < path->Length; i++)
            {
                if (pStrct->path[i] == L'\0')
                {
                    ret = TRUE;
                    break;
                }
                else if (pStrct->path[i] == path->Buffer[i])
                {
                    continue;
                }
                else
                {
                    break; // for loop
                }
            }

            // ret = (wcsstr(path, pStrct->path) != NULL);
            if (ret)
                break;
            // Move to next Entry in list.
            pEntry = pEntry->Flink;
        }
    }
    KeReleaseSpinLock(&directoriesSpinLock, irql);
    return ret;
}

VOID DriverData::ClearDirectories()
{
    KIRQL irql = KeGetCurrentIrql();
    KeAcquireSpinLock(&directoriesSpinLock, &irql);
    PLIST_ENTRY pEntryDirs = rootDirectories.Flink;
    while (pEntryDirs != &rootDirectories)
    {
        LIST_ENTRY temp = *pEntryDirs;
        PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntryDirs, DIRECTORY_ENTRY, entry);
        delete pStrct;
        // next
        pEntryDirs = temp.Flink;
    }
    directoryRootsSize = 0;
    InitializeListHead(&rootDirectories);
    KeReleaseSpinLock(&directoriesSpinLock, irql);
}