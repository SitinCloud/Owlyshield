#pragma once

/*++

Module Name:

    FsFilter.h

Abstract:

    Header file for the kernel FS driver

Environment:

    Kernel mode

--*/

#include <dontuse.h>
#include <fltKernel.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <suppress.h>
#include <wdm.h>

#include "../SharedDefs/SharedDefs.h"
#include "Communication.h"
#include "DriverData.h"
#include "KernelString.h"
#include "ShanonEntropy.h"

NTSTATUS
FSUnloadDriver(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
FSPostOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS
FSPreOperation(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
               _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

NTSTATUS
FSInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                _In_ DEVICE_TYPE VolumeDeviceType, _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS
FSInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID FSInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID FSInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects, _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

// handles pre operation for read, write, set info and close files
NTSTATUS
FSProcessPreOperartion(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                       _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

NTSTATUS
FSEntrySetFileName(const PFLT_VOLUME volume, PFLT_FILE_NAME_INFORMATION nameInfo, PUNICODE_STRING uString);

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadIrp(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadSafe(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                      _In_opt_ PVOID CompletionContext, _In_ FLT_POST_OPERATION_FLAGS Flags);

// handles IRP_MJ_CREATE irps on post op
FLT_POSTOP_CALLBACK_STATUS
FSProcessCreateIrp(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects);

// compares unicode string file name to the directories in protected areas in driverData object
// return true if the file is in one of the dirs
BOOLEAN
FSIsFileNameInScanDirs(CONST PUNICODE_STRING path);

// ZwQueryInformationProcess - dynamic loaded function which query info data about already opened processes
typedef NTSTATUS (*QUERY_INFO_PROCESS)(__in HANDLE ProcessHandle, __in PROCESSINFOCLASS ProcessInformationClass,
                                       __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
                                       __in ULONG ProcessInformationLength, __out_opt PULONG ReturnLength);

QUERY_INFO_PROCESS ZwQueryInformationProcess;

// copy the file id info from the data argument (FLT_CALLBACK_DATA) to DRIVER_MESSAGE class allocated
NTSTATUS
CopyFileIdInfo(_Inout_ PFLT_CALLBACK_DATA Data, PDRIVER_MESSAGE newItem);

// recieves a pointer to allocated unicode string, FLT_RELATED_OBJECTS and FILE_NAME_INFORMATION class.
// function gets the file name from the name info and flt objects and fill the unicode string with it
NTSTATUS GetFileNameInfo(_In_ PCFLT_RELATED_OBJECTS FltObjects, PUNICODE_STRING FilePath,
                         PFLT_FILE_NAME_INFORMATION nameInfo);

// copy extension info from FILE_NAME_INFORMATION class to null terminated wchar string
VOID CopyExtension(PWCHAR dest, PFLT_FILE_NAME_INFORMATION nameInfo);

// AddRemProcessRoutine is the function hooked to the processes creation and exit.
// When a new process enter we add it to parent gid if there is any.
// if parent doesnt have a gid and both are system process, new process isnt recorded
// else we create a new gid for process

VOID AddRemProcessRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);

UNICODE_STRING GvolumeData;
