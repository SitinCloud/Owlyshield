/*++

Module Name:

	FsFilter.c

Abstract:

	This is the main module of the FsFilter miniFilter driver.

Environment:

	Kernel mode

--*/

#include "FsFilter.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//  Structure that contains all the global data structures used throughout the driver.

EXTERN_C_START

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
);

DRIVER_INITIALIZE DriverEntry;


EXTERN_C_END

//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{IRP_MJ_CREATE, 0, FSPreOperation, FSPostOperation},
	//{IRP_MJ_CLOSE, 0, FSPreOperation, FSPostOperation},
	{IRP_MJ_READ, 0, FSPreOperation, FSPostOperation}, 
	{IRP_MJ_CLEANUP, 0, FSPreOperation, NULL},
	{IRP_MJ_WRITE, 0, FSPreOperation, NULL},
	{IRP_MJ_SET_INFORMATION, 0, FSPreOperation, NULL},
	{ IRP_MJ_OPERATION_END }
};

/*++

FilterRegistration Defines what we want to filter with the driver

--*/
CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	NULL,								//  Context Registration.
	Callbacks,                          //  Operation callbacks
	FSUnloadDriver,                     //  FilterUnload
	FSInstanceSetup,					//  InstanceSetup
	FSInstanceQueryTeardown,			//  InstanceQueryTeardown
	FSInstanceTeardownStart,            //  InstanceTeardownStart
	FSInstanceTeardownComplete,         //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

	This is the initialization routine for the Filter driver.  This
	registers the Filter with the filter manager and initializes all
	its global data structures.

Arguments:

	DriverObject - Pointer to driver object created by the system to
		represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
		driver are located in the registry.

Return Value:

	Returns STATUS_SUCCESS.
--*/
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS status;

	//
	//  Default to NonPagedPoolNx for non paged pool allocations where supported.
	//

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	//
	//  Register with filter manager.
	//

	driverData = new DriverData(DriverObject);
	if (driverData == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}


	PFLT_FILTER* FilterAdd = driverData->getFilterAdd();

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		FilterAdd);


	if (!NT_SUCCESS(status)) {
		delete driverData;
		return status;
	}

	commHandle = new CommHandler(driverData->getFilter());
	if (commHandle == NULL) {
		delete driverData;
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	status = InitCommData();

	if (!NT_SUCCESS(status)) {
		FltUnregisterFilter(driverData->getFilter());
		delete driverData;
		delete commHandle;
		return status;
	}
	//
	//  Start filtering I/O.
	//
	status = FltStartFiltering(driverData->getFilter());

	if (!NT_SUCCESS(status)) {


		CommClose();
		FltUnregisterFilter(driverData->getFilter());
		delete driverData;
		delete commHandle;
		return status;
	}
	driverData->setFilterStart();
	DbgPrint("loaded scanner successfully");
	// new code
	// FIXME: check status and release in unload
	PsSetCreateProcessNotifyRoutine(AddRemProcessRoutine, FALSE);
	return STATUS_SUCCESS;
}

NTSTATUS
FSUnloadDriver(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

	This is the unload routine for the Filter driver.  This unregisters the
	Filter with the filter manager and frees any allocated global data
	structures.

Arguments:

	None.

Return Value:

	Returns the final status of the deallocation routines.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	//
	//  Close the server port.
	//
	driverData->setFilterStop();
	CommClose();

	//
	//  Unregister the filter
	//

	FltUnregisterFilter(driverData->getFilter());
	delete driverData;
	delete commHandle;
	PsSetCreateProcessNotifyRoutine(AddRemProcessRoutine, TRUE);
	return STATUS_SUCCESS;
}

NTSTATUS
FSInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

This routine is called whenever a new instance is created on a volume. This
gives us a chance to decide if we need to attach to this volume or not.

If this routine is not defined in the registration structure, automatic
instances are always created.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Flags describing the reason for this attach request.

Return Value:

STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);


	DbgPrint("FSFIlter: Entered FSInstanceSetup\n");


	WCHAR newTemp[40];

	GvolumeData.MaximumLength = 80;
	GvolumeData.Buffer = newTemp;
	GvolumeData.Length = 0;
	
	NTSTATUS hr = STATUS_SUCCESS;
	PDEVICE_OBJECT devObject;
	hr = FltGetDiskDeviceObject(FltObjects->Volume, &devObject);
	if (!NT_SUCCESS(hr)) {
		return STATUS_SUCCESS;
		//return hr;
	}
	hr = IoVolumeDeviceToDosName(devObject, &GvolumeData);
	if (!NT_SUCCESS(hr)) {
	//	return STATUS_SUCCESS;

		return hr;
	}
	return STATUS_SUCCESS;
}

NTSTATUS
FSInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

If this routine is not defined in the registration structure, explicit
detach requests via FltDetachVolume or FilterDetach will always be
failed.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	DbgPrint("FSFIlter: Entered FSInstanceQueryTeardown\n");

	return STATUS_SUCCESS;
}

VOID
FSInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This routine is called at the start of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is being deleted.

Return Value:

None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	DbgPrint("FSFIlter: Entered FSInstanceTeardownStart\n");
}

VOID
FSInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This routine is called at the end of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is being deleted.

Return Value:

None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	DbgPrint("FSFIlter: Entered FSInstanceTeardownComplete\n");
}


FLT_PREOP_CALLBACK_STATUS
FSPreOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

	Pre operations callback

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - Output parameter which can be used to pass a context
		from this pre-create callback to the post-create callback.

Return Value:

   FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
   FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

--*/
{

	NTSTATUS hr = STATUS_SUCCESS;
	if (FltGetRequestorProcessId(Data) == 4) return FLT_PREOP_SUCCESS_NO_CALLBACK; // system process -  skip
	if (FltGetRequestorProcessId(Data) == driverData->getPID()) {

		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Allowing pre op for trusted process, no post op\n");

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (FltObjects->FileObject == NULL) { //no file object
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	// create tested only on post op, cant check here
	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	hr = FSProcessPreOperartion(Data, FltObjects, CompletionContext);
	if (hr == FLT_PREOP_SUCCESS_WITH_CALLBACK) return FLT_PREOP_SUCCESS_WITH_CALLBACK;

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

NTSTATUS
FSProcessPreOperartion(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) 
{   
	// no communication
	if (driverData->isFilterClosed() || IsCommClosed()) {
		//DbgPrint("!!! FSFilter: Filter is closed or Port is closed, skipping data\n");
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	NTSTATUS hr = FLT_PREOP_SUCCESS_NO_CALLBACK;

	
	PFLT_FILE_NAME_INFORMATION nameInfo;
	hr = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
	if (!NT_SUCCESS(hr))
		return hr;

	BOOLEAN isDir;
	hr = FltIsDirectory(Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance, &isDir);
	if (!NT_SUCCESS(hr))
		return hr;
	if (isDir)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	PIRP_ENTRY newEntry = new IRP_ENTRY();
	if (newEntry == NULL) {
		FltReferenceFileNameInformation(nameInfo);
		return hr;
	}
	
	// reset
	PDRIVER_MESSAGE newItem = &newEntry->data;
	PUNICODE_STRING FilePath = &(newEntry->filePath);

	hr = GetFileNameInfo(FltObjects, FilePath, nameInfo); 

	if (!NT_SUCCESS(hr)) {
		FltReferenceFileNameInformation(nameInfo);
		delete newEntry;
		return hr;
	}
	
	//get pid
	newItem->PID = FltGetRequestorProcessId(Data);

	BOOLEAN isGidFound;
	ULONGLONG gid = driverData->GetProcessGid(newItem->PID, &isGidFound);
	if (gid == 0 || !isGidFound) {
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Item does not have a gid, skipping\n");
		FltReferenceFileNameInformation(nameInfo);
		delete newEntry;
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	newItem->Gid = gid;

	if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Registring new irp for Gid: %d with pid: %d\n", gid, newItem->PID);

	// get file id
	hr = CopyFileIdInfo(Data, newItem);
	if (!NT_SUCCESS(hr)) {
		FltReferenceFileNameInformation(nameInfo);
		delete newEntry;
		return hr;
	}
	
	
	if (FSIsFileNameInScanDirs(FilePath)) {
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: File in scan area \n");
		newItem->FileLocationInfo = FILE_PROTECTED;
	}
 
	if (Data->Iopb->MajorFunction == IRP_MJ_READ || Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
		CopyExtension(newItem->Extension, nameInfo);
	}

	if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Logging IRP op: %s \n", FltGetIrpName(Data->Iopb->MajorFunction));

	if (Data->Iopb->MajorFunction != IRP_MJ_SET_INFORMATION)
		FltReleaseFileNameInformation(nameInfo);
	
	switch (Data->Iopb->MajorFunction) {

	//create is handled on post operation, read is created here but calculated on post(data avilable
	case IRP_MJ_READ:
	{
		newItem->IRP_OP = IRP_READ;
		if (Data->Iopb->Parameters.Read.Length == 0) // no data to read
		{
			delete newEntry;
		    DbgPrint("FsFilter: IRP READ NOCALLBACK LENGTH IS ZERO! \n");
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Preop IRP_MJ_READ, return with postop \n");
		// save context for post, we calculate the entropy of read, we pass the irp to application on post op
		*CompletionContext = newEntry;
		    DbgPrint("FsFilter: IRP READ WITH CALLBACK! ****************** \n");
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}
	case IRP_MJ_CLEANUP:
		newItem->IRP_OP = IRP_CLEANUP;
		break;
	case IRP_MJ_WRITE:
	{
		newItem->IRP_OP = IRP_WRITE;
		//if (newItem->FileLocationInfo == FILE_NOT_PROTECTED) {
		//	delete newEntry;
		//	return FLT_PREOP_SUCCESS_NO_CALLBACK;
		//}
		newItem->FileChange = FILE_CHANGE_WRITE;
		PVOID writeBuffer = NULL;
		if (Data->Iopb->Parameters.Write.Length == 0) // no data to write
		{
			break;
		}

		// prepare buffer for entropy calc
		if (Data->Iopb->Parameters.Write.MdlAddress == NULL) { //there's mdl buffer, we use it
			writeBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
		}
		else {
			writeBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Write.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
		}
		if (writeBuffer == NULL) { // alloc failed
			delete newEntry;
			// fail the irp request
			Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
		newItem->MemSizeUsed = Data->Iopb->Parameters.Write.Length;
		// we catch EXCEPTION_EXECUTE_HANDLER so to prevent crash when calculating
		__try {
			newItem->Entropy = shannonEntropy((PUCHAR)writeBuffer, newItem->MemSizeUsed);
			newItem->isEntropyCalc = TRUE;

		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Failed to calc entropy\n");
			delete newEntry;
			// fail the irp request
			Data->IoStatus.Status = STATUS_INTERNAL_ERROR;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}
		break;
	case IRP_MJ_SET_INFORMATION:
	{
		newItem->IRP_OP = IRP_SETINFO;
		// we check for delete later and renaming
		FILE_INFORMATION_CLASS fileInfo = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

		if (fileInfo == FileDispositionInformation && // handle delete later
			(((PFILE_DISPOSITION_INFORMATION)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer))->DeleteFile))
		{
			newItem->FileChange = FILE_CHANGE_DELETE_FILE;
		} // end delete 1

		else if (fileInfo == FileDispositionInformationEx &&
			FlagOn(((PFILE_DISPOSITION_INFORMATION_EX)(Data->Iopb->Parameters.SetFileInformation.InfoBuffer))->Flags, FILE_DISPOSITION_DELETE)) {
			newItem->FileChange = FILE_CHANGE_DELETE_FILE;
		} // end delete 2

		else if (fileInfo == FileRenameInformation || fileInfo == FileRenameInformationEx) 
		{
			// OPTIONAL: get new name?

			newItem->FileChange = FILE_CHANGE_RENAME_FILE;
			PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
			PFLT_FILE_NAME_INFORMATION newNameInfo;
			WCHAR Buffer[MAX_FILE_NAME_LENGTH];
			UNICODE_STRING NewFilePath;
			NewFilePath.Buffer = Buffer;
			NewFilePath.Length = 0;
			NewFilePath.MaximumLength = MAX_FILE_NAME_SIZE;
			
			hr = FltGetDestinationFileNameInformation(
				FltObjects->Instance,
				FltObjects->FileObject,
				renameInfo->RootDirectory,
				renameInfo->FileName,
				renameInfo->FileNameLength,
				FLT_FILE_NAME_QUERY_DEFAULT | FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER | FLT_FILE_NAME_OPENED,
				&newNameInfo);
			if (!NT_SUCCESS(hr)) {
				delete newEntry;
				FltReleaseFileNameInformation(nameInfo);
				return hr;
			}

			NTSTATUS status = GetFileNameInfo(FltObjects, &NewFilePath, newNameInfo);
			if (!NT_SUCCESS(status)) {
				delete newEntry;
				FltReleaseFileNameInformation(nameInfo);
				FltReleaseFileNameInformation(newNameInfo);
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}

			RtlCopyBytes(newEntry->Buffer, Buffer, MAX_FILE_NAME_SIZE); // replace buffer data with new file
			newItem->FileLocationInfo = FILE_MOVED_OUT;
			/*
			if (FSIsFileNameInScanDirs(&NewFilePath)) {
				if (newItem->FileLocationInfo == FILE_NOT_PROTECTED) { // moved in - report new file name
					newItem->FileLocationInfo = FILE_MOVED_IN;
					//newEntry->filePath = NewFilePath; // remember file moved in
					RtlCopyBytes(newEntry->Buffer, Buffer, MAX_FILE_NAME_SIZE); // replace buffer data with new file
				} // else we still report old file name so we know it was changed
			}
			else { // new file name not protected
				if (newItem->FileLocationInfo == FILE_PROTECTED) { // moved out - report old file name
					newItem->FileLocationInfo = FILE_MOVED_OUT;
				}
				/*else { // we dont care - rename of file in unprotected area to unprotected area
					delete newEntry;
					FltReleaseFileNameInformation(nameInfo);
					FltReleaseFileNameInformation(newNameInfo);
					return FLT_PREOP_SUCCESS_NO_CALLBACK;
				}
			}
			*/

			CopyExtension(newItem->Extension, newNameInfo);
			FltReleaseFileNameInformation(newNameInfo);
			for (LONG i = 0; i < FILE_OBJEC_MAX_EXTENSION_SIZE ; i++) {
				if (i == (nameInfo->Extension.Length / 2)) break;
				if (newItem->Extension[i] != nameInfo->Extension.Buffer[i]) {
					newItem->FileChange = FILE_CHANGE_EXTENSION_CHANGED;
					break;
				}
			}
			FltReleaseFileNameInformation(nameInfo);
		} // end rename
		else // not rename or delete (set info)
		{
			delete newEntry;
			FltReleaseFileNameInformation(nameInfo);
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		break;
	}
	default :
		delete newEntry;
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Adding entry to irps %s\n", FltGetIrpName(Data->Iopb->MajorFunction));
	if (!driverData->AddIrpMessage(newEntry)) {
		delete newEntry;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;

}

FLT_POSTOP_CALLBACK_STATUS
FSPostOperation(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

	Post opeartion callback. we reach here in case of IRP_MJ_CREATE or IRP_MJ_READ

Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
		operation.

	CompletionContext - The operation context passed fron the pre-create
		callback.

	Flags - Flags to say why we are getting this post-operation callback.

Return Value:

	FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
									 access to this file, hence undo the open

--*/
{

	//DbgPrint("!!! FSFilter: Enter post op for irp: %s, pid of process: %u\n", FltGetIrpName(Data->Iopb->MajorFunction), FltGetRequestorProcessId(Data));
	
	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {
		//DbgPrint("!!! FSFilter: finished post operation, already failed \n");
		if (CompletionContext != nullptr && Data->Iopb->MajorFunction == IRP_MJ_READ) {
			delete (PIRP_ENTRY)CompletionContext;
		}
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (Data->Iopb->MajorFunction == IRP_MJ_CREATE) {
		return FSProcessCreateIrp(Data, FltObjects);
	}
	else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
		//return FLT_POSTOP_FINISHED_PROCESSING;
		return FSProcessPostReadIrp(Data, FltObjects, CompletionContext, Flags);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FSProcessCreateIrp(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects
)
{
	NTSTATUS hr;
	if (FlagOn(Data->Iopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY) || FlagOn(Data->Iopb->OperationFlags, SL_OPEN_PAGING_FILE)) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (driverData->isFilterClosed() || IsCommClosed())
	{
		//DbgPrint("!!! FSFilter: filter closed or comm closed, skip irp\n");
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	BOOLEAN isDir;
	hr = FltIsDirectory(Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance, &isDir);
	if (!NT_SUCCESS(hr)) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PFLT_FILE_NAME_INFORMATION nameInfo;
	hr = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
	if (!NT_SUCCESS(hr))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PIRP_ENTRY newEntry = new IRP_ENTRY();
	if (newEntry == NULL) {
		FltReleaseFileNameInformation(nameInfo);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	PDRIVER_MESSAGE newItem = &newEntry->data;

	newItem->PID = FltGetRequestorProcessId(Data);
	newItem->IRP_OP = IRP_CREATE;
	newItem->FileLocationInfo = FILE_PROTECTED;
	PUNICODE_STRING FilePath = &(newEntry->filePath);

	BOOLEAN isGidFound;
	ULONGLONG gid = driverData->GetProcessGid(newItem->PID, &isGidFound);
	if (gid == 0 || !isGidFound) {
		//DbgPrint("!!! FSFilter: Item does not have a gid, skipping\n"); // TODO: incase it doesnt exist we can add it with our method that checks for system process
		FltReferenceFileNameInformation(nameInfo);
		delete newEntry;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	newItem->Gid = gid;
	DbgPrint("!!! FSFilter: Registring new irp for Gid: %d with pid: %d\n", gid, newItem->PID); // TODO: incase it doesnt exist we can add it with our method that checks for system process

	// get file id
	hr = CopyFileIdInfo(Data, newItem);
	if (!NT_SUCCESS(hr)) {
		delete newEntry;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	hr = GetFileNameInfo(FltObjects, FilePath, nameInfo);
	if (!NT_SUCCESS(hr)) {
		delete newEntry;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	CopyExtension(newItem->Extension, nameInfo);

	FltReleaseFileNameInformation(nameInfo);

	/*
	if (!FSIsFileNameInScanDirs(FilePath)) {
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Skipping uninterented file, not in scan area \n");
		delete newEntry;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	*/

	if (isDir && (Data->IoStatus.Information) == FILE_OPENED) {
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Dir listing opened on existing directory\n");
		newItem->FileChange = FILE_OPEN_DIRECTORY;
	} else if (isDir) {
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Dir but not listing, not importent \n");
		delete newEntry;
		return FLT_POSTOP_FINISHED_PROCESSING;
	} else if ((Data->IoStatus.Information) == FILE_OVERWRITTEN || (Data->IoStatus.Information) == FILE_SUPERSEDED) {
		newItem->FileChange = FILE_CHANGE_OVERWRITE_FILE;
	} else  if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
		newItem->FileChange = FILE_CHANGE_DELETE_FILE;
		if ((Data->IoStatus.Information) == FILE_CREATED) {
			newItem->FileChange = FILE_CHANGE_DELETE_NEW_FILE;
		}
	} else if ((Data->IoStatus.Information) == FILE_CREATED) {
		newItem->FileChange = FILE_CHANGE_NEW_FILE;
	}
	if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Adding entry to irps\n");
	if (!driverData->AddIrpMessage(newEntry)) {
		delete newEntry;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadIrp(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	if (CompletionContext == NULL) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PIRP_ENTRY entry = (PIRP_ENTRY)CompletionContext;

	if (driverData->isFilterClosed() || IsCommClosed()) {
		if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Post op read, comm or filter closed\n");
		delete entry;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FLT_POSTOP_CALLBACK_STATUS status = FLT_POSTOP_FINISHED_PROCESSING;
	
	PVOID ReadBuffer = NULL;

	// prepare buffer for entropy calc
	if (Data->Iopb->Parameters.Read.MdlAddress != NULL) { //there's mdl buffer, we use it
		ReadBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);

	}
	else if (FlagOn(Data->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER)) //safe 
	{
		ReadBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
	} else
	{
		if (FltDoCompletionProcessingWhenSafe(Data, FltObjects, CompletionContext, Flags, FSProcessPostReadSafe, &status)) { //post to worker thread or run if irql is ok
			return FLT_POSTOP_FINISHED_PROCESSING;
		}
		else {
			Data->IoStatus.Status = STATUS_INTERNAL_ERROR;
			Data->IoStatus.Information = 0;
			delete entry;
			return status;
		}
	}
	if (!ReadBuffer)
	{
		delete entry;
		Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		Data->IoStatus.Information = 0;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	entry->data.MemSizeUsed = (ULONG)Data->IoStatus.Information; //successful read data
	// we catch EXCEPTION_EXECUTE_HANDLER so to prevent crash when calculating
	__try {
		entry->data.Entropy = shannonEntropy((PUCHAR)ReadBuffer, Data->IoStatus.Information);
		entry->data.isEntropyCalc = TRUE;

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		delete entry;
		// fail the irp request
		Data->IoStatus.Status = STATUS_INTERNAL_ERROR;
		Data->IoStatus.Information = 0;
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Addung entry to irps IRP_MJ_READ\n");
	if (!driverData->AddIrpMessage(entry)) {
		delete entry;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
FSProcessPostReadSafe(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(FltObjects);

	NTSTATUS status = STATUS_SUCCESS;
	PIRP_ENTRY entry = (PIRP_ENTRY)CompletionContext;
	ASSERT(entry != nullptr);
	status = FltLockUserBuffer(Data);
	if (NT_SUCCESS(status))
	{
		PVOID ReadBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority | MdlMappingNoExecute);
		if (ReadBuffer != NULL) {
			__try {
				entry->data.Entropy = shannonEntropy((PUCHAR)ReadBuffer, Data->IoStatus.Information);
				entry->data.MemSizeUsed = Data->IoStatus.Information;
				entry->data.isEntropyCalc = TRUE;
				if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: Addung entry to irps IRP_MJ_READ\n");
				if (driverData->AddIrpMessage(entry)) {
					return FLT_POSTOP_FINISHED_PROCESSING;
				}
			}
			__except(EXCEPTION_EXECUTE_HANDLER) {
				status = STATUS_INTERNAL_ERROR;
			}

		}
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	delete entry;
	return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN
FSIsFileNameInScanDirs(
	CONST PUNICODE_STRING path
) 
{
	//ASSERT(driverData != NULL);
	return driverData->IsContainingDirectory(path);
}

NTSTATUS
FSEntrySetFileName(
	CONST PFLT_VOLUME Volume,
	PFLT_FILE_NAME_INFORMATION nameInfo,
	PUNICODE_STRING uString
)
{
	NTSTATUS hr = STATUS_SUCCESS;
	PDEVICE_OBJECT devObject;
	USHORT volumeDosNameSize;
	USHORT finalNameSize;
	USHORT volumeNameSize = nameInfo->Volume.Length; // in bytes
	USHORT origNameSize = nameInfo->Name.Length; // in bytes
	
	WCHAR newTemp[40]; 

	UNICODE_STRING volumeData; 
	volumeData.MaximumLength = 80;
	volumeData.Buffer = newTemp;
	volumeData.Length = 0;
	
	hr = FltGetDiskDeviceObject(Volume, &devObject);
	if (!NT_SUCCESS(hr)) {
		return hr;
	}
	/*if (KeAreAllApcsDisabled()) {
		return hr;
	}*/

	if (!KeAreAllApcsDisabled()) {
		hr = IoVolumeDeviceToDosName(devObject, &GvolumeData); 
	}
	volumeDosNameSize = GvolumeData.Length;
	finalNameSize = origNameSize - volumeNameSize + volumeDosNameSize; // not null terminated, in bytes

	//DbgPrint("Volume name: %wZ, Size: %d, finalNameSize: %d, volumeNameSize: %d\n", volumeData, volumeDosNameSize, finalNameSize, volumeNameSize);
	//DbgPrint("Name buffer: %wZ\n", nameInfo->Name);
	
	if (uString == NULL) {
		ObDereferenceObject(devObject);
		return STATUS_INVALID_ADDRESS;
	}
	if (volumeNameSize == origNameSize) { // file is the volume, don't need to do anything
		ObDereferenceObject(devObject);
		return RtlUnicodeStringCopy(uString, &nameInfo->Name);
	}
	
	if (NT_SUCCESS(hr = RtlUnicodeStringCopy(uString, &GvolumeData))) {// prefix of volume e.g. C:

		#DbgPrint("File name: %wZ\n", uString);
		RtlCopyMemory(uString->Buffer + (volumeDosNameSize / 2),
			nameInfo->Name.Buffer + (volumeNameSize / 2),
			((finalNameSize - volumeDosNameSize > MAX_FILE_NAME_SIZE - volumeDosNameSize) ? (MAX_FILE_NAME_SIZE - volumeDosNameSize) : (finalNameSize - volumeDosNameSize))
		);
		uString->Length = (finalNameSize > MAX_FILE_NAME_SIZE) ? MAX_FILE_NAME_SIZE : finalNameSize;
		#DbgPrint("File name: %wZ\n", uString);	
	}
	ObDereferenceObject(devObject);
	return hr;
}

NTSTATUS CopyFileIdInfo(_Inout_ PFLT_CALLBACK_DATA Data, PDRIVER_MESSAGE newItem) {
	FILE_ID_INFORMATION fileInformation;
	NTSTATUS hr = FltQueryInformationFile(Data->Iopb->TargetInstance,
		Data->Iopb->TargetFileObject,
		&fileInformation,
		sizeof(FILE_ID_INFORMATION),
		FileIdInformation,
		NULL);
	RtlCopyMemory(&(newItem->FileID), &fileInformation, sizeof(FILE_ID_INFORMATION));
	return hr;
}

NTSTATUS GetFileNameInfo(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	PUNICODE_STRING FilePath, 
	PFLT_FILE_NAME_INFORMATION  nameInfo
) {
	NTSTATUS hr;
	hr = FltParseFileNameInformation(nameInfo);
	if (!NT_SUCCESS(hr))  {
		FltReleaseFileNameInformation(nameInfo);
		return hr;
	}
	hr = FSEntrySetFileName(FltObjects->Volume, nameInfo, FilePath);
	//DbgPrint("!!!FSFILTER DEBUG EntryFileName %d \n", NT_SUCCESS(hr));
	if (!NT_SUCCESS(hr)) {
		FltReleaseFileNameInformation(nameInfo);
	}//*/
	return hr;
}



VOID CopyExtension(PWCHAR dest, PFLT_FILE_NAME_INFORMATION nameInfo) {
	if (IS_DEBUG_IRP) DbgPrint("!!! FSFilter: copying the file type extension, extension length: %d, name: %wZ\n", nameInfo->Extension.Length, nameInfo->Extension);
	RtlZeroBytes(dest, (FILE_OBJEC_MAX_EXTENSION_SIZE + 1) * sizeof(WCHAR));
	for (LONG i = 0; i < FILE_OBJEC_MAX_EXTENSION_SIZE; i++) {
		if (i == (nameInfo->Extension.Length / 2)) break;
		dest[i] = nameInfo->Extension.Buffer[i];
	}
}

static NTSTATUS GetProcessNameByHandle(_In_ HANDLE ProcessHandle, _Out_ PUNICODE_STRING* Name)
{
	ULONG retLength = 0;
	ULONG pniSize = 512;
	PUNICODE_STRING pni = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	do {
		pni = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, pniSize, 'RW');
		if (pni != NULL) {
			status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, pni, pniSize, &retLength);
			if (!NT_SUCCESS(status)) {
				ExFreePoolWithTag(pni, 'RW');
				pniSize *= 2;
			}
		}
		else status = STATUS_INSUFFICIENT_RESOURCES;
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status))
		* Name = pni;

	return status;
}

// new code process recording
VOID AddRemProcessRoutine(
	HANDLE ParentId,
	HANDLE ProcessId,
	BOOLEAN Create
) {
	if (commHandle->CommClosed) return;
	if (Create) {
		NTSTATUS hr;
		if (ZwQueryInformationProcess == NULL)
		{
			UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

			ZwQueryInformationProcess =
				(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

			if (ZwQueryInformationProcess == NULL)
			{
				DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
				hr = STATUS_UNSUCCESSFUL;
				return;
			}
		}
		HANDLE procHandleParent;
		HANDLE procHandleProcess;

		CLIENT_ID clientIdParent;
		clientIdParent.UniqueProcess = ParentId;
		clientIdParent.UniqueThread = 0;

		CLIENT_ID clientIdProcess;
		clientIdProcess.UniqueProcess = ProcessId;
		clientIdProcess.UniqueThread = 0;

		OBJECT_ATTRIBUTES objAttribs;

		InitializeObjectAttributes(&objAttribs,
			NULL,
			OBJ_KERNEL_HANDLE,
			NULL,
			NULL);

		hr = ZwOpenProcess(&procHandleParent, PROCESS_ALL_ACCESS, &objAttribs, &clientIdParent);
		if (!NT_SUCCESS(hr)) {
			DbgPrint("!!! FSFilter: Failed to open process: %#010x.\n", hr);
			return;
		}
		hr = ZwOpenProcess(&procHandleProcess, PROCESS_ALL_ACCESS, &objAttribs, &clientIdProcess);
		if (!NT_SUCCESS(hr)) {
			DbgPrint("!!! FSFilter: Failed to open process: %#010x.\n", hr);
			hr = ZwClose(procHandleParent);
			if (!NT_SUCCESS(hr)) {
				DbgPrint("!!! FSFilter: Failed to close process: %#010x.\n", hr);
				return;
			}
			return;
		}

		PUNICODE_STRING procName;
		PUNICODE_STRING parentName;
		hr = GetProcessNameByHandle(procHandleParent, &parentName);
		if (!NT_SUCCESS(hr)) {
			DbgPrint("!!! FSFilter: Failed to get parent name: %#010x\n", hr);
			return;
		}
		hr = GetProcessNameByHandle(procHandleProcess, &procName);
		if (!NT_SUCCESS(hr)) {
			DbgPrint("!!! FSFilter: Failed to get process name: %#010x\n", hr);
			return;
		}

		DbgPrint("!!! FSFilter: New Process, parent: %wZ. Pid: %d\n", parentName, (ULONG)(ULONG_PTR)ParentId);

		hr = ZwClose(procHandleParent);
		if (!NT_SUCCESS(hr)) {
			DbgPrint("!!! FSFilter: Failed to close process: %#010x.\n", hr);
			return;
		}
		hr = ZwClose(procHandleProcess);
		if (!NT_SUCCESS(hr)) {
			DbgPrint("!!! FSFilter: Failed to close process: %#010x.\n", hr);
			return;
		}
		DbgPrint("!!! FSFilter: New Process, process: %wZ , pid: %d.\n", procName, (ULONG)(ULONG_PTR)ProcessId);

		BOOLEAN found = FALSE;
		if (startsWith(procName, driverData->GetSystemRootPath()) && // process in safe area
			startsWith(parentName, driverData->GetSystemRootPath()) && // parent in safe area
			(driverData->GetProcessGid((ULONG)(ULONG_PTR)ParentId, &found) == 0) && !found) // parent is not documented, if it was there was a recursive call from not safe process which resulted in safe are in windows dir 
		{
			DbgPrint("!!! FSFilter: Open Process not recorded, both parent and process are safe\n");
			delete parentName;
			delete procName;
			return;
		}
		// options to reach: process is not safe (parent safe or not), process safe parent is not, both safe but before parent there was unsafe process
		DbgPrint("!!! FSFilter: Open Process recording, is parent safe: %d, is process safe: %d\n", startsWith(procName, driverData->GetSystemRootPath()), startsWith(parentName, driverData->GetSystemRootPath()));
		driverData->RecordNewProcess(procName, (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)ParentId);
		delete parentName;
	}
	else {
		DbgPrint("!!! FSFilter: Terminate Process, Process: %d pid\n", (ULONG)(ULONG_PTR)ProcessId);
		driverData->RemoveProcess((ULONG)(ULONG_PTR)ProcessId); 
	}
}
