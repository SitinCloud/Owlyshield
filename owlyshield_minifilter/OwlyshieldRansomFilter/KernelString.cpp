#include "KernelString.h"

NTSTATUS
FSAllocateUnicodeString(_Inout_ PUNICODE_STRING String)
/*++

Routine Description:

	This routine allocates a unicode string

Arguments:

	String - supplies the size of the string to be allocated in the MaximumLength field
			 return the unicode string

Return Value:

	STATUS_SUCCESS                  - success
	STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{
    String->Buffer =
        (PWCH)ExAllocatePoolWithTag(NonPagedPool, String->MaximumLength, 'RW');

    if (String->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}

VOID FSFreeUnicodeString(_Inout_ PUNICODE_STRING String)
/*++

Routine Description:

	This routine frees a unicode string

Arguments:

	String - supplies the string to be freed

Return Value:

	None

--*/
{
    if (String->Buffer) {
        ExFreePoolWithTag(String->Buffer, 'RW');
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}