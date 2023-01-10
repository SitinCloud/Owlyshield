#pragma once

#include <fltKernel.h>

NTSTATUS
FSAllocateUnicodeString(_Inout_ PUNICODE_STRING String);

VOID FSFreeUnicodeString(_Inout_ PUNICODE_STRING String);