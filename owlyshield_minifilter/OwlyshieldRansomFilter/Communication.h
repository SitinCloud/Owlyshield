#pragma once

#include <fltKernel.h>
#include <stdio.h>

#include "../SharedDefs/SharedDefs.h"
#include "DriverData.h"

struct CommHandler
{
    //  Server-side communicate ports.
    PFLT_PORT ServerPort;

    //  port for a connection to user-mode
    PFLT_PORT ClientPort;

    //  The filter handle that results from a call to
    PFLT_FILTER Filter;

    //  A flag that indicating that the filter is connected
    BOOLEAN CommClosed;

    //  User process that connected to the port

    ULONG UserProcess;

    CommHandler(PFLT_FILTER Filter)
        : ServerPort(NULL), ClientPort(NULL), Filter(Filter), CommClosed(TRUE), UserProcess(0)
    {
    }
};

extern CommHandler *commHandle;

NTSTATUS InitCommData();

// close the comm handler, close both ports
void CommClose();

BOOLEAN IsCommClosed();

// AMFConnect: Handles user mode application which connects to the driver

NTSTATUS
RWFConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerPortCookie,
           _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext, _In_ ULONG SizeOfContext,
           _Outptr_result_maybenull_ PVOID *ConnectionCookie);

// AMFConnect: handle messages received from user mode

NTSTATUS RWFNewMessage(IN PVOID PortCookie, IN PVOID InputBuffer, IN ULONG InputBufferLength, OUT PVOID OutputBuffer,
                       IN ULONG OutputBufferLength, OUT PULONG ReturnOutputBufferLength);

// AMFDisconnect: Handles user mode application which disconnects from the driver

VOID RWFDissconnect(_In_opt_ PVOID ConnectionCookie);