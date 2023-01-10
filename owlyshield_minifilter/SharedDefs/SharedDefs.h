#pragma once

/*++

Abstract :

Header file which contains the structures, type definitions,
constants, global variables and function prototypes that are
shared between kernel and user mode.

Environment :

    Kernel & user mode

--*/

//
//  Name of port used to communicate
//

const PCWSTR ComPortName = L"\\RWFilter";

#define MAX_FILE_NAME_LENGTH 520
#define MAX_FILE_NAME_SIZE (MAX_FILE_NAME_LENGTH * sizeof(WCHAR)) // max length in bytes of files sizes and dir paths
#define FILE_OBJECT_ID_SIZE 16
#define FILE_OBJEC_MAX_EXTENSION_SIZE 11

#define MAX_COMM_BUFFER_SIZE 0x10000 // size of the buffer we allocate to receive irp ops from the driver
#define MAX_OPS_SAVE                                                                                                   \
    0x1000 // max ops to save, we limit this to prevent driver from filling the non paged memory and crashing the os

// msgs types that the application may send to the driver
enum COM_MESSAGE_TYPE
{
    MESSAGE_ADD_SCAN_DIRECTORY,
    MESSAGE_REM_SCAN_DIRECTORY,
    MESSAGE_GET_OPS,
    MESSAGE_SET_PID,
    MESSAGE_KILL_GID
};

// msgs struct that the application send when sending msg to the driver, type member should be one of the
// COM_MESSAGE_TYPE
typedef struct _COM_MESSAGE
{
    ULONG type;
    ULONG pid;
    ULONGLONG gid;
    WCHAR path[MAX_FILE_NAME_LENGTH];

} COM_MESSAGE, *PCOM_MESSAGE;

enum FILE_CHANGE_INFO
{
    FILE_CHANGE_NOT_SET,
    FILE_OPEN_DIRECTORY,
    FILE_CHANGE_WRITE,
    FILE_CHANGE_NEW_FILE,
    FILE_CHANGE_RENAME_FILE,
    FILE_CHANGE_EXTENSION_CHANGED,
    FILE_CHANGE_DELETE_FILE,
    FILE_CHANGE_DELETE_NEW_FILE,
    FILE_CHANGE_OVERWRITE_FILE
};

enum FILE_LOCATION_INFO
{
    FILE_NOT_PROTECTED, // nothing to set, not protected
    FILE_PROTECTED,     // if not read remember change in file
    FILE_MOVED_IN,      // new file to remove from protected
    FILE_MOVED_OUT      // keep filename if not already exist
};

enum IRP_MAJOR_OP
{
    IRP_NONE,
    IRP_READ,
    IRP_WRITE,
    IRP_SETINFO,
    IRP_CREATE,
    IRP_CLEANUP,
};

// -64- bytes structure, fixed to -96- bytes, fixed to 104 bytes
typedef struct _DRIVER_MESSAGE
{
    WCHAR Extension[FILE_OBJEC_MAX_EXTENSION_SIZE + 1]; // null terminated 24 bytes

#ifdef _KERNEL_MODE
    FILE_ID_INFORMATION
    FileID; // 24 bytes - file id 128 bits and its volume serial number
#else
    FILE_ID_INFO
    FileID; // 24 bytes - file id 128 bits and its volume serial number
#endif

    ULONGLONG
    MemSizeUsed;            // for read and write, we follow buffer sizes 8 bytes
    DOUBLE Entropy;         // 8 bytes
    ULONG PID;              // 4 bytes
    UCHAR IRP_OP;           // 1 byte
    BOOLEAN isEntropyCalc;  // 1 byte
    UCHAR FileChange;       // 1 byte
    UCHAR FileLocationInfo; // 1 byte align
    UNICODE_STRING
    filePath;      // 16 bytes unicode string - filename, also contains size and max size, buffer is outside the struct
    ULONGLONG Gid; // 8 bytes process gid
    PVOID
    next; // 8 bytes - next PDRIVER_MESSAGE, we use it to allow adding the fileName to the same buffer, this pointer
    // should point to the next PDRIVER_MESSAGE in buffer (kernel handled)

} DRIVER_MESSAGE, *PDRIVER_MESSAGE;

// header for return buffer from driver on irp ops, has pointer to the first driver message, num ops in the buffer and
// readable data size in the buffer
typedef struct _RWD_REPLY_IRPS
{
    size_t dataSize; // 8 bytes
    PDRIVER_MESSAGE
    data; // 8 bytes points to the first IRP driver message, the next DRIVER_MESSAGE is a pointer inside DRIVER_MESSAGE
    ULONGLONG num_ops; // 8 bytes

    size_t size()
    {
        return dataSize + sizeof(_RWD_REPLY_IRPS);
    }

    size_t addSize(size_t size)
    {
        dataSize += size;
        return dataSize;
    }

    ULONGLONG addOp()
    {
        num_ops++;
        return num_ops;
    }

    ULONGLONG numOps()
    {
        return num_ops;
    }

    _RWD_REPLY_IRPS() : dataSize(sizeof(_RWD_REPLY_IRPS)), data(nullptr), num_ops(0)
    {
    }
} RWD_REPLY_IRPS, *PRWD_REPLY_IRPS;