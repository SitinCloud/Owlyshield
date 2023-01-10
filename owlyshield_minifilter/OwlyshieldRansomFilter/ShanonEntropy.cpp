#include "ShanonEntropy.h"

constexpr DOUBLE M_LOG2E = 1.4426950408889634;

constexpr ULONG MAX_BYTE_SIZE = 256;

_Kernel_float_used_ DOUBLE shannonEntropy(PUCHAR buffer, size_t size)
{
    if (IS_DEBUG_IRP)
        DbgPrint("!!! snFilter: Calc entropy started\n");
    DOUBLE entropy = 0.0;
    ULONG bucketByteVals[MAX_BYTE_SIZE] = {};
    for (ULONG i = 0; i < size; i++)
    {
        bucketByteVals[buffer[i]]++;
    }

    __try
    {
        for (ULONG i = 0; i < MAX_BYTE_SIZE; i++)
        {
            if (bucketByteVals[i] != 0)
            {
                DOUBLE
                val = (DOUBLE)bucketByteVals[i] / (DOUBLE)size;
                entropy += (-1) * val * log(val) * M_LOG2E;
            }
        }
    }
    __finally
    {
    }

    return entropy;
}