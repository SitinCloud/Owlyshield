#pragma once

#include <fltKernel.h>
#include <math.h>

#include "KernelCommon.h"

// entropy between 0.0  to 8.0
_Kernel_float_used_ DOUBLE shannonEntropy(PUCHAR buffer, size_t size);