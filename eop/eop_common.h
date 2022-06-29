#ifndef __EOP_COMMON_H__
#define __EOP_COMMON_H__

#include <IOKit/IOKitLib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/port.h>
#include <sys/dtrace.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/sysctl.h>
#include <setjmp.h>

void exploit();

#endif
