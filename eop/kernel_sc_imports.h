struct mac_policy_conf {
    char* mpc_name;
    char* mpc_fullname;
    char** mpc_labelnames;
    unsigned int mpc_labelname_count;
    void* mpc_ops;
    int mpc_loadtime_flags;
    int* mpc_field_off;
    int mpc_runtime_flags;
    struct mac_policy_conf* mpc_list;
    void* mpc_data;
};
struct mac_policy_list_element {
    struct mac_policy_conf* mpc;
};
struct mac_policy_list {
    unsigned int numloaded;
    unsigned int max;
    unsigned int maxindex;
    unsigned int staticmax;
    unsigned int chunks;
    unsigned int freehint;
    struct mac_policy_list_element* entries;
};

#define FOR_EACH_KIMP(v) \
    FOR_EACH_KIMPDATA(v)\
    FOR_EACH_KIMPFUNC(v)

#define FOR_EACH_KIMPDATA(v) \
    v(char*, osversion)\
    v(char*, version)\
    v(void**, kernel_map)\
    v(struct mac_policy_list*, mac_policy_list)\
    v(unsigned long*, physmap_base)\
    v(void*, PE_state)

#define FOR_EACH_KIMPFUNC(v) \
    v(void*, kauth_cred_get_with_ref)\
    v(void*, kauth_cred_setresuid, void*, unsigned int, unsigned int, unsigned int, unsigned int)\
    v(void*, kauth_cred_setresgid, void*, unsigned int, unsigned int, unsigned int)\
    v(void*, current_proc)\
    v(void, mac_cred_label_init, void*)\
    v(void, mac_cred_label_destroy, void*)\
    v(char*, strcpy, char*, char*)\
    v(int, strcmp, char*, char*)\
    v(int, mac_policy_unregister, unsigned int)\
    v(int, printf, char*, ...)\
    v(int, mach_vm_protect, void*, unsigned long, unsigned long, int, int)\
    v(unsigned long, kvtophys, void*)\
    v(unsigned long, chgproccnt, unsigned int, int)

#define KIMP_TYPEDEF(typ, name) typedef typ __type_##name;
FOR_EACH_KIMPDATA(KIMP_TYPEDEF)
#undef KIMP_TYPEDEF
#define KIMP_TYPEDEF(ret, name, ...) typedef ret (*__type_##name)(__VA_ARGS__);
FOR_EACH_KIMPFUNC(KIMP_TYPEDEF)
#undef KIMP_TYPEDEF

#define KIMPENT_DEF(typ, name, ...) union {unsigned long val64_##name; __type_##name name;};
struct kimports {
    FOR_EACH_KIMP(KIMPENT_DEF)
};
