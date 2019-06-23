#include<libdrakvuf/libdrakvuf.h>
#include<libinjector/libinjector.h>


struct hijacker {
    drakvuf_t drakvuf;
    vmi_pid_t target_pid;
    char *function_name;
    bool global_search;
    bool is32bit;
    x86_registers_t saved_regs;
    status_type_t status;
    addr_t exec_func;
    json_object* driver_rekall_profile_json;
    drakvuf_trap_t bp;
};
typedef struct hijacker* hijacker_t;

bool hijack_get_driver_function_rva(hijacker_t hijacker, char * function_name, addr_t *rva);

int hijack(drakvuf_t drakvuf, vmi_pid_t hijack_pid,
                      char *hijack_function, 
                      char *driver_rekall_profile) ;



