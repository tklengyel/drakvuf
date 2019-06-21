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
};
typedef struct hijacker* hijacker_t;


int hijack(drakvuf_t drakvuf, vmi_pid_t hijack_pid,
                      char *hijack_function) ;



