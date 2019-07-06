#include<libdrakvuf/libdrakvuf.h>
#include<libinjector/libinjector.h>
#include<gmodule.h>

#ifdef __cplusplus
extern "C" {
#endif
struct hijacker {
    drakvuf_t drakvuf;
    vmi_pid_t target_pid;
    uint32_t target_tid;
    char *function_name;
    bool global_search;
    bool is32bit;
    status_type_t int3_status;
    status_type_t cr3_status;
    addr_t exec_func;
    json_object *driver_rekall_profile_json;
    json_object *args;
    drakvuf_trap_t bp;
    volatile  int *spin_lock;
    bool rc;
    x86_registers_t saved_regs;
};
typedef struct hijacker* hijacker_t;

bool hijack_get_driver_function_rva(hijacker_t hijacker, char * function_name, addr_t *rva);

bool setup_KeBugCheckEx_stack(hijacker_t hijacker, drakvuf_trap_info_t *info);

bool setup_add1_stack(hijacker_t hijacker, drakvuf_trap_info_t *info);

bool setup_stack_from_json(hijacker_t hijacker, drakvuf_trap_info_t *info);

int hijack(drakvuf_t drakvuf, vmi_pid_t hijack_pid,
                      uint32_t target_tid,
                      char *hijack_function, 
                      char *driver_rekall_profile,
                      char *lib_name,
                      json_object *args,
                      volatile int *spin_lock) ;

json_object *hijack_get_modules(json_object* candidates);
int hijack_get_num_modules(json_object *modules);

char * hijack_get_module_name(json_object* module);
char * hijack_get_module_rekall_profile(json_object *module);
json_object * hijack_get_functions(json_object *module);
int hijack_get_num_functions(json_object *module);

char * hijack_get_fucntion_name(json_object *function);
json_object * hijack_get_arguments(json_object *function);

int hijack_get_num_arguments(json_object *args);
char * hijack_get_argument_type(json_object *arg, int idx);


#ifdef __cplusplus
}
#endif

