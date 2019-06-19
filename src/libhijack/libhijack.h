#include "../libdrakvuf/libdrakvuf.h"
#include "../libinjector/libinjector.h"



bool hijack(drakvuf_t drakvuf, vmi_pid_t hijack_pid,
                      char *hijack_function) ;

static event_response_t hijack_wait_for_kernel_cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info);

static bool setup_hijack_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr);

static event_response_t hijack_return_path(drakvuf_t drakvuf, drakvuf_trap_info_t *info);

static bool setup_message_box_stack(injector_t injector, drakvuf_trap_info_t *info);

