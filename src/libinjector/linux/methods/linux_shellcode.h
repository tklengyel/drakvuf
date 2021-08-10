#ifndef LINUX_SHELLCODE_H
#define LINUX_SHELLCODE_H
#include "linux_utils.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
bool load_shellcode_from_file(injector_t injector, const char* file);
#endif
