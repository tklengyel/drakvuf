#ifndef METHOD_HELPERS_H
#define METHOD_HELPERS_H

#include "win_utils.h"

bool setup_create_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
bool is_fun_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const char* err);

#endif
