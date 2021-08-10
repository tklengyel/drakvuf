#ifndef LINUX_DEBUG_H
#define LINUX_DEBUG_H

#include "linux_utils.h"

void print_hex(char* shellcode, int len, int bytes_write_read);
void print_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
void print_registers(drakvuf_trap_info_t* info);

#endif
