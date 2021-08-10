#ifndef LINUX_SYSCALLS_H
#define LINUX_SYSCALLS_H

#include "linux_utils.h"

bool setup_mmap_syscall(injector_t injector, x86_registers_t* regs, size_t size);

#endif
