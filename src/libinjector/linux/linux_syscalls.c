#include "linux_syscalls.h"
#include <sys/mman.h>
#include <fcntl.h>

bool setup_mmap_syscall(injector_t injector, x86_registers_t* regs, size_t size)
{
    // mmap(NULL, size, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0)
    struct argument args[6] = { {0} };
    init_int_argument(&args[0], 0);
    init_int_argument(&args[1], size);
    init_int_argument(&args[2], PROT_EXEC|PROT_WRITE|PROT_READ);
    init_int_argument(&args[3], MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE);
    init_int_argument(&args[4], -1);
    init_int_argument(&args[5], 0);

    injector->syscall_no = sys_mmap;

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}
