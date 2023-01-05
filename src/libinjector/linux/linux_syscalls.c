/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 * This file was created by Manorit Chawdhry.                              *
 * It is distributed as part of DRAKVUF under the same license             *
 ***************************************************************************/


#include "linux_syscalls.h"
#include <sys/mman.h>

bool init_syscalls(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t vdso = find_vdso(drakvuf, info);
    if (!vdso)
        return false;

    addr_t syscall_addr = find_syscall(drakvuf, info, vdso);
    if (!syscall_addr)
        return false;

    return setup_post_syscall_trap(drakvuf, info, syscall_addr);
}

bool setup_mmap_syscall(linux_injector_t injector, x86_registers_t* regs, size_t size)
{
    // mmap(NULL, size, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0)
    struct argument args[6] = { {0} };
    init_int_argument(&args[0], 0);
    init_int_argument(&args[1], size);
    init_int_argument(&args[2], PROT_EXEC|PROT_WRITE|PROT_READ);
    init_int_argument(&args[3], MAP_SHARED|MAP_ANONYMOUS|MAP_POPULATE);
    init_int_argument(&args[4], -1);
    init_int_argument(&args[5], 0);

    regs->rax = sys_mmap;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup mmap syscall\n");
        return false;
    }

    return true;

}

bool setup_open_syscall(linux_injector_t injector, x86_registers_t* regs, const char* target_file, int flags, int mode)
{
    // open(const char* file, int flags, int mode)
    struct argument args[3] = { {0} };

    init_string_argument(&args[0], target_file);
    init_int_argument(&args[1], flags);
    init_int_argument(&args[2], mode);

    regs->rax = sys_open;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup open syscall\n");
        return false;
    }
    return true;
}

bool setup_close_syscall(linux_injector_t injector, x86_registers_t* regs, int fd)
{
    struct argument args[1] = { {0} };
    init_int_argument(&args[0], fd);

    regs->rax = sys_close;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup close syscall\n");
        return false;
    }
    return true;
}

bool setup_write_syscall(linux_injector_t injector, x86_registers_t* regs, int fd, addr_t buffer_addr, size_t amount)
{
    // write(unsigned int fd, const char *buf, size_t count);
    struct argument args[3] = { {0} };
    init_int_argument(&args[0], fd);
    init_int_argument(&args[1], buffer_addr);
    init_int_argument(&args[2], amount);

    regs->rax = sys_write;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup write syscall\n");
        return false;
    }
    return true;
}

bool setup_read_syscall(linux_injector_t injector, x86_registers_t* regs, int fd, addr_t buffer_addr, size_t amount)
{
    // read(unsigned int fd, char *buf, size_t count);
    struct argument args[3] = { {0} };
    init_int_argument(&args[0], fd);
    init_int_argument(&args[1], buffer_addr);
    init_int_argument(&args[2], amount);

    regs->rax = sys_read;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup read syscall\n");
        return false;
    }
    return true;
}

bool setup_exit_syscall(linux_injector_t injector, x86_registers_t* regs, uint64_t rc)
{
    struct argument args[1] = { {0} };
    init_int_argument(&args[0], rc);

    regs->rax = sys_exit;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup exit syscall\n");
        return false;
    }
    return true;
}

void setup_vfork_syscall(linux_injector_t injector, x86_registers_t* regs, char* proc_name, vmi_pid_t parent_pid)
{
    regs->rax = sys_vfork;
    regs->rip = injector->syscall_addr;

    // set the ppid and name info for the child process
    // ( to be used in check_userspace_int3_trap )
    injector->child_data.name = proc_name;
    injector->child_data.ppid = parent_pid;

    // this will loosen the checks in check_userspace_int3_trap
    // till we get the pid of the child in the next step
    injector->fork = true;
}

static addr_t place_argv(linux_injector_t injector, x86_registers_t* regs, addr_t* data_addr, addr_t* array_addr)
{
    struct argument arg; // this will be passed in place_array_on_addr_64
    struct argument* argv = g_new0(struct argument, injector->args_count + 1);

    PRINT_DEBUG("Total arguments: %d\n", injector->args_count);

    init_string_argument(&argv[0], injector->host_file);
    PRINT_DEBUG("Args 0: %s\n", injector->host_file);

    for (int i=0; i<injector->args_count; i++)
    {
        init_string_argument(&argv[i+1], injector->args[i]);
        PRINT_DEBUG("Args %d: %s\n", i+1, injector->args[i]);
    }

    init_array_argument(&arg, argv, injector->args_count + 1);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);

    *array_addr = place_array_on_addr_64(vmi, regs, &arg, true, data_addr, array_addr);
    if (*array_addr == 0)
        goto err;

    g_free(argv);
    drakvuf_release_vmi(injector->drakvuf);
    return arg.data_on_stack;

err:
    fprintf(stderr, "Could not create argv arrays\n");
    g_free(argv);
    drakvuf_release_vmi(injector->drakvuf);
    return 0;
}

static addr_t place_environ(linux_injector_t injector, x86_registers_t* regs, GHashTable* environ, addr_t* data_addr, addr_t* array_addr)
{
    struct argument arg; // this will be passed in place_array_on_addr_64

    size_t envs_count = g_hash_table_size(environ);
    struct argument* envp = g_new0(struct argument, envs_count);
    // Allocate a NULL-terminated array of strings
    char** str_holder = g_new0(char*, envs_count + 1);

    GHashTableIter iter;
    gpointer key, value;

    int idx = 0;
    g_hash_table_iter_init(&iter, environ);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        gchar* str = str_holder[idx] = g_strdup_printf("%s=%s", (char*)key, (char*)value);
        PRINT_DEBUG("Envs %d: %s\n", idx + 1, str);
        init_string_argument(&envp[idx++], str);
    }

    init_array_argument(&arg, envp, envs_count);

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(injector->drakvuf);
    *array_addr = place_array_on_addr_64(vmi, regs, &arg, true, data_addr, array_addr);
    drakvuf_release_vmi(injector->drakvuf);

    g_strfreev(str_holder);
    g_free(envp);

    if (*array_addr == 0)
    {
        fprintf(stderr, "Could not create envp arrays\n");
        return 0;
    }

    return arg.data_on_stack;
}

static bool create_argv_and_envp_arrays(linux_injector_t injector, x86_registers_t* regs, GHashTable* environ, addr_t* argv_addr, addr_t* envp_addr)
{
    addr_t data_addr = injector->virtual_memory_addr + injector->virtual_memory_size;
    addr_t array_addr = injector->virtual_memory_addr + injector->virtual_memory_size/2;

    *argv_addr = place_argv(injector, regs, &data_addr, &array_addr);
    *envp_addr = place_environ(injector, regs, environ, &data_addr, &array_addr);

    return *argv_addr && *envp_addr;
}

bool setup_execve_syscall(linux_injector_t injector, x86_registers_t* regs, const char* binary_file, const GHashTable* environ)
{
    // execve(const char *filename, const char *const argv[], const char *const envp[])
    struct argument args[3] = { {0} };

    addr_t argv_addr, envp_addr;
    if (!create_argv_and_envp_arrays(injector, regs, (GHashTable*)environ, &argv_addr, &envp_addr))
    {
        PRINT_DEBUG("Failed to place execve syscall params\n");
        return false;
    }

    init_string_argument(&args[0], binary_file);
    init_int_argument(&args[1], argv_addr);
    init_int_argument(&args[2], envp_addr);

    regs->rax = sys_execve;
    regs->rip = injector->syscall_addr;

    if (!setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args)))
    {
        PRINT_DEBUG("Failed to setup execve syscall\n");
        return false;
    }

    // this will loosen the checks in check_userspace_int3_trap
    // if execve fails child process would hit BP with different RIP
    injector->execve = true;
    return true;
}

bool call_read_syscall_cb(linux_injector_t injector, x86_registers_t* regs)
{
    if (is_syscall_error(regs->rax, "Could not read chunk from guest"))
        return false;

    injector->buffer.len = regs->rax;
    PRINT_DEBUG("Chunk read successful (%ld)\n", injector->buffer.len);

    return true;
}

bool call_vfork_syscall_cb(linux_injector_t injector, x86_registers_t* regs, vmi_pid_t pid, uint32_t tid)
{
    if (is_syscall_error(regs->rax, "vfork syscall failed"))
        return false;

    injector->child_data.pid = pid;
    injector->child_data.tid = tid;

    PRINT_DEBUG("Child process pid: %d\n", injector->child_data.pid);
    return true;
}

bool call_write_syscall_cb(linux_injector_t injector, x86_registers_t* regs)
{
    if (is_syscall_error(regs->rax, "Could not write chunk to guest"))
        return false;

    PRINT_DEBUG("Chunk write successful (%ld/%ld)\n", injector->buffer.total_processed, injector->buffer.total_len);
    return true;
}

bool call_open_syscall_cb(linux_injector_t injector, x86_registers_t* regs)
{
    if (is_syscall_error(regs->rax, "Could not open file in guest"))
        return false;

    injector->fd = regs->rax;
    PRINT_DEBUG("File descriptor: %ld\n", injector->fd);

    return true;
}

bool call_mmap_syscall_cb(linux_injector_t injector, x86_registers_t* regs, size_t size)
{
    if (is_syscall_error(regs->rax, "mmap syscall failed"))
        return false;

    // save it for future use
    injector->virtual_memory_addr = regs->rax;
    injector->virtual_memory_size = size;
    PRINT_DEBUG("memory address allocated using mmap: %lx\n", injector->virtual_memory_addr);

    return true;
}
