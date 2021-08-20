/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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
#include <fcntl.h>

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

    regs->rax = sys_mmap;

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

bool setup_open_syscall(injector_t injector, x86_registers_t* regs)
{
    // open(const char* file, int flags, int mode)
    struct argument args[3] = { {0} };
    init_string_argument(&args[0], injector->target_file);

    switch (injector->method)
    {
        case INJECT_METHOD_WRITE_FILE:
        {
            init_int_argument(&args[1], O_WRONLY|O_CREAT|O_TRUNC);
            break;
        }
        case INJECT_METHOD_READ_FILE:
        {
            init_int_argument(&args[1], O_RDONLY);
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    init_int_argument(&args[2], S_IRWXU | S_IRWXG | S_IRWXO);
    regs->rax = sys_open;

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

bool setup_close_syscall(injector_t injector, x86_registers_t* regs)
{
    struct argument args[1] = { {0} };
    init_int_argument(&args[0], injector->fd);

    regs->rax = sys_close;

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

bool setup_write_syscall(injector_t injector, x86_registers_t* regs, size_t amount)
{
    // write(unsigned int fd, const char *buf, size_t count);
    struct argument args[3] = { {0} };
    init_int_argument(&args[0], injector->fd);
    init_int_argument(&args[1], injector->virtual_memory_addr);
    init_int_argument(&args[2], amount);

    regs->rax = sys_write;

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

bool setup_read_syscall(injector_t injector, x86_registers_t* regs, size_t amount)
{
    // read(unsigned int fd, char *buf, size_t count);
    struct argument args[3] = { {0} };
    init_int_argument(&args[0], injector->fd);
    init_int_argument(&args[1], injector->virtual_memory_addr);
    init_int_argument(&args[2], amount);

    regs->rax = sys_read;

    return setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
}

bool call_close_syscall(injector_t injector, x86_registers_t* regs)
{
    if (!setup_close_syscall(injector, regs))
    {
        PRINT_DEBUG("Failed to setup close syscall\n");
        return false;
    }

    regs->rip = injector->syscall_addr;
    return true;
}

bool call_read_syscall(injector_t injector, x86_registers_t* regs, size_t amount)
{
    if (!setup_read_syscall(injector, regs, amount))
    {
        PRINT_DEBUG("Failed to setup close syscall\n");
        return false;
    }

    regs->rip = injector->syscall_addr;
    return true;
}

bool call_read_syscall_cb(injector_t injector, x86_registers_t* regs)
{
    if ( is_syscall_error(regs->rax) )
    {
        fprintf(stderr, "Could not read chunk from guest\n");
        return false;
    }

    injector->buffer.len = regs->rax;
    PRINT_DEBUG("Chunk read successful (%ld)\n", injector->buffer.len);

    return true;
}

bool call_open_syscall(injector_t injector, x86_registers_t* regs)
{
    if (!setup_open_syscall(injector, regs))
    {
        PRINT_DEBUG("Failed to setup open syscall\n");
        return false;
    }

    regs->rip = injector->syscall_addr;
    return true;
}

bool call_open_syscall_cb(injector_t injector, x86_registers_t* regs)
{
    if ( is_syscall_error(regs->rax) )
    {
        fprintf(stderr, "Could not open file in guest\n");
        return false;
    }

    injector->fd = regs->rax;
    PRINT_DEBUG("File descriptor: %ld\n", injector->fd);

    return true;
}

bool call_mmap_syscall(injector_t injector, x86_registers_t* regs, size_t size)
{
    if (!setup_mmap_syscall(injector, regs, size))
    {
        PRINT_DEBUG("Failed to setup mmap syscall");
        return false;
    }

    regs->rip = injector->syscall_addr;
    return true;
}

bool call_mmap_syscall_cb(injector_t injector, x86_registers_t* regs)
{
    if ( is_syscall_error(regs->rax) )
    {
        fprintf(stderr, "mmap syscall failed\n");
        return false;
    }

    // save it for future use
    injector->virtual_memory_addr = regs->rax;
    PRINT_DEBUG("memory address allocated using mmap: %lx\n", injector->virtual_memory_addr);

    return true;
}
