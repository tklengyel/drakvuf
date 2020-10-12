/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
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
 ***************************************************************************/

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <assert.h>
#include <string>
#include <vector>

#include "syscalls.h"
#include "private.h"
#include "linux.h"

// Builds the argument buffer from the current context, returns status
static std::vector<uint64_t> linux_build_argbuf(vmi_instance_t vmi,
        drakvuf_trap_info_t* info, syscalls* s,
        const syscall_t* sc,
        addr_t pt_regs_addr)
{
    std::vector<uint64_t> args;

    if (NULL == sc)
        return args;

    int nargs = sc->num_args;

    // get arguments only if we know how many to get
    if (0 == nargs)
        return args;

    // Now now, only support legacy syscall arg passing on 32 bit
    if ( 4 == s->reg_size )
    {
        if ( nargs > 0 )
            args.push_back(info->regs->rbx);
        if ( nargs > 1 )
            args.push_back(info->regs->rcx);
        if ( nargs > 2 )
            args.push_back(info->regs->rdx);
        if ( nargs > 3 )
            args.push_back(info->regs->rsi);
        if ( nargs > 4 )
            args.push_back(info->regs->rdi);
    }
    else if ( 8 == s->reg_size )
    {
        // Support both calling conventions for 64 bit Linux syscalls
        if (pt_regs_addr)
        {
            // The syscall args are passed via a struct pt_regs *, which is in %rdi upon entry
            size_t pt_regs[__PT_REGS_MAX] = {0};
            access_context_t ctx =
            {
                .translate_mechanism = VMI_TM_PROCESS_DTB,
                .dtb = info->regs->cr3
            };

            for ( int i=0; i<__PT_REGS_MAX; i++)
            {
                ctx.addr = pt_regs_addr + s->offsets[i];
                if ( VMI_FAILURE == vmi_read_64(vmi, &ctx, &pt_regs[i]) )
                {
                    fprintf(stderr, "vmi_read_va(%p) failed\n", (void*)ctx.addr);
                    return args;
                }
            }

            if ( nargs > 0 )
                args.push_back(pt_regs[PT_REGS_RDI]);
            if ( nargs > 1 )
                args.push_back(pt_regs[PT_REGS_RSI]);
            if ( nargs > 2 )
                args.push_back(pt_regs[PT_REGS_RDX]);
            if ( nargs > 3 )
                args.push_back(pt_regs[PT_REGS_RCX]);
            if ( nargs > 4 )
                args.push_back(pt_regs[PT_REGS_R8]);
            if ( nargs > 5 )
                args.push_back(pt_regs[PT_REGS_R9]);
        }
        else
        {
            // The args are passed directly via registers in sycall context
            if ( nargs > 0 )
                args.push_back(info->regs->rdi);
            if ( nargs > 1 )
                args.push_back(info->regs->rsi);
            if ( nargs > 2 )
                args.push_back(info->regs->rdx);
            if ( nargs > 3 )
                args.push_back(info->regs->rcx);
            if ( nargs > 4 )
                args.push_back(info->regs->r8);
            if ( nargs > 5 )
                args.push_back(info->regs->r9);
        }
    }

    return args;
}

static event_response_t linux_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    struct wrapper* w = (struct wrapper*)info->trap->data;

    if ( w->tid != info->proc_data.tid )
        return 0;

    syscalls* s = w->s;

    const syscall_t* sc = w->num < NUM_SYSCALLS_LINUX ? linuxsc::linux_syscalls[w->num] : NULL;

    std::vector<uint64_t> args;
    print_syscall(s, drakvuf, VMI_OS_LINUX, false, info, w->num, std::string(info->trap->breakpoint.module), sc, args, info->regs->rax, nullptr);

    drakvuf_remove_trap(drakvuf, info->trap, (drakvuf_trap_free_t)free_trap);
    s->traps = g_slist_remove(s->traps, info->trap);

    return 0;
}

static event_response_t linux_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto vmi = vmi_lock_guard(drakvuf);
    struct wrapper* w = (struct wrapper*)info->trap->data;
    syscalls* s = w->s;

    const syscall_t* sc = NULL;
    addr_t pt_regs = 0;

    addr_t ret = 0, nr = ~0;
    if ( VMI_GET_BIT(info->regs->rdi, 47) )
    {
        /*
         * On older kernels: __visible void do_syscall_64(struct pt_regs *regs)
         */
        pt_regs = info->regs->rdi;
        vmi_read_addr_va(vmi, pt_regs + s->offsets[PT_REGS_ORIG_RAX], 0, &nr);
    }
    else
    {
        /*
         * On newer kernels: __visible void do_syscall_64(unsigned long nr, struct pt_regs *regs)
         */
        nr = info->regs->rdi;
        pt_regs = info->regs->rsi;
    }

    vmi_read_addr_va(vmi, info->regs->rsp, 0, &ret);

    if ( nr<NUM_SYSCALLS_LINUX )
    {
        sc = linuxsc::linux_syscalls[nr];

        if ( s->filter && !g_hash_table_contains(s->filter, sc->name) )
            return 0;
    }

    auto args = linux_build_argbuf(vmi, info, s, sc, pt_regs);

    print_syscall(s, drakvuf, VMI_OS_LINUX, true, info, nr, std::string(info->trap->breakpoint.module), sc, args, 0, NULL);

    if ( s->disable_sysret )
        return 0;

    struct wrapper* wr = g_slice_new0(struct wrapper);
    wr->s = s;
    wr->num = nr;
    wr->tid = info->proc_data.tid;

    drakvuf_trap_t* ret_trap = g_slice_new0(drakvuf_trap_t);
    ret_trap->breakpoint.lookup_type = LOOKUP_DTB;
    ret_trap->breakpoint.dtb = info->regs->cr3;
    ret_trap->breakpoint.addr_type = ADDR_VA;
    ret_trap->breakpoint.addr = ret;
    ret_trap->breakpoint.module = "linux";
    ret_trap->type = BREAKPOINT;
    ret_trap->cb = linux_ret_cb;
    ret_trap->data = wr;

    if ( drakvuf_add_trap(drakvuf, ret_trap) )
        s->traps = g_slist_prepend(s->traps, ret_trap);
    else
    {
        g_slice_free(drakvuf_trap_t, ret_trap);
        g_slice_free(struct wrapper, w);
    }

    return 0;
}

void setup_linux(drakvuf_t drakvuf, syscalls* s)
{
    s->offsets = (size_t*)g_try_malloc0(__PT_REGS_MAX*sizeof(size_t));
    if ( !s->offsets )
        throw -1;

    for ( int i=0; i<__PT_REGS_MAX; i++ )
        if ( !drakvuf_get_kernel_struct_member_rva(drakvuf, "pt_regs", linux_pt_regs_names[i], &s->offsets[i]) )
            throw -1;

    addr_t _text;
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "_text", &_text) )
        throw -1;

    addr_t syscall64;
    if ( !drakvuf_get_kernel_symbol_rva(drakvuf, "do_syscall_64", &syscall64) )
        throw -1;

    addr_t kaslr = s->kernel_base - _text;

    drakvuf_trap_t* trap = g_slice_new0(drakvuf_trap_t);
    struct wrapper* w = g_slice_new0(struct wrapper);

    w->s = s;

    trap->breakpoint.lookup_type = LOOKUP_PID;
    trap->breakpoint.pid = 0;
    trap->breakpoint.addr_type = ADDR_VA;
    trap->breakpoint.addr = syscall64 + kaslr;
    trap->breakpoint.module = "linux";
    trap->type = BREAKPOINT;
    trap->cb = linux_cb;
    trap->data = w;

    if ( drakvuf_add_trap(drakvuf, trap) )
        s->traps = g_slist_prepend(s->traps, trap);
    else
    {
        free_trap(trap);
        throw -1;
    }
}
