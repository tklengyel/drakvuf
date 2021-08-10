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


#include "linux_shellcode.h"
#include "linux_debug.h"
#include "linux_syscalls.h"

static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool clear_trap);
static bool setup_mmap_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
static bool write_shellcode_to_mmap_location(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
bool load_shellcode_from_file(injector_t injector, const char* file);

/* This function handles the shellcode injection, it does so in total of 5 steps
 *
 * STEP1:
 * The job of this step is to find syscall instruction inside of vdso associated
 * with the process, we will be using this to call mmap by jumping to the syscall
 * after setting up the registers and trapping into the next instruction after syscall
 * we won't be removing the initial trap in this step as that can be used
 * for cleanup in the end i.e STEP5
 *
 * STEP2:
 * This is the trap that we are reaching after the mmap is successful,
 * now we can copy our shellcode to the mmapped location and jump to it,
 * we will trap the mmap location so that we can track the shellcode execution
 * and restore the state after it is done
 *
 * STEP3:
 * Since we just jumped to it and mmap location was trapped, we hit this, now we will
 * be saving rip on the stack as the user shellcode is being appended by ret internally
 * so that we come back to the same trap for furthur processing down the line
 *
 * STEP4:
 * We will reach this trap after the shellcode is executed and the ret at the end
 * of the shellcode is executed, since rip was saved, we will come back to the same mmap trap
 * and this will tell us that the shellcode has been successfully executed, now we will restore
 * the state of the process as it was before all the injection
 *
 * STEP5:
 * Now since we had kept the initial trap active in STEP1 and the registers are restored, we will hit
 * the initial rip trap now. This time we can remove the trap and interrupt the drakvuf loop so that the
 * injection can exit successfully, any failure step should just restore the registers
 * and set the injector->step as this step for cleanup;
 */
event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;

    event_response_t event;

    switch (injector->step)
    {
        case STEP1: // Finds vdso and sets up mmap
        {
            memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

            addr_t vdso = find_vdso(drakvuf, info);
            if (!vdso)
                return cleanup(drakvuf, info, false); // STEP1 trap is being cleared in STEP5

            addr_t syscall_addr = find_syscall(drakvuf, info, vdso);
            if (!syscall_addr)
                return cleanup(drakvuf, info, false);

            setup_post_syscall_trap(drakvuf, info, syscall_addr);
            // don't remove the initial trap
            // it is used for cleanup after restoring registers

            if (!setup_mmap_syscall(injector, info->regs, 4096))
            {
                fprintf(stderr, "Failed to setup mmap syscall");
                return cleanup(drakvuf, info, false);
            }

            info->regs->rip = syscall_addr;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;

            break;
        }
        case STEP2: // setup shellcode
        {
            if ( is_syscall_error(info->regs->rax) )
            {
                fprintf(stderr, "mmap syscall failed\n");
                return cleanup(drakvuf, info, true);
            }
            PRINT_DEBUG("memory address allocated using mmap: %lx\n", info->regs->rax);

            // save it for future use
            injector->virtual_memory_addr = info->regs->rax;

            if (!write_shellcode_to_mmap_location(drakvuf, info))
                return cleanup(drakvuf, info, true);

            setup_mmap_trap(drakvuf, info);
            info->regs->rip = injector->virtual_memory_addr;

            free_bp_trap(drakvuf, injector, info->trap);

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP3: //since mmap starting location is trapped, the first one will be this
        {
            PRINT_DEBUG("Shellcode begin\n");

            if (!save_rip_for_ret(drakvuf, info->regs))
                return cleanup(drakvuf, info, true);

            // rsp is being updated
            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP4: // shellcode should've executed and we will be returned to the same trap as ret is appended in the end
        {
            PRINT_DEBUG("Shellcode end\n");
            free_bp_trap(drakvuf, injector, info->trap);

            // restore regs
            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP5: // cleanup
        {
            PRINT_DEBUG("Removing traps and exiting\n");

            // remove the initial trap here
            free_bp_trap(drakvuf, injector, info->trap);
            drakvuf_interrupt(drakvuf, SIGINT);

            event = VMI_EVENT_RESPONSE_NONE;
            break;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    return event;
}

static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool clear_trap)
{
    fprintf(stderr, "Doing premature cleanup\n");
    injector_t injector = (injector_t)info->trap->data;

    // restore regs
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    if (clear_trap)
        free_bp_trap(drakvuf, injector, info->trap);

    // since we are jumping to some arbitrary step, we will set this
    injector->step_override = true;

    // give the last step
    injector->step = STEP5;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static bool setup_mmap_trap(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    injector->bp = g_try_malloc0(sizeof(drakvuf_trap_t));

    injector->bp->type = BREAKPOINT;
    injector->bp->name = "injector_mmap_trap";
    injector->bp->cb = injector_int3_userspace_cb;
    injector->bp->data = injector;
    injector->bp->breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp->breakpoint.dtb = info->regs->cr3;
    injector->bp->breakpoint.addr_type = ADDR_VA;
    injector->bp->breakpoint.addr = injector->virtual_memory_addr;
    injector->bp->ttl = UNLIMITED_TTL;
    injector->bp->ah_cb = NULL;

    if ( drakvuf_add_trap(drakvuf, injector->bp) )
    {
        PRINT_DEBUG("mmap trap successful\n");
        return true;
    }
    else
    {
        fprintf(stderr, "Couldn't trap mmap location\n");
        return false;
    }
}

static bool write_shellcode_to_mmap_location(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = (injector_t)info->trap->data;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->virtual_memory_addr
    );

    size_t bytes_write = 0;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    if ( vmi_write(vmi, &ctx, injector->buffer.len, injector->buffer.data, &bytes_write) != VMI_SUCCESS )
    {
        drakvuf_release_vmi(drakvuf);
        fprintf(stderr, "Could not write the shellcode in memory\n");
        return false;
    }

    PRINT_DEBUG("Shellcode write success in memory\n");
    print_hex(injector->buffer.data, injector->buffer.len, bytes_write);

    drakvuf_release_vmi(drakvuf);

    return true;
}

bool load_shellcode_from_file(injector_t injector, const char* file)
{
    FILE* fp = fopen(file, "rb");
    if (!fp)
    {
        fprintf(stderr, "Shellcode file (%s) not existing\n", file);
        return false;
    }

    fseek(fp, 0, SEEK_END);
    if ( (injector->buffer.len = ftell (fp)) < 0 )
    {
        fprintf(stderr, "ftell returned -1\n");
        fclose(fp);
        return false;
    }
    rewind(fp);

    // we are adding +1 as we will append ret instruction for restoring the state of the VM
    injector->buffer.data = g_try_malloc0(injector->buffer.len + 1);
    if ( !injector->buffer.data )
    {
        fprintf(stderr, "Could not malloc buffer for shellcode\n");
        fclose(fp);
        injector->buffer.len = 0;
        return false;
    }

    if ( (size_t)injector->buffer.len != fread(injector->buffer.data, 1, injector->buffer.len, fp))
    {
        fprintf(stderr, "Could not read full shellcode from file\n");
        g_free(injector->buffer.data);
        injector->buffer.data = NULL;
        injector->buffer.len = 0;
        fclose(fp);
        return false;
    }
    *(char*)(injector->buffer.data + injector->buffer.len ) = 0xc3;  //ret
    injector->buffer.len += 1;

    PRINT_DEBUG("Shellcode loaded to injector->buffer\n");
    print_hex(injector->buffer.data, injector->buffer.len, -1);

    fclose(fp);

    return true;
}
