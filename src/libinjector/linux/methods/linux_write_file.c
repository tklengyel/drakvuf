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


#include <libinjector/debug_helpers.h>

#include "linux_write_file.h"
#include "linux_syscalls.h"

static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool clear_trap);
static bool write_buffer_to_mmap_location(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

bool init_write_file_method(injector_t injector, const char* file)
{
    FILE* fp = fopen(file, "rb");
    if (!fp)
    {
        fprintf(stderr, "File (%s) not existing\n", file);
        return false;
    }

    fseek (fp, 0, SEEK_END);
    if ( (long int)(injector->buffer.total_len = ftell(fp)) < 0 )
    {
        PRINT_DEBUG("File size < 0\n");
        fclose(fp);
        return false;
    }
    rewind(fp);

    injector->buffer.data = g_malloc0(FILE_BUF_SIZE);

    PRINT_DEBUG("File init success\n");
    PRINT_DEBUG("Total File size: %ld\n", injector->buffer.total_len);

    injector->fp = fp;

    return true;
}

/* This function handles writing file to guest OS, it does that in total of 6 steps
 *
 * STEP1:
 * It finds the location of syscall present inside vdso, it is used for jumping
 * to syscall instruction, After that it calls mmap, mmap is used as a buffer for exchanging
 * data between the guest VM and the host OS. The initial trap must not be removed here,
 * it should be done in the last step as it will be used for cleanup
 *
 * STEP2:
 * Saves the mmap address and opens the file handle inside guest VM
 *
 * STEP3:
 * This step is the initialization before the while loop analogy, it will verify the file descriptor
 * and write the initial chunk, it first writes the buffer to mmap location and in write file syscall,
 * the mmap address is given for the pointer to buffer.
 *
 * STEP4:
 * We will reach this after the callback from STEP3, In the beginning of this step, we know that the previous
 * write is done. This is the step which will happen in loop, it reads the next chunk of file from the host OS,
 * if that is not empty, it executes similarly to STEP3 and writes that chunk to the file
 * but it overries the next step as this one only until the buffer read from host OS file is 0.
 * When it reaches zero, it closes the file handle inside the guest OS which tells us that the
 * write file operation is complete
 *
 * STEP5:
 * It restores the state of the VM
 *
 * STEP6:
 * It removes the initial trap and exits out of drakvuf loop
 */
event_response_t handle_write_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
                return cleanup(drakvuf, info, false); // STEP1 trap is being cleared in the last step

            addr_t syscall_addr = find_syscall(drakvuf, info, vdso);
            if (!syscall_addr)
                return cleanup(drakvuf, info, false);

            setup_post_syscall_trap(drakvuf, info, syscall_addr);
            // don't remove the initial trap
            // it is used for cleanup after restoring registers

            if (!setup_mmap_syscall(injector, info->regs, FILE_BUF_SIZE))
            {
                PRINT_DEBUG("Failed to setup mmap syscall");
                return cleanup(drakvuf, info, false);
            }

            info->regs->rip = injector->syscall_addr;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;

            break;
        }
        case STEP2: // open file handle
        {
            if ( is_syscall_error(info->regs->rax) )
            {
                fprintf(stderr, "mmap syscall failed\n");
                return cleanup(drakvuf, info, true);
            }
            PRINT_DEBUG("memory address allocated using mmap: %lx\n", info->regs->rax);

            // save it for future use
            injector->virtual_memory_addr = info->regs->rax;

            PRINT_DEBUG("Opening file descriptor\n");
            setup_open_syscall(injector, info->regs);

            info->regs->rip = injector->syscall_addr;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP3: // verify fd and write the first chunk
        {
            if ( is_syscall_error(info->regs->rax) )
            {
                fprintf(stderr, "File descriptor could not be opened\n");
                return cleanup(drakvuf, info, true);
            }

            injector->fd = info->regs->rax;
            PRINT_DEBUG("File descriptor: %ld\n", injector->fd);

            injector->buffer.len = fread(injector->buffer.data, 1, FILE_BUF_SIZE, injector->fp);
            injector->buffer.total_processed = injector->buffer.len;

            PRINT_DEBUG("Initial File chunk loaded (%ld/%ld)\n", injector->buffer.total_processed, injector->buffer.total_len);

            if (!setup_write_syscall(injector, info->regs, injector->buffer.len))
                PRINT_DEBUG("Failed to setup write syscall\n");

            if (!write_buffer_to_mmap_location(drakvuf, info))
                return cleanup(drakvuf, info, true);

            info->regs->rip = injector->syscall_addr;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP4: // loop till all chunks are written and then close the fd
        {
            if ( is_syscall_error(info->regs->rax) )
            {
                fprintf(stderr, "Could not write chunk to guest\n");
                return cleanup(drakvuf, info, true);
            }

            PRINT_DEBUG("Chunk write successful (%ld/%ld)\n", injector->buffer.total_processed, injector->buffer.total_len);

            injector->buffer.len = fread(injector->buffer.data, 1, FILE_BUF_SIZE, injector->fp);
            injector->buffer.total_processed += injector->buffer.len;

            if (!injector->buffer.len)
            {
                PRINT_DEBUG("Write file successful\n");

                if (!setup_close_syscall(injector, info->regs))
                {
                    PRINT_DEBUG("Failed to setup close syscall\n");
                    return cleanup(drakvuf, info, true);
                }
            }
            else
            {
                PRINT_DEBUG("Chunk read successful (%ld/%ld)\n", injector->buffer.total_processed, injector->buffer.total_len);

                if (!write_buffer_to_mmap_location(drakvuf, info))
                    return cleanup(drakvuf, info, true);

                if (!setup_write_syscall(injector, info->regs, injector->buffer.len))
                {
                    PRINT_DEBUG("Failed to setup write syscall\n");
                    return cleanup(drakvuf, info, true);
                }

                injector->step_override = true;
                injector->step = STEP4;
            }

            info->regs->rip = injector->syscall_addr;

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP5: // restore the registers
        {
            PRINT_DEBUG("Closed File descriptor\n");
            PRINT_DEBUG("Restoring state\n");
            free_bp_trap(drakvuf, injector, info->trap);

            // restore regs
            memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

            event = VMI_EVENT_RESPONSE_SET_REGISTERS;
            break;
        }
        case STEP6: // cleanup
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
    PRINT_DEBUG("Doing premature cleanup\n");
    injector_t injector = (injector_t)info->trap->data;

    // restore regs
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    if (clear_trap)
        free_bp_trap(drakvuf, injector, info->trap);

    // since we are jumping to some arbitrary step, we will set this
    injector->step_override = true;

    // give the last step for cleanup
    injector->step = STEP6;

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static bool write_buffer_to_mmap_location(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
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
        fprintf(stderr, "Could not write the buffer in mmap address\n");
        return false;
    }

    PRINT_DEBUG("Buffer written to mmap address\n");

    drakvuf_release_vmi(drakvuf);

    return true;

}
