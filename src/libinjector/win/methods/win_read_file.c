/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
 *                                                                         *
 * DRAKVUF (C) 2014-2022 Tamas K Lengyel.                                  *
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
***************************************************************************/

#include "win_read_file.h"
#include "win_functions.h"
#include <libinjector/win/method_helpers.h>

static bool process_read_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* num_bytes);
static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

event_response_t handle_readfile_x64(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;
    base_injector_t base_injector = &injector->base_injector;

    switch (base_injector->step)
    {
        case STEP1: // allocate virtual memory
        {
            // save registers
            PRINT_DEBUG("Saving registers\n");
            memcpy_s(&injector->x86_saved_regs, sizeof(injector->x86_saved_regs), info->regs, sizeof(x86_registers_t));

            if (!setup_virtual_alloc_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup virtual alloc for passing inputs!\n");
                return cleanup(drakvuf, info);
            }

            info->regs->rip = injector->exec_func;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP2: // write payload to virtual memory
        {
            // any error checks?
            PRINT_DEBUG("Writing to allocated virtual memory to allocate physical memory..\n");
            injector->payload_addr = info->regs->rax;
            PRINT_DEBUG("Payload is at: 0x%lx\n", injector->payload_addr);

            if (!setup_memset_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup memset stack for passing inputs!\n");
                return cleanup(drakvuf, info);
            }

            info->regs->rip = injector->memset;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP3: // expand env in memory
        {
            PRINT_DEBUG("Expanding shell...\n");
            if (!setup_expand_env_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return cleanup(drakvuf, info);
            }

            info->regs->rip = injector->expand_env;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP4: // open file handle
        {
            if (!info->regs->rax)
            {
                PRINT_DEBUG("Failed to expand environment variables!\n");
                return cleanup(drakvuf, info);
            }
            PRINT_DEBUG("Env expand status: %lx\n", info->regs->rax);

            if (info->regs->rax * 2 > FILE_BUF_SIZE)
            {
                PRINT_DEBUG("Env expand reported more than the buffer can carry.\n");
                return cleanup(drakvuf, info);
            }

            if (!setup_create_file(drakvuf, info))
                return cleanup(drakvuf, info);

            info->regs->rip = injector->create_file;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP5: // verify file handle and open host file
        {
            PRINT_DEBUG("File create result %lx\n", info->regs->rax);

            if (is_fun_error(drakvuf, info, "Couldn't open guest file"))
                return cleanup(drakvuf, info);

            injector->file_handle = info->regs->rax;

            if (!open_host_file(injector, "wb"))
                return cleanup(drakvuf, info);

            PRINT_DEBUG("Reading file...\n");

            if (!setup_read_file_stack(injector, info->regs))
            {
                PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                return 0;
            }

            info->regs->rip = injector->read_file;
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP6: // read chunk from guest and write to host
        {
            PRINT_DEBUG("File read result: %lx\n", info->regs->rax);

            if (is_fun_error(drakvuf, info, "Failed to read guest file"))
                return cleanup(drakvuf, info);

            uint32_t num_bytes;

            if (!process_read_file(drakvuf, info, &num_bytes))
                return cleanup(drakvuf, info);

            if (num_bytes != 0)
            {
                PRINT_DEBUG("Reading next chunk\n");
                if (!setup_read_file_stack(injector, info->regs))
                {
                    PRINT_DEBUG("Failed to setup stack for passing inputs!\n");
                    return cleanup(drakvuf, info);
                }

                info->regs->rip = injector->read_file;
                return override_step(base_injector, STEP6, VMI_EVENT_RESPONSE_SET_REGISTERS);
            }
            else
            {
                PRINT_DEBUG("Finishing\n");

                if (!setup_close_handle_stack(injector, info->regs))
                {
                    PRINT_DEBUG("Failed to setup stack for closing handle\n");
                    return cleanup(drakvuf, info);
                }
                info->regs->rip = injector->close_handle;
            }

            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        case STEP7: // close file handle
        {
            PRINT_DEBUG("Close handle RAX: 0x%lx\n", info->regs->rax);
            fclose(injector->host_file);

            if (is_fun_error(drakvuf, info, "Could not close File handle"))
                return cleanup(drakvuf, info);

            PRINT_DEBUG("File operation executed OK\n");
            injector->rc = INJECTOR_SUCCEEDED;

            drakvuf_remove_trap(drakvuf, info->trap, NULL);
            drakvuf_interrupt(drakvuf, SIGINT);

            memcpy_s(info->regs, sizeof(*info->regs), &injector->x86_saved_regs, sizeof(x86_registers_t));
            return VMI_EVENT_RESPONSE_SET_REGISTERS;
        }
        default:
        {
            PRINT_DEBUG("Should not be here\n");
            assert(false);
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t cleanup(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("Exiting prematurely\n");

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

    memcpy_s(info->regs, sizeof(*info->regs), &injector->x86_saved_regs, sizeof(x86_registers_t));
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static bool process_read_file(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* num_bytes)
{
    injector_t injector = (injector_t)info->trap->data;
    uint8_t buf[FILE_BUF_SIZE];

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = injector->payload_addr
    );

    PRINT_DEBUG("Reading Payload chunk\n");
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, FILE_BUF_SIZE, buf, NULL));
    drakvuf_release_vmi(drakvuf);

    if (!success)
    {
        PRINT_DEBUG("Failed to read payload chunk!\n");
        return 0;
    }

    *num_bytes = *(uint32_t*)buf;

    if (*num_bytes > FILE_BUF_SIZE)
    {
        *num_bytes = FILE_BUF_SIZE;
        PRINT_DEBUG("Number of bytes read by ReadFile is greater than the buffer size, truncating.\n");
    }

    fwrite(buf + FILE_BUF_RESERVED, *num_bytes, 1, injector->host_file);

    return true;
}
