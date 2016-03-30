/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF Dynamic Malware Analysis System (C) 2014-2015 Tamas K Lengyel.  *
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

#include <libvmi/libvmi.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <glib.h>

#include "vmi.h"

typedef enum dispatcher_object {
    DISPATCHER_PROCESS_OBJECT = 3,
    DISPATCHER_THREAD_OBJECT  = 6
} dispatcher_object_t ;


addr_t drakvuf_get_current_thread(drakvuf_t drakvuf, uint64_t vcpu_id, x86_registers_t *regs){
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t thread;
    addr_t prcb;
    reg_t fsgs;

    /*
     * fs_base/gs_base in the info->regs structure are not actually filled in
     * by Xen for vm_events, so we need to manually ask for these each time
     */
    if(vmi_get_page_mode(vmi) == VMI_PM_IA32E)  {
        if (!regs->gs_base)
            vmi_get_vcpureg(vmi, &fsgs, GS_BASE, vcpu_id);
        else
            fsgs = regs->gs_base;

        prcb=offsets[KPCR_PRCB];
    } else {
        if (!regs->fs_base)
            vmi_get_vcpureg(vmi, &fsgs, FS_BASE, vcpu_id);
        else
            fsgs = regs->fs_base;

        prcb=offsets[KPCR_PRCBDATA];
    }

    if (VMI_SUCCESS != vmi_read_addr_va(vmi, fsgs + prcb + offsets[KPRCB_CURRENTTHREAD], 0, &thread)){
        return 0;
    }

    return thread;
}

addr_t drakvuf_get_current_process(drakvuf_t drakvuf, uint64_t vcpu_id, x86_registers_t *regs) {
    addr_t thread, process;

    thread=drakvuf_get_current_thread(drakvuf,vcpu_id,regs);

    if (thread == 0 || VMI_SUCCESS != vmi_read_addr_va(drakvuf->vmi, thread + offsets[KTHREAD_PROCESS], 0, &process)){
        return 0;
    }

    return process;
}

char *drakvuf_get_process_name(drakvuf_t drakvuf, addr_t eprocess_base) {
    return vmi_read_str_va(drakvuf->vmi, eprocess_base + offsets[EPROCESS_PNAME], 0);
}

char *drakvuf_get_current_process_name(drakvuf_t drakvuf, uint64_t vcpu_id, x86_registers_t *regs) {
    return drakvuf_get_process_name(drakvuf, drakvuf_get_current_process(drakvuf, vcpu_id, regs));
}

/////////////////////////////////////////////////////////////////////////////////////////////


bool drakvuf_get_current_thread_id( drakvuf_t drakvuf, uint64_t vcpu_id, x86_registers_t *regs,
                                    uint32_t *thread_id )
{
    addr_t p_tid ;
    addr_t ethread = drakvuf_get_current_thread( drakvuf, vcpu_id, regs );

    if ( ethread )
    {
        if ( vmi_read_addr_va( drakvuf->vmi, ethread + offsets[ ETHREAD_CID ] + offsets[ CLIENT_ID_UNIQUETHREAD ],
                               0,
                               &p_tid ) == VMI_SUCCESS )
        {
            *thread_id = p_tid;

            return true;
        }
    }

    return false ;
}


/////////////////////////////////////////////////////////////////////////////////////////////

// Microsoft PreviousMode KTHREAD explanation:
// https://msdn.microsoft.com/en-us/library/windows/hardware/ff559860(v=vs.85).aspx

bool drakvuf_get_thread_previous_mode( drakvuf_t drakvuf, addr_t kthread, privilege_mode_t *previous_mode )
{
    if ( kthread )
    {
        if ( vmi_read_8_va( drakvuf->vmi, kthread + offsets[ KTHREAD_PREVIOUSMODE ], 0,
                            (uint8_t *)previous_mode ) == VMI_SUCCESS )
        {
            if ( ( *previous_mode == KERNEL_MODE ) || ( *previous_mode == USER_MODE ) )
                return true ;
        }
    }

    return false ;
}

bool drakvuf_get_current_thread_previous_mode( drakvuf_t drakvuf, drakvuf_trap_info_t *info, 
                                               privilege_mode_t *previous_mode )
{
    addr_t kthread = drakvuf_get_current_thread( drakvuf, info->vcpu, info->regs );

    return drakvuf_get_thread_previous_mode( drakvuf, kthread, previous_mode );
}


/////////////////////////////////////////////////////////////////////////////////////////////


bool drakvuf_is_ethread( drakvuf_t drakvuf, drakvuf_trap_info_t *info, addr_t ethread_addr )
{
    dispatcher_object_t dispatcher_type ;
    access_context_t ctx = {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
    };

    ctx.addr = ethread_addr + offsets[ ETHREAD_TCB ] + offsets[ KTHREAD_HEADER ]
                            + offsets[ DISPATCHER_TYPE ] ;

    if ( vmi_read_8( drakvuf->vmi, &ctx, (uint8_t *)&dispatcher_type ) == VMI_SUCCESS )
    {
        if ( dispatcher_type == DISPATCHER_THREAD_OBJECT )
            return true ;
    }

    return false ;
}


/////////////////////////////////////////////////////////////////////////////////////////////


bool drakvuf_is_eprocess( drakvuf_t drakvuf, drakvuf_trap_info_t *info, addr_t eprocess_addr )
{
    dispatcher_object_t dispatcher_type ;
    access_context_t ctx = {
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
    };

    ctx.addr = eprocess_addr + offsets[ EPROCESS_PCB ] + offsets[ KPROCESS_HEADER ]
                             + offsets[ DISPATCHER_TYPE ] ;

    if ( vmi_read_8( drakvuf->vmi, &ctx, (uint8_t *)&dispatcher_type ) == VMI_SUCCESS )
    {
        if ( dispatcher_type == DISPATCHER_PROCESS_OBJECT )
            return true ;
    }

    return false ;
}

bool drakvuf_get_module_list(drakvuf_t drakvuf, addr_t eprocess_base, addr_t *module_list) {

    vmi_instance_t vmi = drakvuf->vmi;
    vmi_pid_t pid;
    addr_t peb, ldr, modlist;

    if(!eprocess_base)
        return false;

    if(VMI_FAILURE == vmi_read_32_va(vmi, eprocess_base + offsets[EPROCESS_PID], 0, (uint32_t*)&pid))
        return false;

    if(VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + offsets[EPROCESS_PEB], 0, &peb))
        return false;

    if(VMI_FAILURE == vmi_read_addr_va(vmi, peb + offsets[PEB_LDR], pid, &ldr))
        return false;

    if(VMI_FAILURE == vmi_read_addr_va(vmi, ldr + offsets[PEB_LDR_DATA_INLOADORDERMODULELIST], pid, &modlist))
        return false;

    *module_list = modlist;

    return true;
}

bool drakvuf_find_eprocess(drakvuf_t drakvuf, vmi_pid_t find_pid, const char *find_procname, addr_t *eprocess_addr) {
    addr_t current_process = 0, next_list_entry = 0;
    vmi_instance_t vmi = drakvuf->vmi;
    vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);

    addr_t list_head = current_process + offsets[EPROCESS_TASKS];
    addr_t current_list_entry = list_head;

    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0,
                                       &next_list_entry);
    if (status == VMI_FAILURE) {
        PRINT_DEBUG(
                "Failed to read next pointer at 0x%"PRIx64" before entering loop\n",
                current_list_entry);
        return false;
    }

    do {
        vmi_pid_t pid = ~0;
        vmi_read_32_va(vmi, current_process + offsets[EPROCESS_PID], 0, (uint32_t*)&pid);
        char *procname = vmi_read_str_va(vmi, current_process + offsets[EPROCESS_PNAME], 0);

        if((pid != ~0 && find_pid != ~0 && pid == find_pid) || (find_procname && procname && !strcmp(procname, find_procname))) {
            *eprocess_addr = current_list_entry - offsets[EPROCESS_TASKS];
            free(procname);
            return true;
        }

        free(procname);

        current_list_entry = next_list_entry;
        status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
        if (status == VMI_FAILURE) {
            PRINT_DEBUG("Failed to read next pointer in loop at %"PRIx64"\n",
                    current_list_entry);
            return false;
        }

    } while (next_list_entry != list_head);

    return false;
}
