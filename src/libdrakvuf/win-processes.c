/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2019 Tamas K Lengyel.                                  *
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
#include <limits.h>

#include "private.h"
#include "win-offsets.h"
#include "win-wow-offsets.h"
#include "win-error-codes.h"
#include "win.h"

#define MMVAD_MAX_DEPTH (100)

#define POOL_TAG_VAD    (0x20646156) // daV
#define POOL_TAG_VADL   (0x6c646156) // ldaV
#define POOL_TAG_VADM   (0x6d646156) // mdaV

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3
#define RTL_BALANCED_NODE_GET_PARENT_POINTER(Node) \
     ((PRTL_BALANCED_NODE)((Node)->ParentValue & \
                           ~RTL_BALANCED_NODE_RESERVED_PARENT_MASK))

typedef enum dispatcher_object
{
    __DISPATCHER_INVALID_OBJECT = 0,
    DISPATCHER_PROCESS_OBJECT = 3,
    DISPATCHER_THREAD_OBJECT  = 6
} dispatcher_object_t ;

bool win_search_modules( drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx, addr_t eprocess_addr, addr_t wow_process, vmi_pid_t pid, access_context_t* ctx );
bool win_search_modules_wow( drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx, addr_t eprocess_addr, addr_t wow_peb, vmi_pid_t pid, access_context_t* ctx );

addr_t win_get_current_thread(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t thread = 0;
    addr_t prcb = 0;
    addr_t kpcr = 0;

    // TODO: check whether we could use ss_arbytes here
    unsigned int cpl = info->regs->cs_sel & 3;

    if (VMI_PM_IA32E == drakvuf->pm)
    {
        prcb = drakvuf->offsets[KPCR_PRCB];
        if ( cpl )
        {
            // TODO: Xen 4.13 will have the correct value in the info->regs->shadow_gs
            if (VMI_FAILURE == vmi_get_vcpureg(vmi, &kpcr, SHADOW_GS, info->vcpu))
                return 0;
        }
        else
            kpcr = info->regs->gs_base;
    }
    else
    {
        /*
         * "In 32-bit Windows, entering kernel mode gets fs loaded with a GDT selector (0x0030)
         * for a segment whose base address is that of the processor’s KPCR."
         * https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/kpcr.htm
         * https://wiki.osdev.org/Global_Descriptor_Table
         */
        if ( cpl )
        {
            addr_t gdt;

            // TODO: Xen 4.13 will have the value delivered in the info->regs->gdtr_base
            if (VMI_FAILURE == vmi_get_vcpureg(vmi, &gdt, GDTR_BASE, info->vcpu))
                return 0;

            uint16_t fs_low = 0;
            uint8_t fs_mid = 0, fs_high = 0;

            if (VMI_FAILURE == vmi_read_16_va(vmi, gdt + 0x32, 0, &fs_low))
                return 0;
            if (VMI_FAILURE == vmi_read_8_va(vmi, gdt + 0x34, 0, &fs_mid))
                return 0;
            if (VMI_FAILURE == vmi_read_8_va(vmi, gdt + 0x37, 0, &fs_high))
                return 0;

            kpcr = ((uint32_t)fs_low) | ((uint32_t)fs_mid) << 16 | ((uint32_t)fs_high) << 24;
        }
        else
            kpcr = info->regs->fs_base;

        prcb = drakvuf->offsets[KPCR_PRCBDATA];
    }

    if (VMI_SUCCESS != vmi_read_addr_va(vmi, kpcr + prcb + drakvuf->offsets[KPRCB_CURRENTTHREAD], 0, &thread))
    {
        return 0;
    }

    return thread;
}

addr_t win_get_current_process(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    addr_t thread;
    addr_t process;

    thread=win_get_current_thread(drakvuf, info);

    if (thread == 0 || VMI_SUCCESS != vmi_read_addr_va(drakvuf->vmi, thread + drakvuf->offsets[KTHREAD_PROCESS], 0, &process))
    {
        return 0;
    }

    return process;
}

bool win_get_last_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* err, const char** err_str)
{
    if (!err || !err_str)
        return false;

    vmi_instance_t vmi = drakvuf->vmi;

    addr_t eprocess = win_get_current_process(drakvuf, info);
    addr_t cr3 = 0;
    vmi_pid_t pid = 0;
    if (eprocess && win_get_process_pid(drakvuf, eprocess, &pid))
        if (VMI_SUCCESS != vmi_pid_to_dtb(vmi, pid, &cr3))
            return false;

    addr_t kthread = win_get_current_thread(drakvuf, info);
    if (!kthread)
        return false;

    addr_t teb = 0;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, kthread + drakvuf->offsets[KTHREAD_TEB], 0, &teb))
        return false;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = cr3;
    ctx.addr = teb + drakvuf->offsets[TEB_LASTERRORVALUE];

    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, err))
        return false;

    if (*err >= __WIN_ERROR_CODES_MAX)
        return false;

    if (win_error_code_names[*err])
        *err_str = win_error_code_names[*err];

    return true;
}

static unicode_string_t* win_get_process_full_name(drakvuf_t drakvuf, addr_t eprocess_base)
{
    addr_t image_file_name_addr;
    if ( vmi_read_addr_va(drakvuf->vmi,
                          eprocess_base + drakvuf->offsets[EPROCESS_PROCCREATIONINFO] + drakvuf->offsets[PROCCREATIONINFO_IMAGEFILENAME],
                          0, &image_file_name_addr) != VMI_SUCCESS )
    {
        PRINT_DEBUG("in win_get_process_full_name(...) couldn't read IMAGEFILENAME address\n");
        return NULL;
    }

    return drakvuf_read_unicode_va(drakvuf->vmi,
                                   image_file_name_addr + drakvuf->offsets[OBJECTNAMEINFORMATION_NAME], 0);
}

char* win_get_process_name(drakvuf_t drakvuf, addr_t eprocess_base, bool fullpath)
{
    if ( fullpath )
    {
        unicode_string_t* fullname = win_get_process_full_name( drakvuf, eprocess_base );

        if (fullname && fullname->contents && strlen((const char*)fullname->contents) > 0)
        {
            // Replace 'proc_data->name' with 'fullname->contents'
            // Moving ownership of fullname->contents to name for later cleanup
            char* name = (char*)fullname->contents;
            g_free( (gpointer)fullname );
            return name;
        }

        if (fullname)
            vmi_free_unicode_str(fullname);
    }

    return vmi_read_str_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PNAME], 0);
}

char* win_get_process_commandline(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t eprocess_base)
{
    vmi_instance_t vmi = drakvuf->vmi;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;

    addr_t peb = 0;
    ctx.addr = eprocess_base + drakvuf->offsets[EPROCESS_PEB];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &peb))
        return NULL;

    addr_t proc_params = 0;
    ctx.addr = peb + drakvuf->offsets[PEB_PROCESSPARAMETERS];
    if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &proc_params))
        return NULL;

    addr_t cmdline_va = proc_params + drakvuf->offsets[RTL_USER_PROCESS_PARAMETERS_COMMANDLINE];

    unicode_string_t* cmdline_us = drakvuf_read_unicode(drakvuf, info, cmdline_va);
    if (!cmdline_us)
        return NULL;

    char* cmdline = (char*)cmdline_us->contents;
    g_free( (gpointer)cmdline_us );

    return cmdline;
}

bool win_get_process_pid(drakvuf_t drakvuf, addr_t eprocess_base, vmi_pid_t* pid)
{

    if ( VMI_SUCCESS == vmi_read_32_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PID], 0, (uint32_t*)pid) )
        return true;

    return false;
}

char* win_get_current_process_name(drakvuf_t drakvuf, drakvuf_trap_info_t* info, bool fullpath)
{
    return win_get_process_name(drakvuf, win_get_current_process(drakvuf, info), fullpath);
}

int64_t win_get_process_userid(drakvuf_t drakvuf, addr_t eprocess_base)
{

    addr_t peb;
    addr_t userid;
    vmi_instance_t vmi = drakvuf->vmi;
    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;

    if (!eprocess_base)
        return -1;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + drakvuf->offsets[EPROCESS_PEB], 0, &peb))
        return -1;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + drakvuf->offsets[EPROCESS_PDBASE], 0, &ctx.dtb))
        return -1;

    ctx.addr = peb + drakvuf->offsets[PEB_SESSIONID];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &userid) )
        return -1;

    /* It should be safe to stash userid into a int64_t as it seldom goes above INT_MAX */
    if ( userid > INT_MAX )
        PRINT_DEBUG("The process at 0x%" PRIx64 " has a userid larger then INT_MAX!\n", eprocess_base);

    return (int64_t)userid;
};

int64_t win_get_current_process_userid(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    return win_get_process_userid(drakvuf, win_get_current_process(drakvuf, info));
}

/////////////////////////////////////////////////////////////////////////////////////////////


bool win_get_current_thread_id(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* thread_id)
{
    addr_t p_tid ;
    addr_t ethread = win_get_current_thread(drakvuf, info);

    if ( ethread )
    {
        if ( vmi_read_addr_va( drakvuf->vmi, ethread + drakvuf->offsets[ ETHREAD_CID ] + drakvuf->offsets[ CLIENT_ID_UNIQUETHREAD ],
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

bool win_get_thread_previous_mode( drakvuf_t drakvuf, addr_t kthread, privilege_mode_t* previous_mode )
{
    if ( kthread )
    {
        if ( vmi_read_8_va( drakvuf->vmi, kthread + drakvuf->offsets[ KTHREAD_PREVIOUSMODE ], 0,
                            (uint8_t*)previous_mode ) == VMI_SUCCESS )
        {
            if ( ( *previous_mode == KERNEL_MODE ) || ( *previous_mode == USER_MODE ) )
                return true ;
        }
    }

    return false ;
}

bool win_get_current_thread_previous_mode(drakvuf_t drakvuf,
        drakvuf_trap_info_t* info,
        privilege_mode_t* previous_mode )
{
    addr_t kthread = win_get_current_thread(drakvuf, info);

    return win_get_thread_previous_mode(drakvuf, kthread, previous_mode);
}


/////////////////////////////////////////////////////////////////////////////////////////////


bool win_is_ethread( drakvuf_t drakvuf, addr_t dtb, addr_t ethread_addr )
{
    dispatcher_object_t dispatcher_type = __DISPATCHER_INVALID_OBJECT;
    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = dtb;

    ctx.addr = ethread_addr + drakvuf->offsets[ ETHREAD_TCB ] + drakvuf->offsets[ KTHREAD_HEADER ]
               + drakvuf->offsets[ DISPATCHER_TYPE ] ;

    if ( vmi_read_8( drakvuf->vmi, &ctx, (uint8_t*)&dispatcher_type ) == VMI_SUCCESS )
    {
        if ( dispatcher_type == DISPATCHER_THREAD_OBJECT )
            return true ;
    }

    return false ;
}


/////////////////////////////////////////////////////////////////////////////////////////////


bool win_is_eprocess( drakvuf_t drakvuf, addr_t dtb, addr_t eprocess_addr )
{
    dispatcher_object_t dispatcher_type = __DISPATCHER_INVALID_OBJECT;
    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = dtb;
    ctx.addr = eprocess_addr + drakvuf->offsets[ EPROCESS_PCB ] + drakvuf->offsets[ KPROCESS_HEADER ]
               + drakvuf->offsets[ DISPATCHER_TYPE ] ;

    if ( vmi_read_8( drakvuf->vmi, &ctx, (uint8_t*)&dispatcher_type ) == VMI_SUCCESS )
    {
        if ( dispatcher_type == DISPATCHER_PROCESS_OBJECT )
            return true ;
    }

    return false ;
}

bool win_get_module_list(drakvuf_t drakvuf, addr_t eprocess_base, addr_t* module_list)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t peb=0;
    addr_t ldr=0;
    addr_t modlist=0;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;

    if (!eprocess_base)
        return false;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + drakvuf->offsets[EPROCESS_PDBASE], 0, &ctx.dtb))
        return false;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + drakvuf->offsets[EPROCESS_PEB], 0, &peb))
        return false;

    ctx.addr = peb + drakvuf->offsets[PEB_LDR];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &ldr))
        return false;

    ctx.addr = ldr + drakvuf->offsets[PEB_LDR_DATA_INLOADORDERMODULELIST];
    if (VMI_FAILURE == vmi_read_addr(vmi, &ctx, &modlist))
        return false;

    if (!modlist)
        return false;

    *module_list = modlist;

    return true;
}

bool win_get_module_list_wow( drakvuf_t drakvuf, access_context_t* ctx, addr_t wow_peb, addr_t* module_list )
{
    if ( wow_peb && drakvuf->wow_offsets)
    {
        vmi_instance_t vmi = drakvuf->vmi;
        addr_t ldr=0;
        addr_t modlist=0;

        ctx->addr = wow_peb + drakvuf->wow_offsets[WOW_PEB_LDR];

        if (VMI_FAILURE == vmi_read_32( vmi, ctx, (uint32_t*)&ldr ) )
            return false;

        ctx->addr = ldr + drakvuf->wow_offsets[WOW_PEB_LDR_DATA_INLOADORDERMODULELIST];

        if (VMI_FAILURE == vmi_read_32( vmi, ctx, (uint32_t*)&modlist ) )
            return false;

        if (!modlist)
            return false;

        *module_list = modlist;

        return true;
    }

    return false ;
}


static bool win_find_process_list(drakvuf_t drakvuf, addr_t* list_head)
{
    vmi_instance_t vmi = drakvuf->vmi;

    addr_t current_process;
    status_t status = vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);
    if ( VMI_FAILURE == status )
        return false;

    *list_head = current_process + drakvuf->offsets[EPROCESS_TASKS];
    return true;
}

static bool win_find_next_process_list_entry(drakvuf_t drakvuf, addr_t current_list_entry, addr_t* next_list_entry)
{
    if ( VMI_SUCCESS == vmi_read_addr_va(drakvuf->vmi, current_list_entry, 0, next_list_entry) )
        return true;

    return false;
}

static addr_t win_process_list_entry_to_process(drakvuf_t drakvuf, addr_t list_entry)
{
    return list_entry - drakvuf->offsets[EPROCESS_TASKS];
}

bool win_find_eprocess(drakvuf_t drakvuf, vmi_pid_t find_pid, const char* find_procname, addr_t* eprocess_addr)
{
    addr_t list_head;
    if (!win_find_process_list(drakvuf, &list_head))
        return false;
    addr_t current_list_entry = list_head;
    addr_t next_list_entry;
    if (!win_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
    {
        PRINT_DEBUG("Failed to read next pointer at 0x%"PRIx64" before entering loop\n", current_list_entry);
        return false;
    }

    do
    {
        vmi_pid_t pid;
        addr_t current_process = current_list_entry - drakvuf->offsets[EPROCESS_TASKS] ;

        if (!win_get_process_pid(drakvuf, current_process, &pid))
        {
            PRINT_DEBUG("Failed to read PID of process at %"PRIx64"\n", current_process);
            return false;
        }

        char* procname = win_get_process_name(drakvuf, current_process, false);

        if ((find_pid != ~0 && pid == find_pid) || (find_procname && procname && !strcasecmp(procname, find_procname)))
        {
            *eprocess_addr = current_process;
            if ( procname )
                free(procname);
            return true;
        }

        free(procname);

        current_list_entry = next_list_entry;

        if (!win_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
        {
            PRINT_DEBUG("Failed to read next pointer in loop at %"PRIx64"\n", current_list_entry);
            return false;
        }

    } while (next_list_entry != list_head);

    return false;
}

bool win_search_modules( drakvuf_t drakvuf,
                         const char* module_name,
                         bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx),
                         void* visitor_ctx,
                         addr_t eprocess_addr,
                         addr_t wow_process,
                         vmi_pid_t pid,
                         access_context_t* ctx )
{
    bool ret = false ;
    addr_t module_list_head;

    // List x64 modules...
    if ( win_get_module_list( drakvuf, eprocess_addr, &module_list_head ) )
    {
        module_info_t* module_info = win_get_module_info_ctx( drakvuf, module_list_head, ctx, module_name );

        if ( module_info )
        {
            module_info->eprocess_addr  = eprocess_addr ;
            module_info->dtb            = ctx->dtb ;
            module_info->pid            = pid ;
            module_info->is_wow_process = wow_process ? true : false ;
            module_info->is_wow         = false ;

            ret = visitor_func( drakvuf, module_info, visitor_ctx );

            vmi_free_unicode_str( module_info->full_name );
            vmi_free_unicode_str( module_info->base_name );
            g_free( module_info );
        }
    }

    return ret ;
}

bool win_search_modules_wow( drakvuf_t drakvuf,
                             const char* module_name,
                             bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx),
                             void* visitor_ctx,
                             addr_t eprocess_addr,
                             addr_t wow_peb,
                             vmi_pid_t pid,
                             access_context_t* ctx )
{
    bool ret = false ;
    addr_t module_list_head ;

    if ( win_get_module_list_wow( drakvuf, ctx, wow_peb, &module_list_head ) )
    {
        module_info_t* module_info = win_get_module_info_ctx_wow( drakvuf, module_list_head, ctx, module_name );

        if ( module_info )
        {
            module_info->eprocess_addr  = eprocess_addr ;
            module_info->dtb            = ctx->dtb ;
            module_info->pid            = pid ;
            module_info->is_wow_process = true ;
            module_info->is_wow         = true ;

            ret = visitor_func( drakvuf, module_info, visitor_ctx );

            vmi_free_unicode_str( module_info->full_name );
            vmi_free_unicode_str( module_info->base_name );
            g_free( module_info );
        }
    }

    return ret ;
}

addr_t win_get_wow_peb( drakvuf_t drakvuf, access_context_t* ctx, addr_t eprocess )
{
    // 'Wow64Process' could not be the first member of '_EPROCESS' so this is cheap check
    if (!drakvuf->offsets[EPROCESS_WOW64PROCESS] && !drakvuf->offsets[EPROCESS_WOW64PROCESS_WIN10])
        return 0;

    addr_t ret_peb_addr = 0 ;
    addr_t wow_process = 0 ;
    addr_t eprocess_wow64_addr = eprocess + drakvuf->offsets[EPROCESS_WOW64PROCESS];

    if ( vmi_get_winver( drakvuf->vmi ) == VMI_OS_WINDOWS_10 )
        eprocess_wow64_addr = eprocess + drakvuf->offsets[EPROCESS_WOW64PROCESS_WIN10];

    if ( vmi_read_addr_va( drakvuf->vmi, eprocess_wow64_addr, 0, &wow_process ) == VMI_SUCCESS )
    {
        if ( vmi_get_winver( drakvuf->vmi ) == VMI_OS_WINDOWS_10 )
        {
            ctx->addr = wow_process + drakvuf->offsets[EWOW64PROCESS_PEB] ;

            if ( vmi_read_addr( drakvuf->vmi, ctx, &ret_peb_addr ) == VMI_FAILURE )
                ret_peb_addr = 0;
        }
        else
            ret_peb_addr = wow_process ;
    }

    return ret_peb_addr ;
}

// see https://github.com/mic101/windows/blob/master/WRK-v1.2/public/internal/base/inc/wow64tls.h#L23
#define WOW64_TLS_CPURESERVED 1

// magic offset in undocumented structure
#define WOW64_CONTEXT_PAD 4

bool win_get_wow_context(drakvuf_t drakvuf, addr_t ethread, addr_t* wow_ctx)
{
    addr_t teb_ptr;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_PID;
    ctx.addr = ethread + drakvuf->offsets[KTHREAD_TEB];

    if (vmi_read_addr(drakvuf->vmi, &ctx, &teb_ptr) != VMI_SUCCESS)
        return false;

    addr_t eprocess;
    ctx.addr = ethread + drakvuf->offsets[KTHREAD_PROCESS];

    if (vmi_read_addr(drakvuf->vmi, &ctx, &eprocess) != VMI_SUCCESS)
        return false;

    addr_t wow64process;
    ctx.addr = eprocess + drakvuf->offsets[EPROCESS_WOW64PROCESS];

    if ( vmi_get_winver( drakvuf->vmi ) == VMI_OS_WINDOWS_10 )
        ctx.addr = eprocess + drakvuf->offsets[EPROCESS_WOW64PROCESS_WIN10];

    if (vmi_read_addr(drakvuf->vmi, &ctx, &wow64process) != VMI_SUCCESS)
        return false;

    // seems like process is not a WOW64 process, so the data in TLS may be fake
    if (!wow64process)
        return false;

    pid_t pid;

    if (!win_get_process_pid(drakvuf, eprocess, &pid))
        return false;

    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;

    if (vmi_pid_to_dtb(drakvuf->vmi, pid, &ctx.dtb) != VMI_SUCCESS)
        return false;

    addr_t self_teb_ptr;
    if (vmi_read_addr(drakvuf->vmi, &ctx, &self_teb_ptr) != VMI_SUCCESS)
        return false;

    addr_t tls_slot;
    // like: NtCurrentTeb()->TlsSlots[WOW64_TLS_CPURESERVED]
    tls_slot = teb_ptr + drakvuf->offsets[TEB_TLS_SLOTS] + (WOW64_TLS_CPURESERVED * sizeof(uint64_t));

    addr_t tls_slot_val;
    ctx.addr = tls_slot;

    if (vmi_read_addr(drakvuf->vmi, &ctx, &tls_slot_val) != VMI_SUCCESS)
        return false;

    *wow_ctx = tls_slot_val + WOW64_CONTEXT_PAD;
    return true;
}

bool win_get_user_stack64(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr)
{
    addr_t ptrap_frame;
    uint64_t rsp;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_PID;
    ctx.addr = win_get_current_thread(drakvuf, info) + drakvuf->offsets[KTHREAD_TRAPFRAME];

    if (vmi_read_addr(drakvuf->vmi, &ctx, &ptrap_frame) != VMI_SUCCESS)
        return false;

    ctx.addr = ptrap_frame + drakvuf->offsets[KTRAP_FRAME_RSP];

    if (vmi_read_64(drakvuf->vmi, &ctx, &rsp) != VMI_SUCCESS)
        return false;

    *stack_ptr = rsp;
    return true;
}

bool win_get_user_stack32(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t* stack_ptr, addr_t* frame_ptr)
{
    uint32_t esp;
    uint32_t ebp;

    addr_t wow_ctx;

    if (!drakvuf->wow_offsets)
        return false;

    if (!win_get_wow_context(drakvuf, win_get_current_thread(drakvuf, info), &wow_ctx))
        return false;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_DTB;
    ctx.dtb = info->regs->cr3;
    ctx.addr = wow_ctx + drakvuf->wow_offsets[WOW_CONTEXT_ESP];

    if (vmi_read_32(drakvuf->vmi, &ctx, &esp) != VMI_SUCCESS)
        return false;

    ctx.addr = wow_ctx + drakvuf->wow_offsets[WOW_CONTEXT_EBP];

    if (vmi_read_32(drakvuf->vmi, &ctx, &ebp) != VMI_SUCCESS)
        return false;

    *stack_ptr = esp;
    *frame_ptr = ebp;
    return true;
}

bool win_enumerate_processes( drakvuf_t drakvuf, void (*visitor_func)(drakvuf_t drakvuf, addr_t eprocess, void* visitor_ctx), void* visitor_ctx )
{
    addr_t list_head;
    if (!win_find_process_list(drakvuf, &list_head))
        return false;
    addr_t current_list_entry = list_head;
    addr_t next_list_entry;

    if (!win_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
    {
        PRINT_DEBUG("Failed to read next pointer at 0x%"PRIx64" before entering loop\n", current_list_entry);
        return false;
    }

    do
    {
        addr_t eprocess = win_process_list_entry_to_process(drakvuf, current_list_entry);

        visitor_func(drakvuf, eprocess, visitor_ctx);

        current_list_entry = next_list_entry;

        if (!win_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
        {
            PRINT_DEBUG("Failed to read next pointer in loop at %"PRIx64"\n", current_list_entry);
            return false;
        }
    } while (next_list_entry != list_head);

    return true;
}

bool win_enumerate_processes_with_module( drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx )
{
    addr_t list_head;
    if (!win_find_process_list(drakvuf, &list_head))
        return false;
    addr_t current_list_entry = list_head;
    addr_t next_list_entry;

    if (!win_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
    {
        PRINT_DEBUG("Failed to read next pointer at 0x%"PRIx64" before entering loop\n", current_list_entry);
        return false;
    }

    do
    {
        addr_t current_process = win_process_list_entry_to_process(drakvuf, current_list_entry);

        vmi_pid_t pid ;

        if ( win_get_process_pid( drakvuf, current_process, &pid) )
        {
            access_context_t ctx = { .translate_mechanism = VMI_TM_PROCESS_DTB };

            if ( vmi_pid_to_dtb( drakvuf->vmi, pid, &ctx.dtb ) == VMI_SUCCESS )
            {
                addr_t wow_peb = win_get_wow_peb( drakvuf, &ctx, current_process ) ;

                if ( win_search_modules( drakvuf, module_name, visitor_func, visitor_ctx, current_process,
                                         wow_peb, pid, &ctx ) )
                    return true ;

                // List WoW64 modules...
                if ( wow_peb )
                {
                    if ( win_search_modules_wow( drakvuf, module_name, visitor_func, visitor_ctx, current_process,
                                                 wow_peb, pid, &ctx ) )
                        return true ;
                }
            }
        }

        current_list_entry = next_list_entry;

        if (!win_find_next_process_list_entry(drakvuf, current_list_entry, &next_list_entry))
        {
            PRINT_DEBUG("Failed to read next pointer in loop at %"PRIx64"\n", current_list_entry);
            return false;
        }
    } while (next_list_entry != list_head);

    return false;
}

bool win_is_crashreporter(drakvuf_t drakvuf, drakvuf_trap_info_t* info, vmi_pid_t* pid)
{
    if (sizeof("WerFault.exe") - 1 > strlen(info->proc_data.name))
        return false;

    if (!strstr(info->proc_data.name, "WerFault.exe"))
        return false;

    char* cmdline = win_get_process_commandline(drakvuf, info, info->proc_data.base_addr);
    if (!cmdline)
    {
        PRINT_DEBUG("Error. Failed to get command line\n");
        return false;
    }

    char* param = strstr(cmdline, "-p ");
    if (!param)
    {
        PRINT_DEBUG("Error. Failed to get param\n");
        free(cmdline);
        return false;
    }

    char* end = NULL;
    *pid = strtoul(param + 3, &end, 10);
    if (ERANGE == errno)
    {
        PRINT_DEBUG("Error. Failed to parse PID: the value is out of range\n");
        free(cmdline);
        return false;
    }

    free(cmdline);
    return true;
}

////////////////////////////////////////////////////////////////

bool win_get_process_ppid( drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid )
{
    if ( VMI_SUCCESS == vmi_read_32_va( drakvuf->vmi, process_base + drakvuf->offsets[EPROCESS_INHERITEDPID], 0, (uint32_t*)ppid ) )
        return true;

    return false;
}

bool win_get_process_data( drakvuf_t drakvuf, addr_t base_addr, proc_data_priv_t* proc_data )
{
    proc_data->base_addr = base_addr;

    if ( base_addr )
    {
        if ( win_get_process_pid( drakvuf, base_addr, &proc_data->pid ) )
        {
            if ( win_get_process_ppid( drakvuf, base_addr, &proc_data->ppid ) )
            {
                proc_data->userid = win_get_process_userid( drakvuf, base_addr );
                proc_data->name   = win_get_process_name( drakvuf, base_addr, true );

                if ( proc_data->name )
                    return true;
            }
        }
    }

    return false;
}

bool win_find_mmvad(drakvuf_t drakvuf, addr_t eprocess, addr_t vaddr, mmvad_info_t* out_mmvad)
{
    int depth = 0;
    bool is_win7 = vmi_get_winver( drakvuf->vmi ) <= VMI_OS_WINDOWS_7;

    access_context_t ctx;
    memset(&ctx, 0, sizeof(access_context_t));
    ctx.translate_mechanism = VMI_TM_PROCESS_PID;
    ctx.pid = 4;

    addr_t node_addr;

    if (is_win7)
    {
        node_addr = eprocess + drakvuf->offsets[EPROCESS_VADROOT] + drakvuf->offsets[VADROOT_BALANCED_ROOT];
    }
    else
    {
        ctx.addr = eprocess + drakvuf->offsets[EPROCESS_VADROOT] + drakvuf->offsets[RTL_AVL_TREE_ROOT];

        if (vmi_read_addr(drakvuf->vmi, &ctx, &node_addr) != VMI_SUCCESS)
        {
            PRINT_DEBUG("MMVAD failed for node addr\n");
            return false;
        }
    }

    while (node_addr)
    {
        addr_t left_child;
        addr_t right_child;

        uint64_t starting_vpn;
        uint64_t ending_vpn;

        uint32_t starting_vpn_low;
        uint32_t ending_vpn_low;
        uint8_t starting_vpn_high;
        uint8_t ending_vpn_high;

        uint64_t mmvad_core = 0;
        uint64_t flags1;

        if (depth > MMVAD_MAX_DEPTH)
        {
            PRINT_DEBUG("Error. Max depth exceeded when walking MMVAD tree.\n");
            return false;
        }

        ++depth;


        if (is_win7)
        {
            ctx.addr = node_addr + drakvuf->offsets[MMVAD_LEFT_CHILD];
        }
        else
        {
            ctx.addr = node_addr + drakvuf->offsets[RTL_BALANCED_NODE_LEFT];
        }

        if (vmi_read_addr(drakvuf->vmi, &ctx, &left_child) != VMI_SUCCESS)
        {
            return false;
        }

        if (is_win7)
        {
            ctx.addr = node_addr + drakvuf->offsets[MMVAD_RIGHT_CHILD];
        }
        else
        {
            ctx.addr = node_addr + drakvuf->offsets[RTL_BALANCED_NODE_RIGHT];
        }

        if (vmi_read_addr(drakvuf->vmi, &ctx, &right_child) != VMI_SUCCESS)
        {
            return false;
        }

        if (is_win7)
        {
            ctx.addr = node_addr + drakvuf->offsets[MMVAD_STARTING_VPN];

            if (vmi_read_64(drakvuf->vmi, &ctx, &starting_vpn) != VMI_SUCCESS)
            {
                return false;
            }

            ctx.addr = node_addr + drakvuf->offsets[MMVAD_ENDING_VPN];

            if (vmi_read_64(drakvuf->vmi, &ctx, &ending_vpn) != VMI_SUCCESS)
            {
                return false;
            }
        }
        else
        {
            mmvad_core = node_addr + drakvuf->offsets[MMVAD_CORE];
            ctx.addr = mmvad_core + drakvuf->offsets[MMVAD_SHORT_STARTING_VPN];

            if (vmi_read_32(drakvuf->vmi, &ctx, &starting_vpn_low) != VMI_SUCCESS)
            {
                return false;
            }

            ctx.addr = mmvad_core + drakvuf->offsets[MMVAD_SHORT_ENDING_VPN];

            if (vmi_read_32(drakvuf->vmi, &ctx, &ending_vpn_low) != VMI_SUCCESS)
            {
                return false;
            }

            ctx.addr = mmvad_core + drakvuf->offsets[MMVAD_SHORT_STARTING_VPN_HIGH];

            if (vmi_read_8(drakvuf->vmi, &ctx, &starting_vpn_high) != VMI_SUCCESS)
            {
                return false;
            }

            ctx.addr = mmvad_core + drakvuf->offsets[MMVAD_SHORT_ENDING_VPN_HIGH];

            if (vmi_read_8(drakvuf->vmi, &ctx, &ending_vpn_high) != VMI_SUCCESS)
            {
                return false;
            }

            starting_vpn = starting_vpn_high;
            starting_vpn <<= 32;
            starting_vpn |= starting_vpn_low;

            ending_vpn = ending_vpn_high;
            ending_vpn <<= 32;
            ending_vpn |= ending_vpn_low;
        }

        if (starting_vpn == 0 && ending_vpn == 0)
        {
            // the root node seems to be empty with only right child pointer filled in
            node_addr = right_child;
        }
        else if (starting_vpn * VMI_PS_4KB <= vaddr && (ending_vpn + 1) * VMI_PS_4KB > vaddr)
        {
            uint32_t pool_tag;
            addr_t subsection;
            addr_t control_area;
            addr_t file_object;

            out_mmvad->file_name_ptr = 0;

            if (is_win7)
            {
                ctx.addr = node_addr + drakvuf->offsets[MMVAD_FLAGS1];
            }
            else
            {
                ctx.addr = mmvad_core + drakvuf->offsets[MMVAD_SHORT_FLAGS1];
            }

            if (vmi_read_64(drakvuf->vmi, &ctx, &flags1) != VMI_SUCCESS)
            {
                return false;
            }

            // read Windows' PoolTag which is 12 bytes before the actual object
            ctx.addr = node_addr - 0xC;
            if (vmi_read_32(drakvuf->vmi, &ctx, &pool_tag) != VMI_SUCCESS)
            {
                return false;
            }

            // Windows MMVAD can have multiple types, can be differentiated with pool tags
            // some types are shorter and don't even contain "Subsection" field
            if (pool_tag == POOL_TAG_VADL || pool_tag == POOL_TAG_VAD || pool_tag == POOL_TAG_VADM)
            {
                ctx.addr = node_addr + drakvuf->offsets[MMVAD_SUBSECTION];

                if (vmi_read_addr(drakvuf->vmi, &ctx, &subsection) == VMI_SUCCESS)
                {
                    ctx.addr = subsection + drakvuf->offsets[SUBSECTION_CONTROL_AREA];

                    if (vmi_read_addr(drakvuf->vmi, &ctx, &control_area) == VMI_SUCCESS)
                    {
                        ctx.addr = control_area + drakvuf->offsets[CONTROL_AREA_FILEPOINTER];

                        if (vmi_read_addr(drakvuf->vmi, &ctx, &file_object) == VMI_SUCCESS)
                        {
                            // file_object is a special _EX_FAST_REF pointer, we need to explicitly clear low bits
                            file_object &= (~0xFULL);

                            if ((void*)file_object != NULL)
                            {
                                out_mmvad->file_name_ptr = (file_object + drakvuf->offsets[FILEOBJECT_NAME]);
                            }
                        }
                    }
                }
            }

            out_mmvad->starting_vpn = starting_vpn;
            out_mmvad->ending_vpn = ending_vpn;
            out_mmvad->flags1 = flags1;

            return true;
        }
        else if (starting_vpn * VMI_PS_4KB > vaddr)
        {
            node_addr = left_child;
        }
        else
        {
            node_addr = right_child;
        }
    }

    return false;
}

bool win_get_pid_from_handle(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t handle, vmi_pid_t* pid)
{
    if (handle == 0 || handle == UINT64_MAX)
    {
        *pid = info->proc_data.pid;
        return false;
    }

    if (!info->proc_data.base_addr)
    {
        return false;
    }

    addr_t obj = drakvuf_get_obj_by_handle(drakvuf, info->proc_data.base_addr, handle);
    if (!obj)
    {
        return false;
    }

    addr_t eprocess_base = obj + drakvuf->offsets[OBJECT_HEADER_BODY];
    return drakvuf_get_process_pid(drakvuf, eprocess_base, pid);
}
