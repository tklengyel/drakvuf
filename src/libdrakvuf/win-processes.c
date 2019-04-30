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

typedef enum dispatcher_object
{
    __DISPATCHER_INVALID_OBJECT = 0,
    DISPATCHER_PROCESS_OBJECT = 3,
    DISPATCHER_THREAD_OBJECT  = 6
} dispatcher_object_t ;

bool win_get_module_list_wow( drakvuf_t drakvuf, access_context_t* ctx, addr_t wow_peb, addr_t* module_list );
bool win_search_modules( drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx, addr_t eprocess_addr, addr_t wow_process, vmi_pid_t pid, access_context_t* ctx );
bool win_search_modules_wow( drakvuf_t drakvuf, const char* module_name, bool (*visitor_func)(drakvuf_t drakvuf, const module_info_t* module_info, void* visitor_ctx), void* visitor_ctx, addr_t eprocess_addr, addr_t wow_peb, vmi_pid_t pid, access_context_t* ctx );
addr_t win_get_wow_peb( drakvuf_t drakvuf, access_context_t* ctx, addr_t wow_process );

addr_t win_get_current_thread(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    vmi_instance_t vmi = drakvuf->vmi;
    addr_t thread;
    addr_t prcb;
    addr_t kpcr;

    if (drakvuf->pm == VMI_PM_IA32E)
    {
        prcb=drakvuf->offsets[KPCR_PRCB];

        vmi_get_vcpureg(drakvuf->vmi, &kpcr, GS_BASE, info->vcpu);
    }
    else
    {
        prcb=drakvuf->offsets[KPCR_PRCBDATA];

        vmi_get_vcpureg(drakvuf->vmi, &kpcr, FS_BASE, info->vcpu);
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

status_t win_get_last_error(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t* err, const char** err_str)
{
    if (!err || !err_str)
        return VMI_FAILURE;

    vmi_instance_t vmi = drakvuf->vmi;

    addr_t eprocess = win_get_current_process(drakvuf, info);
    addr_t cr3 = 0;
    vmi_pid_t pid = 0;
    if (eprocess && VMI_SUCCESS == win_get_process_pid(drakvuf, eprocess, &pid))
        if (VMI_SUCCESS != vmi_pid_to_dtb(vmi, pid, &cr3))
            return VMI_FAILURE;

    addr_t kthread = win_get_current_thread(drakvuf, info);
    if (!kthread)
        return VMI_FAILURE;

    addr_t teb = 0;
    if (VMI_SUCCESS != vmi_read_addr_va(vmi, kthread + drakvuf->offsets[KTHREAD_TEB], 0, &teb))
        return VMI_FAILURE;

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = cr3,
        .addr = teb + drakvuf->offsets[TEB_LASTERRORVALUE],
    };

    if (VMI_SUCCESS != vmi_read_32(vmi, &ctx, err))
        return VMI_FAILURE;

    if (*err >= __WIN_ERROR_CODES_MAX)
        return VMI_FAILURE;

    if (win_error_code_names[*err])
        *err_str = win_error_code_names[*err];

    return VMI_SUCCESS;
}

static unicode_string_t* win_get_process_full_name(drakvuf_t drakvuf, addr_t eprocess_base)
{
    addr_t image_file_name_addr;
    if ( vmi_read_addr_va(drakvuf->vmi,
                          eprocess_base + drakvuf->offsets[EPROCESS_PROCCREATIONINFO] + drakvuf->offsets[PROCCREATIONINFO_IMAGEFILENAME],
                          0, &image_file_name_addr) != VMI_SUCCESS )
    {
#ifdef DRAKVUF_DEBUG
        PRINT_DEBUG("in win_get_process_full_name(...) couldn't read IMAGEFILENAME address\n");
#endif
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

    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
    };

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

status_t win_get_process_pid(drakvuf_t drakvuf, addr_t eprocess_base, vmi_pid_t* pid)
{

    return vmi_read_32_va(drakvuf->vmi, eprocess_base + drakvuf->offsets[EPROCESS_PID], 0, (uint32_t*)pid);
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
    access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB};

    if (!eprocess_base)
        return -1;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + drakvuf->offsets[EPROCESS_PEB], 0, &peb))
        return -1;

    if (VMI_FAILURE == vmi_read_addr_va(vmi, eprocess_base + drakvuf->offsets[EPROCESS_PDBASE], 0, &ctx.dtb))
        return -1;

    ctx.addr = peb + drakvuf->offsets[PEB_SESSIONID];
    if ( VMI_FAILURE == vmi_read_addr(vmi, &ctx, &userid) )
        return -1;

#ifdef DRAKVUF_DEBUG
    /* It should be safe to stash userid into a int64_t as it seldom goes above INT_MAX */
    if ( userid > INT_MAX )
        PRINT_DEBUG("The process at 0x%" PRIx64 " has a userid larger then INT_MAX!\n", eprocess_base);
#endif

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
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
    };

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
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = dtb,
    };

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

    access_context_t ctx = {.translate_mechanism = VMI_TM_PROCESS_DTB};

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
    vmi_instance_t vmi = drakvuf->vmi;
    status_t status = vmi_read_addr_va(vmi, current_list_entry, 0, next_list_entry);
    return VMI_FAILURE != status;
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

        status_t status = win_get_process_pid(drakvuf, current_process, &pid);
        if ( VMI_FAILURE == status )
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

    }
    while (next_list_entry != list_head);

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
    if (!drakvuf->offsets[EPROCESS_WOW64PROCESS])
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
    }
    while (next_list_entry != list_head);

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

        if ( win_get_process_pid( drakvuf, current_process, &pid) == VMI_SUCCESS )
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
    }
    while (next_list_entry != list_head);

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
        return false;
    }

    char* end = NULL;
    *pid = strtoul(param + 3, &end, 10);
    if (ERANGE == errno)
    {
        PRINT_DEBUG("Error. Failed to parse PID: the value is out of range\n");
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////

status_t win_get_process_ppid( drakvuf_t drakvuf, addr_t process_base, vmi_pid_t* ppid )
{
    return vmi_read_32_va( drakvuf->vmi, process_base + drakvuf->offsets[EPROCESS_INHERITEDPID], 0, (uint32_t*)ppid );
}

bool win_get_process_data( drakvuf_t drakvuf, addr_t base_addr, proc_data_priv_t* proc_data )
{
    proc_data->base_addr = base_addr;

    if ( base_addr )
    {
        if ( win_get_process_pid( drakvuf, base_addr, &proc_data->pid ) == VMI_SUCCESS )
        {
            if ( win_get_process_ppid( drakvuf, base_addr, &proc_data->ppid ) == VMI_SUCCESS )
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
